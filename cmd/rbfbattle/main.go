package main

import (
	"fmt"
	"log"
	"log/slog"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/fatih/color"
)

const (
	// Default fee settings
	defaultFeeRate = 2.0 // satoshis per vbyte
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

var network = &chaincfg.RegressionNetParams

// connectToBitcoinNode establishes a connection to the Bitcoin node

type TrackedUTXO struct {
	Address string
	// OutputValue
	Amount btcutil.Amount
	// OutputIndex
	N    uint32
	TxID string

	// New
	Script btcjson.ScriptPubKeyResult
	Tx     *btcjson.TxRawResult
}

// extractUTXOs extracts all addresses that received funds in a transaction
func extractUTXOs(tx *btcjson.TxRawResult) []*TrackedUTXO {
	var addresses []*TrackedUTXO

	// Process each output (vout) in the transaction
	for _, vout := range tx.Vout {
		// Extract addresses from the scriptPubKey
		if vout.ScriptPubKey.Address != "" {
			amount, _ := btcutil.NewAmount(vout.Value)

			addresses = append(addresses, &TrackedUTXO{
				Address: vout.ScriptPubKey.Address,
				Amount:  amount,
				N:       vout.N,
				TxID:    tx.Txid,
				Script:  vout.ScriptPubKey,
				Tx:      tx,
			})
		}
	}

	return addresses
}

// processTransaction processes a transaction that got added to the mempool
func processTransaction(client *rpcclient.Client, tx *btcjson.TxRawResult, config *Config) {
	txID := tx.Txid

	utxos := extractUTXOs(tx)

	for _, vout := range tx.Vout {
		isSentToUs := vout.ScriptPubKey.Address == config.DestinationAddress
		voutValue, _ := btcutil.NewAmount(vout.Value)

		if tx.Confirmations > 0 {
			// A transaction sent to us spending one of our monitored utxos was confirmed.
			for _, vin := range tx.Vin {
				id := vin.Txid + ":" + strconv.Itoa(int(vin.Vout))

				if monitoredUtxo, ok := monitoredUtxos[id]; ok {
					if isSentToUs {
						log.Printf(color.GreenString("RBF battle won for %s and transaction was received by us\n"+
							"\ttxid=%s\n"+
							"\tutxo=%s:%d\n"+
							"\treceived_value=%f BTC\n"+
							"\toriginal_value=%f BTC\n"+
							"\tblock_hash=%s"),
							monitoredUtxo.Address,
							txID,
							monitoredUtxo.TxID,
							monitoredUtxo.N,
							(monitoredUtxo.Amount - voutValue).ToBTC(),
							monitoredUtxo.Amount.ToBTC(),
							tx.BlockHash,
						)
					} else {
						log.Printf(color.RedString("RBF battle lost for %s\n"+
							"\ttxid=%s\n"+
							"\tutxo=%s:%d\n"+
							"\treceived_value=%f BTC\n"+
							"\toriginal_value=%f BTC\n"+
							"\tblock_hash=%s"),
							monitoredUtxo.Address,
							txID,
							monitoredUtxo.TxID,
							monitoredUtxo.N,
							(monitoredUtxo.Amount - voutValue).ToBTC(),
							monitoredUtxo.Amount.ToBTC(),
							tx.BlockHash,
						)

						cleanup(monitoredUtxo)
					}

					// Select a new utxo to spend for the next battle
					unspentUtxo = nil
					selectUnspentUtxo(client)
				}
			}
			return
		}

		if isSentToUs && len(utxos) > 1 {
			// Maybe the attacker is trying to fool us by sending a small amount to our address
			// and the rest to himself in another output.
			// Since our transactions have one output only, we try to replace it again.
			log.Printf("Transaction %s has multiple outputs and is sending %f BTC to our address", txID, voutValue.ToBTC())
		} else if isSentToUs {
			// This is our own replacement transaction
			return
		}
	}

	for _, utxo := range utxos {
		// Check if utxo address is watched by us

		privKey, ok := ourAddresses[utxo.Address]

		if !ok {
			continue
		}

		if tx.Confirmations > 0 {
			log.Printf("Transaction to watched address %s was confirmed\n"+
				"\ttxid=%s\n"+
				"\tblock_hash=%s",
				utxo.Address,
				txID,
				tx.BlockHash,
			)

			// delete(monitoredUtxos, txID)
			return
		}

		log.Printf(color.YellowString(
			"Detected transaction to watched address %s. Trying to spend it\n"+
				"\ttxid=%s\n"+
				"\tvout=%d\n"+
				"\tamount=%f BTC",
		),
			utxo.Address,
			txID,
			utxo.N,
			utxo.Amount.ToBTC(),
		)

		monitor(utxo)

		_, err := SpendTransaction(client, utxo, privKey, config)
		if err != nil {
			// Someone else was faster and spent the UTXO first.
			log.Printf(color.RedString("Failed to send initial spend transaction: %v"), err)
		}
		return
	}

	if tx.Confirmations > 0 {
		return
	}

	// Check if a counterpart is spending one of our monitored UTXOs
	for _, vin := range tx.Vin {
		id := vin.Txid + ":" + strconv.Itoa(int(vin.Vout))

		if utxo, ok := monitoredUtxos[id]; ok {
			for _, vout := range tx.Vout {
				if vout.ScriptPubKey.Asm == "OP_RETURN" {
					log.Printf(color.RedString("Transaction %s has an OP_RETURN output"), txID)
				}
			}

			privateKeyWIF := ourAddresses[utxo.Address]

			go TryReplacingAttacker(client, tx, utxo, privateKeyWIF, config)

			return
		}
	}
}

// SpendTransaction tries to spend the UTXO we're watching to our destination address.
// This might fail if another bot is faster and spends the UTXO first, in which we'll engage in the RBF battle.
func SpendTransaction(client *rpcclient.Client, trackedUtxo *TrackedUTXO, privateKeyWIF string, config *Config) (string, error) {

	// Get
	outputHash, err := chainhash.NewHashFromStr(trackedUtxo.TxID)
	if err != nil {
		return "", fmt.Errorf("error parsing transaction hash: %v", err)
	}
	outputIndex := trackedUtxo.N
	outputValue := trackedUtxo.Amount

	// Create a new transaction
	newTx := wire.NewMsgTx(2)

	// Add the input
	outpoint := wire.NewOutPoint(outputHash, outputIndex)
	txIn := wire.NewTxIn(outpoint, nil, nil)
	newTx.AddTxIn(txIn)

	// Parse destination address
	// TODO - During startup when we load the config, decode the destination address and check it there
	destAddr, err := btcutil.DecodeAddress(config.DestinationAddress, network)
	if err != nil {
		return "", fmt.Errorf("error decoding destination address: %v", err)
	}

	// Create destination script
	destScript, err := txscript.PayToAddrScript(destAddr)
	if err != nil {
		return "", fmt.Errorf("error creating destination script: %v", err)
	}

	// Estimate transaction size
	estimatedSize := estimateTransactionSize(config, outputValue, trackedUtxo.Script.Hex)

	feeRate := defaultFeeRate

	// If we can get fee estimates from the node, use that instead
	// TODO do not let EstimateSmartFee block here
	feeEstimate, err := client.EstimateSmartFee(1, &btcjson.EstimateModeConservative)
	if err == nil && feeEstimate.FeeRate != nil {
		// Convert from BTC/KB to satoshis/vbyte
		nodeFeeRate := *feeEstimate.FeeRate * 1_0000_0000 / 1000
		log.Printf("Fee estimate from node: %f sat/vbyte", nodeFeeRate)
		feeRate = nodeFeeRate
	} else {
		log.Printf("No fee estimate from node, using default fee rate %f sat/vbyte", defaultFeeRate)
	}

	// Calculate the fee in satoshis based on estimated size
	feeSatoshis := int64(float64(estimatedSize) * feeRate)

	// Calculate output amount (input amount - fee)
	outputSatoshis := int64(outputValue.ToUnit(btcutil.AmountSatoshi)) - feeSatoshis
	if outputSatoshis <= 0 {
		return "", fmt.Errorf("not enough funds to cover fee")
	}

	// Add the output
	txOut := wire.NewTxOut(outputSatoshis, destScript)
	newTx.AddTxOut(txOut)

	if err := SignInput(client, newTx, 0, privateKeyWIF, trackedUtxo); err != nil {
		return "", fmt.Errorf("error signing transaction: %v", err)
	}

	log.Printf("Broadcasting fee_rate=%f total_fee=%f sats tx_size=%d", feeRate, float64(feeSatoshis), estimatedSize)

	// Broadcast the transaction
	newTxHash, err := client.SendRawTransaction(newTx, true)
	if err != nil {
		return "", fmt.Errorf("error broadcasting transaction: %v", err)
	}

	log.Printf(color.GreenString("Spent utxo from watched address %s:%d\n"+
		"\ttxid=%s\n"+
		"\tfee_rate=%f sat/vbyte\n"+
		"\tvalue=%f BTC\n"+
		"\toutput_value=%f BTC"),
		trackedUtxo.TxID,
		trackedUtxo.N,
		newTxHash,
		feeRate,
		trackedUtxo.Amount.ToBTC(),
		btcutil.Amount(outputSatoshis).ToBTC(),
	)
	return newTxHash.String(), nil
}

func TryReplacingAttacker(client *rpcclient.Client, counterpart *btcjson.TxRawResult, utxo *TrackedUTXO, privateKeyWIF string, config *Config) {
	mempool, err := client.GetMempoolEntry(counterpart.Txid)
	if err != nil {
		log.Printf(color.RedString("Failed to get mempool entry for %s. The attacking transaction was probably already replaced by someone else: %v"), counterpart.Txid, err)
		return
	}

	counterFee, _ := btcutil.NewAmount(mempool.Fees.Descendant)
	vsize := mempool.VSize
	counterFeeRate := counterFee.ToUnit(btcutil.AmountSatoshi) / float64(vsize)

	log.Printf(
		color.YellowString("Someone is spending monitored UTXO!\n"+
			"\tcounterpart=%s\n"+
			"\tutxo=%s:%d\n"+
			"\tfee_rate=%f sat/vbyte\n"+
			"\ttotal_fee=%f BTC\n"+
			"\tfee_percentage=%f%%"),
		counterpart.Txid,
		utxo.TxID,
		utxo.N,
		counterFeeRate,
		counterFee.ToBTC(),
		(counterFee.ToBTC()/utxo.Amount.ToBTC())*100,
	)

	if counterFee > utxo.Amount {
		log.Printf(color.RedString("Counterpart paid more in fee than what the utxo is worth. Giving up."+
			"\n\tfees=%f BTC\n"+
			"\tamount=%f BTC"),
			counterFee.ToBTC(),
			utxo.Amount.ToBTC(),
		)
		return
	} else if counterFee == utxo.Amount {
		log.Printf(color.RedString("Counterpart burned the utxo. Giving up."+
			"\n\tfees=%f BTC\n"+
			"\tamount=%f BTC"),
			counterFee.ToBTC(),
			utxo.Amount.ToBTC(),
		)
		cleanup(utxo)
		return
	}

	// Select the transaction in our wallet we're using as an input along with the utxo we're trying to spend
	unspent, err := selectUnspentUtxo(client)
	if err != nil {
		log.Fatalf(color.RedString("error listing unspent: %v"), err)
		return
	}
	unspentSats, _ := btcutil.NewAmount(unspent.Amount)

	utxoValue := (utxo.Amount)
	estimatedTxSize := estimateTransactionSize(config, utxoValue+unspentSats, utxo.Script.Hex, unspent.ScriptPubKey)

	// New fee rate we're trying to counter with
	newFee, overpaying := newFee(counterFee, vsize, int32(estimatedTxSize), utxo)
	newFeeRate := float64(newFee) / float64(estimatedTxSize)

	// The new output value we're trying to spend
	// It's our own utxo value + the utxo value we're trying to take - the fees we're paying
	outputValueSatoshis := btcutil.Amount(utxoValue - newFee + unspentSats)
	feePercentage := (float64(newFee) / float64(utxoValue)) * 100

	log.Printf("Trying to broadcast replacement for %s\n"+
		"\tpercentage_paid_in_fees=%f%%\n"+
		"\tfee_rate=%f sat/vbyte\n"+
		"\ttotal_fee=%f BTC\n"+
		"\toutput_value=%f BTC",
		formatTxId(counterpart.Txid),
		feePercentage,
		newFeeRate,
		newFee.ToBTC(),
		btcutil.Amount(utxoValue-newFee).ToBTC(),
	)

	if overpaying {
		log.Printf(color.RedString("Burning utxo as we would spend %f%% of the value on fees. %s"), feePercentage, formatTxId(counterpart.Txid))

		if _, err := BurnTransaction(client, counterpart, utxo, privateKeyWIF, config); err != nil {
			log.Printf(color.RedString("Failed to burn transaction: %v"), err)
		}
		return
	}

	if outputValueSatoshis < 547 {
		log.Printf("Output value is less than dust limit. Giving up.")
		return
	}

	newTxID, err := ReplaceTransaction(client, int64(outputValueSatoshis), unspent, counterpart, utxo, privateKeyWIF, config)

	// We were able to replace the transaction
	if err == nil {
		feeIncrease := (counterFeeRate / newFeeRate) * 100
		log.Printf(color.GreenString("Replaced counterpart transaction %s with new transaction %s, fee_increase=%f%%"), formatTxId(counterpart.Txid), newTxID, feeIncrease)
		return
	}

	// We're basing our new feerate on the counterpart feerate
	if strings.Contains(err.Error(), "-26: insufficient fee") {
		// The new proposed replacement fee rate is too low.
		// This is probably because another replacement was broadcasted,
		// so we just abort and try replacing the other transaction when we detect it.
		log.Printf(color.RedString("Insufficient fees paid. err=%v"), err)
		return
	} else if strings.Contains(err.Error(), "not enough funds to cover fee") {
		log.Printf(color.RedString("No money left to spend. Burning. err=%v"), err)
		if _, err := BurnTransaction(client, counterpart, utxo, privateKeyWIF, config); err != nil {
			log.Printf(color.RedString("Failed to burn transaction. err=%v"), err)
		}
		return
	} else if strings.Contains(err.Error(), "-26: dust") {
		log.Printf(color.RedString("Replacement was rejected as it would leave only dust. Giving up. %s"), err)
		if _, err := BurnTransaction(client, counterpart, utxo, privateKeyWIF, config); err != nil {
			log.Printf(color.RedString("Failed to burn transaction: %v"), err)
		}
		return
	} else if strings.Contains(err.Error(), "bad-txns-inputs-missingorspent") {
		// We tried to replace a transaction that was already confirmed.
		log.Printf(color.RedString("Counterpart transaction %s was confirmed. %s"), counterpart.Txid, err)
		return
	}

	log.Printf("Error replacing counterattack transaction: %v", err)
}

func BurnTransaction(client *rpcclient.Client, counterpart *btcjson.TxRawResult, trackedUtxo *TrackedUTXO, privateKeyWIF string, config *Config) (string, error) {

	// Create a transaction spending the output
	txHash, err := chainhash.NewHashFromStr(trackedUtxo.TxID)
	if err != nil {
		return "", fmt.Errorf("error parsing transaction hash: %v", err)
	}

	newTx := wire.NewMsgTx(2)

	// Add the input
	outpoint := wire.NewOutPoint(txHash, trackedUtxo.N)
	txIn := wire.NewTxIn(outpoint, nil, nil)
	newTx.AddTxIn(txIn)

	msg := []byte(config.BurnMessage)
	// Create destination script
	destScript, err := txscript.NullDataScript(msg)
	if err != nil {
		return "", fmt.Errorf("error creating destination script: %v", err)
	}

	// Add the output
	txOut := wire.NewTxOut(0, destScript)
	newTx.AddTxOut(txOut)

	if err := SignInput(client, newTx, 0, privateKeyWIF, trackedUtxo); err != nil {
		return "", fmt.Errorf("error creating signature script: %v", err)
	}

	// Broadcast the transaction
	newTxHash, err := client.SendRawTransaction(newTx, true)
	if err != nil {
		return "", fmt.Errorf("error broadcasting transaction: %v", err)
	}

	log.Printf(color.GreenString("BURNED IN %s"), newTxHash.String())

	cleanup(trackedUtxo)
	return newTxHash.String(), nil
}

// ReplaceTransaction creates and broadcasts a transaction to send funds to our destination address
func ReplaceTransaction(client *rpcclient.Client, outputValue int64, unspent btcjson.ListUnspentResult, counterpart *btcjson.TxRawResult, trackedUtxo *TrackedUTXO, privateKeyWIF string, config *Config) (string, error) {
	// Create a transaction spending the output
	txHash, err := chainhash.NewHashFromStr(trackedUtxo.TxID)
	if err != nil {
		return "", fmt.Errorf("error parsing transaction hash: %v", err)
	}

	// Create a new transaction
	newTx := wire.NewMsgTx(2)

	// Add the input
	outpoint := wire.NewOutPoint(txHash, trackedUtxo.N)
	txIn := wire.NewTxIn(outpoint, nil, nil)
	newTx.AddTxIn(txIn)

	// Parse destination address
	destAddr, err := btcutil.DecodeAddress(config.DestinationAddress, network)
	if err != nil {
		return "", fmt.Errorf("error decoding destination address: %v", err)
	}

	// Create destination script
	destScript, err := txscript.PayToAddrScript(destAddr)
	if err != nil {
		return "", fmt.Errorf("error creating destination script: %v", err)
	}

	// Add the output
	txOut := wire.NewTxOut(outputValue, destScript)
	newTx.AddTxOut(txOut)

	txHash2, _ := chainhash.NewHashFromStr(unspent.TxID)
	outpoint2 := wire.NewOutPoint(txHash2, unspent.Vout)
	txIn2 := wire.NewTxIn(outpoint2, nil, nil)
	newTx.AddTxIn(txIn2)

	sig, _, err := client.SignRawTransactionWithWallet(newTx)

	if err != nil {
		return "", fmt.Errorf("error signing transaction with wallet: %v", err)
	}

	if err := SignInput(client, sig, 0, privateKeyWIF, trackedUtxo); err != nil {
		return "", fmt.Errorf("error signing transaction: %v", err)
	}

	// Broadcast the transaction
	newTxHash, err := client.SendRawTransaction(sig, true)
	if err != nil {
		return "", fmt.Errorf("error broadcasting transaction: %v", err)
	}

	return newTxHash.String(), nil
}

var rawTransactionQueue = make(chan *btcjson.TxRawResult, 100)

func processor(client *rpcclient.Client, config *Config) {
	for {
		select {
		case tx := <-rawTransactionQueue:
			processTransaction(client, tx, config)
		}
	}
}

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	// Load configuration
	config, err := LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Connect to Bitcoin node
	client := connectToBitcoinNode(config)
	defer client.Shutdown()

	// Check if the wallet has any spendable utxo we can use when replacing transactions
	_, err = selectUnspentUtxo(client)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Load our addresses and private keys
	err = loadAddressesAndKeys(config.AddressFile)
	if err != nil {
		log.Fatalf("Error loading addresses and keys: %v", err)
	}

	for i := 0; i < 16; i++ {
		go processor(client, config)
	}

	monitorMempoolWithZMQ(client, config)
}
