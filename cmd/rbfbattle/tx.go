package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
)

// estimateTransactionSize roughly estimates the size of a transaction
// we're sending that spends our watched utxos
func estimateTransactionSize(config *Config, outputValue btcutil.Amount, inputScripts ...string) int {
	// Create destination script
	destScript, _ := txscript.PayToAddrScript(config.decodedDestinationAddress)

	// Count input types
	var numP2PKHIns, numP2TRIns, numP2WPKHIns, numNestedP2WPKHIns int

	// Check our input type
	for _, inputScript := range inputScripts {
		inputScriptBytes, _ := hex.DecodeString(inputScript)
		inputScriptClass := txscript.GetScriptClass(inputScriptBytes)

		switch inputScriptClass {
		case txscript.PubKeyHashTy:
			numP2PKHIns++
		case txscript.WitnessV0PubKeyHashTy:
			numP2WPKHIns++
		case txscript.WitnessV1TaprootTy:
			numP2TRIns++
		case txscript.ScriptHashTy:
			numNestedP2WPKHIns++
		default:
			log.Fatalf("unsupported script type: %v", inputScriptClass)
		}
	}

	return txsizes.EstimateVirtualSize(
		numP2PKHIns,
		numP2TRIns,
		numP2WPKHIns,
		numNestedP2WPKHIns,
		[]*wire.TxOut{wire.NewTxOut(int64(outputValue), destScript)},
		0,
	)
}

func formatTxId(txid string) string {
	return txid[:6] + "..." + txid[len(txid)-6:]
}

// SignInput signs a transaction input based on its script type.
// It handles P2PKH, P2SH, P2WPKH, P2WSH, and P2TR inputs.
func SignInput(client *rpcclient.Client, tx *wire.MsgTx, idx int, privateKey string, trackedUtxo *TrackedUTXO) error {
	scriptBytes, err := hex.DecodeString(trackedUtxo.Script.Hex)
	if err != nil {
		return fmt.Errorf("error decoding script hex: %v", err)
	}

	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return fmt.Errorf("error decoding private key: %v", err)
	}

	pk, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	// Default to compressed, but we'll check the script type
	compress := true

	amount := int64(trackedUtxo.Amount)

	// Create a prevOutFetcher that knows about all inputs
	prevOutFetcher := txscript.NewMultiPrevOutFetcher(nil)

	txHash, err := chainhash.NewHashFromStr(trackedUtxo.TxID)
	if err != nil {
		return fmt.Errorf("error parsing transaction hash: %v", err)
	}

	// Add our current input
	prevOutFetcher.AddPrevOut(wire.OutPoint{
		Hash:  *txHash,
		Index: trackedUtxo.N,
	}, &wire.TxOut{
		Value:    amount,
		PkScript: scriptBytes,
	})
	if err != nil {
		return fmt.Errorf("error parsing transaction hash: %v", err)
	}

	// Determine the script type and sign accordingly
	scriptClass := txscript.GetScriptClass(scriptBytes)

	switch scriptClass {
	case txscript.PubKeyHashTy:
		// For P2PKH, we need to check if it's uncompressed
		// Get the public key hash from the script
		if len(scriptBytes) != 25 {
			return fmt.Errorf("invalid P2PKH script length")
		}
		pubKeyHash := scriptBytes[3:23] // Extract the 20-byte hash

		// Check if the hash matches the compressed or uncompressed public key
		compressedHash := btcutil.Hash160(pk.PubKey().SerializeCompressed())
		uncompressedHash := btcutil.Hash160(pk.PubKey().SerializeUncompressed())

		if bytes.Equal(pubKeyHash, compressedHash) {
			compress = true
		} else if bytes.Equal(pubKeyHash, uncompressedHash) {
			compress = false
		} else {
			return fmt.Errorf("public key hash does not match either compressed or uncompressed key")
		}

		fmt.Println("compress", compress)

		// P2PKH
		sigScript, err := txscript.SignatureScript(tx, idx, scriptBytes, txscript.SigHashAll, pk, compress)
		if err != nil {
			return fmt.Errorf("error creating signature script for P2PKH: %v", err)
		}
		tx.TxIn[idx].SignatureScript = sigScript

	case txscript.ScriptHashTy:
		// P2SH

		pubKeyHash := btcutil.Hash160(pk.PubKey().SerializeCompressed())
		redeemScript, err := txscript.NewScriptBuilder().
			AddOp(txscript.OP_0).
			AddData(pubKeyHash).
			Script()
		if err != nil {
			return fmt.Errorf("error creating redeem script: %v", err)
		}

		// Create the witness
		sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)
		witness, err := txscript.WitnessSignature(tx, sigHashes, idx, amount, redeemScript, txscript.SigHashAll, pk, compress)
		if err != nil {
			return fmt.Errorf("error creating witness for P2SH-P2WPKH: %v", err)
		}

		// Create the signature script that includes the redeem script
		builder := txscript.NewScriptBuilder()
		builder.AddData(redeemScript)
		sigScript, err := builder.Script()
		if err != nil {
			return fmt.Errorf("error creating signature script: %v", err)
		}

		tx.TxIn[idx].SignatureScript = sigScript
		tx.TxIn[idx].Witness = witness

	case txscript.WitnessV0PubKeyHashTy:
		// P2WPKH
		sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)
		witness, err := txscript.WitnessSignature(tx, sigHashes, idx, amount, scriptBytes, txscript.SigHashAll, pk, compress)
		if err != nil {
			return fmt.Errorf("error creating witness for P2WPKH: %v", err)
		}
		tx.TxIn[idx].Witness = witness

	case txscript.WitnessV1TaprootTy:
		// P2TR

		// Add all other inputs from the transaction
		for i, txIn := range tx.TxIn {
			if i != idx { // Skip our current input as we already added it
				// Get the previous transaction to get the actual output value and script
				prevTx, err := client.GetRawTransactionVerbose(&txIn.PreviousOutPoint.Hash)
				if err != nil {
					return fmt.Errorf("error getting previous transaction: %v", err)
				}

				// Get the output we're spending
				prevOut := prevTx.Vout[txIn.PreviousOutPoint.Index]
				prevAmount, _ := btcutil.NewAmount(prevOut.Value)
				prevScript, _ := hex.DecodeString(prevOut.ScriptPubKey.Hex)

				prevOutFetcher.AddPrevOut(txIn.PreviousOutPoint, &wire.TxOut{
					Value:    int64(prevAmount),
					PkScript: prevScript,
				})
			}
		}

		sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)
		// For Taproot, we need to ensure we're using the correct hash type
		// and that all inputs are considered in the signature hash calculation
		witness, err := txscript.TaprootWitnessSignature(tx, sigHashes, idx, amount, scriptBytes, txscript.SigHashAll, pk)
		if err != nil {
			return fmt.Errorf("error creating taproot witness: %v", err)
		}
		tx.TxIn[idx].Witness = witness

	// case txscript.WitnessV0ScriptHashTy: // we don't track P2SH-P2WPKH
	default:
		return fmt.Errorf("unsupported script type: %v", scriptClass)
	}

	return nil
}
