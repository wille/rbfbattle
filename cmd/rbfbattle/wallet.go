package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"sort"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
)

var (
	unspentUtxo *btcjson.ListUnspentResult

	errNoUsableUtxo = fmt.Errorf("no usable utxo in wallet. make sure that the correct wallet is loaded and that you have at least one confirmed utxo with value between %f BTC and %f BTC", lowestValueUtxo, highestValueUtxo)
)

const (
	highestValueUtxo = 500.10000000
	lowestValueUtxo  = 0.00001000
)

// selectUnspentUtxo selects the smallest spendable utxo.
//
// We need to select a confirmed utxo because of RBF rule #2
// > The replacement transaction only include an unconfirmed input if that input was included in one of the directly conflicting transactions.
//
// https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md
func selectUnspentUtxo(client *rpcclient.Client) (btcjson.ListUnspentResult, error) {
	if unspentUtxo != nil {
		return *unspentUtxo, nil
	}

	unspent, err := client.ListUnspentMin(1)

	if len(unspent) == 0 {
		return btcjson.ListUnspentResult{}, errNoUsableUtxo
	}

	if err != nil {
		return btcjson.ListUnspentResult{}, err
	}

	// Pick the lowest value utxo first
	sort.Slice(unspent, func(i, j int) bool {
		return unspent[i].Amount < unspent[j].Amount
	})

	for _, utxo := range unspent {
		if utxo.Spendable && utxo.Amount < highestValueUtxo && utxo.Amount > lowestValueUtxo {
			unspentUtxo = &utxo
			break
		}
	}

	if unspentUtxo == nil {
		return btcjson.ListUnspentResult{}, errNoUsableUtxo
	}

	script, err := hex.DecodeString(unspentUtxo.ScriptPubKey)
	if err != nil {
		return btcjson.ListUnspentResult{}, err
	}

	scriptClass := txscript.GetScriptClass(script)

	log.Printf("Selected utxo: %s:%d, %f BTC (%s)", unspentUtxo.TxID, unspentUtxo.Vout, unspentUtxo.Amount, scriptClass.String())

	return *unspentUtxo, nil
}
