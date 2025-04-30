package main

import (
	"log"

	"github.com/btcsuite/btcd/btcutil"
)

// newFee tries to calculate a new feeRate to replace a counterpart transaction.
// If the new calculated fee is too high, try to burn the transaction
// See the current Replace-By-Fee rules:
// https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md
func newFee(attackingFee btcutil.Amount, attackingTxSize, ourEstimatedTxSize int32, utxo *TrackedUTXO) (newFee btcutil.Amount, burn bool) {
	originalFeeRate := float64(attackingFee) / float64(attackingTxSize)

	// New fee rate increased with 1 sat/vbyte and 10% higher than the counterpart transaction
	newFeeRate := 1 + originalFeeRate*1.1

	newFee = btcutil.Amount(float64(ourEstimatedTxSize) * newFeeRate)

	log.Printf("newFee=%d, originalFee: %d, estimatedTxSize: %d, originalFeeRate: %f, newFeeRate: %f", newFee, attackingFee, ourEstimatedTxSize, originalFeeRate, newFeeRate)

	if newFee >= utxo.Amount {
		burn = true
	}

	return newFee, burn
}
