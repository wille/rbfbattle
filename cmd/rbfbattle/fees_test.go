package main

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil"
)

func btc(amount float64) btcutil.Amount {
	b, _ := btcutil.NewAmount(amount)
	return b
}

func TestNewFee(t *testing.T) {
	utxo := &TrackedUTXO{
		Amount: btc(1),
	}

	attackingFee := btc(0.9999_9999)
	attackingTxSize := int32(100)
	ourEstimatedTxSize := int32(250)

	newFee, burn := newFee(attackingFee, attackingTxSize, ourEstimatedTxSize, utxo)

	if newFee < attackingFee+btcutil.Amount(ourEstimatedTxSize) {
		t.Fatalf("newFee is increasing less than 1 sat/vbyte")
	}

	if newFee >= utxo.Amount && !burn {
		t.Fatalf("newFee is greater than the utxo amount")
	}
}
