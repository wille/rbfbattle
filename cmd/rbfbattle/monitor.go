package main

import "strconv"

// txid -> vout
var monitoredUtxos = make(map[string]*TrackedUTXO)

func monitor(utxo *TrackedUTXO) {
	id := utxo.TxID + ":" + strconv.Itoa(int(utxo.N))
	monitoredUtxos[id] = utxo
}

func cleanup(utxo *TrackedUTXO) {
	delete(monitoredUtxos, utxo.TxID+":"+strconv.Itoa(int(utxo.N)))
}
