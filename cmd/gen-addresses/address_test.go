package main

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
)

var network = &chaincfg.MainNetParams

func TestGeneratePrivateKeyFromWord(t *testing.T) {
	word := "bitcoin is awesome"
	list, err := deriveAddressesFromPrivateKey(word, &chaincfg.MainNetParams)
	if err != nil {
		t.Errorf("error deriving addresses: %v", err)
	}

	if list[0] != "23d4a09295be678b21a5f1dceae1f634a69c1b41775f680ebf8165266471401b" {
		t.Errorf("private key is wrong. received %s", list[0])
	}

	if list[1] != "14NWDXkQwcGN1Pd9fboL8npVynD5SfyJAE" {
		t.Errorf("uncompressed legacy p2pkh address is wrong. received %s", list[1])
	}

	if list[2] != "1JRW4d8vHZseMEtYbgJ7MwPG1TasHUUVNq" {
		t.Errorf("compressed legacy p2pkh address is wrong. received %s", list[2])
	}

	if list[3] != "3LtPxQEqqo1sYGF7VTEufzBUki6pFiDVa1" {
		t.Errorf("p2sh address is wrong. received %s", list[3])
	}

	if list[4] != "bc1qhuwxrtqe2akhr4rz8vv97waw9g75ma4unk5vnf" {
		t.Errorf("p2wpkh address is wrong. received %s", list[4])
	}

	if list[5] != "bc1pclm3u06yang46craktcg2ellcpsvuqxm33n3a2jxajq06rea7cws0vrplv" {
		t.Errorf("p2tr address is wrong. received %s", list[5])
	}
}
