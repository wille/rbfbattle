package main

import (
	"log"

	"github.com/btcsuite/btcd/rpcclient"
)

func connectToBitcoinNode(config *Config) *rpcclient.Client {
	user := config.RPCUser
	pass := config.RPCPassword

	host := config.RPCHost
	if config.RPCWallet != "" {
		host += "/wallet/" + config.RPCWallet
	}

	log.Printf("Connecting to node %s", host)

	connCfg := &rpcclient.ConnConfig{
		Host:         host,
		User:         user,
		Pass:         pass,
		CookiePath:   config.RPCCookiePath,
		HTTPPostMode: true,
		DisableTLS:   true,
	}

	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		log.Fatalf("Error connecting to Bitcoin node: %v", err)
	}

	// Test connection
	blockCount, err := client.GetBlockCount()
	if err != nil {
		log.Fatalf("Error connecting to Bitcoin node: %v", err)
	}

	log.Printf("Successfully connected to Bitcoin node. Current block height: %d", blockCount)
	return client
}
