package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/pebbe/zmq4"
)

// monitorMempoolWithZMQ subscribes to ZeroMQ notifications for new transactions
func monitorMempoolWithZMQ(client *rpcclient.Client, config *Config) {
	log.Println("Starting ZeroMQ mempool monitoring...")

	// Initialize ZMQ context and subscriber
	context, err := zmq4.NewContext()
	if err != nil {
		log.Fatalf("Failed to create ZMQ context: %v", err)
	}
	defer context.Term()

	subscriber, err := context.NewSocket(zmq4.SUB)
	if err != nil {
		log.Fatalf("Failed to create ZMQ subscriber socket: %v", err)
	}
	defer subscriber.Close()

	// Connect to the ZMQ endpoint
	if err := subscriber.Connect(config.ZMQ); err != nil {
		log.Fatalf("Failed to connect to ZMQ endpoint %s: %v", config.ZMQ, err)
	}

	// Subscribe to transaction topics
	// "hashtx" for transaction hashes
	// if err := subscriber.SetSubscribe("rawtx"); err != nil {
	// 	log.Fatalf("Failed to subscribe to rawtx topic: %v", err)
	// }

	if err := subscriber.SetSubscribe("hashtx"); err != nil {
		log.Fatalf("Failed to subscribe to hashtx topic: %v", err)
	}

	log.Printf("Successfully subscribed to ZMQ endpoint %s", config.ZMQ)

	// Process incoming messages
	for {
		// Receive multipart message (topic, body, ...)
		msgs, err := subscriber.RecvMessageBytes(0)
		if err != nil {
			log.Printf("Error receiving ZMQ message: %v", err)
			continue
		}

		if len(msgs) < 2 {
			log.Printf("Received incomplete ZMQ message")
			continue
		}

		topic := string(msgs[0])
		body := msgs[1]

		// Process based on topic
		switch topic {
		case "rawtx":
			decoded, err := client.DecodeRawTransaction(body)
			fmt.Println("rawtx", decoded)
			if err != nil {
				log.Printf("Error decoding raw transaction: %v", err)
				continue
			}
			rawTransactionQueue <- decoded
		case "hashtx":
			// For hashtx, we receive the transaction hash and need to fetch the full transaction
			txid := hex.EncodeToString(body)
			txHash, err := chainhash.NewHashFromStr(txid)
			if err != nil {
				log.Printf("Error parsing transaction hash from hashtx: %v", err)
				continue
			}

			// Get the full transaction details
			tx, err := client.GetRawTransactionVerbose(txHash)
			if err != nil {
				// For our own transactions this is gonna fail as zmq sends the hashtx event before it's available in our local mempool
				log.Printf("Error getting transaction %s: %v", txid, err)
				continue
			}

			rawTransactionQueue <- tx
		default:
			log.Printf("Received unknown ZMQ topic: %s", topic)
		}
	}
}
