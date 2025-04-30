package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// Use MainNet parameters for generating real Bitcoin addresses
var netParams = &chaincfg.SigNetParams

func main() {
	var filename string
	flag.StringVar(&filename, "f", "", "The file containing the passwords to generate addresses for")

	var outputFile string
	flag.StringVar(&outputFile, "o", "addresses.csv", "The file to save the generated addresses to")

	var chain string
	flag.StringVar(&chain, "chain", "mainnet", "The chain to generate addresses for")

	var numWorkers int
	flag.IntVar(&numWorkers, "workers", runtime.NumCPU(), "The number of workers to use")

	flag.Parse()

	if filename == "" {
		log.Println("Error: -f is required")
		flag.Usage()
		os.Exit(1)
	}

	switch chain {
	case "mainnet":
		netParams = &chaincfg.MainNetParams
	case "testnet3":
		netParams = &chaincfg.TestNet3Params
	case "signet":
		netParams = &chaincfg.SigNetParams
	case "regtest":
		netParams = &chaincfg.RegressionNetParams
	default:
		log.Println("Error: -chain must be either 'mainnet', 'testnet3', 'signet' or 'regtest'")
		flag.Usage()
		os.Exit(1)
	}

	// Read passwords from file
	passwords, err := readPasswordsFromFile(filename)
	if err != nil {
		log.Println("Error reading password file:", err)
		return
	}

	log.Printf("Found %d passwords", len(passwords))
	log.Printf("Generating %d keys (uncompressed and compressed)", len(passwords)*2)

	// Create CSV file
	file, err := os.Create(outputFile)
	if err != nil {
		log.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	// Set up CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	err = writer.Write([]string{
		"Private Key (hex)",
		"Legacy (uncompressed P2PKH)",
		"Legacy (compressed P2PKH)",
		"Script (P2SH)",
		"Segwit (P2WPKH)",
		"Taproot (P2TR)",
		"Password",
	})
	if err != nil {
		log.Println("Error writing CSV header:", err)
		return
	}

	// Create a channel for results and a mutex for safe CSV writing
	var wg sync.WaitGroup
	//var writerMutex sync.Mutex

	// Create a counter for tracking overall progress
	var counter int64

	// Start worker goroutines
	wg.Add(numWorkers)

	// Divide passwords among workers
	passwordChunks := chunkPasswords(passwords, numWorkers)

	results := make(chan []string, 1000)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		for {
			select {
			case result := <-results:
				//writerMutex.Lock()
				err := writer.Write(result)
				//writerMutex.Unlock()
				if err != nil {
					log.Println("Error writing to CSV:", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Start workers
	for i := 0; i < numWorkers; i++ {
		go func(workerID int, passwordChunk []string) {
			defer wg.Done()

			for _, password := range passwordChunk {

				addresses, err := deriveAddressesFromPrivateKey(password, netParams)
				if err != nil {
					log.Println("Error deriving addresses:", err)
					continue
				}
				results <- addresses

				currentCount := atomic.AddInt64(&counter, 1)
				if currentCount%1000 == 0 {
					log.Printf("Progress: Generated %d/%d passwords (%.2f%%)\n",
						currentCount, len(passwords), float64(currentCount)/float64(len(passwords))*100)
				}
			}
		}(i, passwordChunks[i])
	}

	// Wait for all workers to complete
	wg.Wait()

	close(results)
	cancel()

	log.Printf("Successfully generated %d keys and saved to %s\n", len(passwords)*2, outputFile)
}

// Helper function to divide passwords into chunks for workers
func chunkPasswords(passwords []string, numChunks int) [][]string {
	chunks := make([][]string, numChunks)
	chunkSize := (len(passwords) + numChunks - 1) / numChunks

	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(passwords) {
			end = len(passwords)
		}

		if start < len(passwords) {
			chunks[i] = passwords[start:end]
		} else {
			chunks[i] = []string{} // Empty chunk if we've run out of passwords
		}
	}

	return chunks
}

func readPasswordsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password != "" {
			passwords = append(passwords, password)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return passwords, nil
}

// Generate a private key by hashing a word
func generatePrivateKeyFromWord(word string) *btcec.PrivateKey {
	hash := sha256.Sum256([]byte(word))

	privateKey, _ := btcec.PrivKeyFromBytes(hash[:])
	return privateKey
}

// Derive Bitcoin addresses from private key and return WIF format and addresses
func deriveAddressesFromPrivateKey(password string, net *chaincfg.Params) ([]string, error) {
	privateKey := generatePrivateKeyFromWord(password)

	wif, _ := btcutil.NewWIF(privateKey, net, true)

	pubkey := wif.PrivKey.PubKey()

	uncompressedKey := btcutil.Hash160(pubkey.SerializeUncompressed())
	compressedKey := btcutil.Hash160(pubkey.SerializeCompressed())

	// Create pay-to-pubkey-hash address (starts with 1)
	p2pkhUncompressedAddress, err := btcutil.NewAddressPubKeyHash(uncompressedKey, net)
	if err != nil {
		log.Fatalf("error creating P2PKH address: %v", err)
	}

	p2pkhCompressedAddress, _ := btcutil.NewAddressPubKeyHash(compressedKey, net)

	// Create pay-to-witness-pubkey-hash address (starts with bc1)
	p2wpkhAddress, err := btcutil.NewAddressWitnessPubKeyHash(compressedKey, net)
	if err != nil {
		log.Fatalf("error creating P2WPKH address: %v", err)
	}

	witnessProgram, err := txscript.PayToAddrScript(p2wpkhAddress)
	if err != nil {
		log.Fatalf("error creating witness program: %v", err)
	}

	// Create pay-to-script-hash address (starts with 3)
	p2shAddress, err := btcutil.NewAddressScriptHash(witnessProgram, net)
	if err != nil {
		log.Fatalf("error creating P2SH address: %v", err)
	}

	tapKey := txscript.ComputeTaprootKeyNoScript(pubkey) // 32-byte x-only

	// taproot
	p2trAddress, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), net)
	if err != nil {
		log.Fatalf("error creating P2TR address: %v", err)
	}

	return []string{
		hex.EncodeToString(privateKey.Serialize()),
		p2pkhUncompressedAddress.String(),
		p2pkhCompressedAddress.String(),
		p2shAddress.String(),
		p2wpkhAddress.String(),
		p2trAddress.String(),
		password,
	}, nil
}
