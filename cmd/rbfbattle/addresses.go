package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"
)

type PrivateKey struct {
	PrivateKeyHex string
}

// Map to store our addresses and private keys
var ourAddresses = make(map[string]string) // address -> private key (WIF)

// loadAddressesAndKeys loads our addresses and private keys from the CSV file
func loadAddressesAndKeys(filename string) error {
	log.Printf("Loading addresses and keys from %s", filename)
	// Open the CSV file
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("error opening keys file: %v", err)
	}
	defer file.Close()

	// Create a CSV reader
	reader := csv.NewReader(file)

	// Read the header
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("error reading CSV header: %v", err)
	}

	// Check if the header has the expected format
	if len(header) != 7 || !strings.Contains(header[0], "Private Key") || !strings.Contains(header[1], "P2PKH") {
		return fmt.Errorf("unexpected CSV header format: %v", header)
	}

	// Read the rest of the records
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("error reading CSV records: %v", err)
	}

	// Process each record
	for _, record := range records {
		if len(record) < 2 {
			log.Printf("Warning: Skipping invalid record: %v", record)
			continue
		}

		wif := record[0]

		p2pkh := record[1]
		p2pkhCompressed := record[2]
		p2sh := record[3]
		p2wpkh := record[4]
		p2tr := record[5]

		// Add to our map
		ourAddresses[p2pkh] = wif
		ourAddresses[p2pkhCompressed] = wif
		ourAddresses[p2sh] = wif
		ourAddresses[p2wpkh] = wif
		ourAddresses[p2tr] = wif
	}

	log.Printf("Loaded %d addresses from %s", len(ourAddresses), filename)
	return nil
}
