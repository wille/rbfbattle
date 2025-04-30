package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/jessevdk/go-flags"
)

// Config holds the application configuration
type Config struct {
	ConfigFile string `short:"f" long:"config" description:"The path to the configuration file" default:"rbfbattle.conf"`
	// Required settings
	DestinationAddress        string `short:"d" long:"destinationaddress" description:"The destination address to send the funds to" required:"true"`
	decodedDestinationAddress btcutil.Address

	BurnMessage string `short:"m" long:"burnmessage" description:"Message to include in OP_RETURN when burning" default:"github.com/wille/rbfbattle"`

	Chain string `short:"c" long:"chain" description:"The chain to use (mainnet, testnet3, signet, regtest)" default:"regtest"`

	// Bitcoin node connection settings
	RPCHost       string `long:"rpchost" description:"The host of the Bitcoin node" default:"localhost"`
	RPCUser       string `long:"rpcuser" description:"The username of the Bitcoin node"`
	RPCPassword   string `long:"rpcpass" description:"The password of the Bitcoin node"`
	RPCCookiePath string `long:"rpccookie" description:"The path to the Bitcoin node cookie file"`
	RPCWallet     string `long:"rpcwallet" description:"The wallet to use for the Bitcoin node"`

	// ZMQ settings
	ZMQ string `short:"z" long:"zmq" description:"The ZMQ endpoint to use" default:"tcp://127.0.0.1:18503"`

	// Additional settings
	AddressFile string `short:"a" long:"addressfile" description:"The file containing the addresses to use" default:"addresses.csv"`
}

// LoadConfig loads the configuration from the specified file
func LoadConfig() (*Config, error) {
	cfg := &Config{}

	configFile := "rbfbattle.conf"
	if f := os.Getenv("CONFIG"); f != "" {
		configFile = f
	}

	parser := flags.NewParser(cfg, flags.Default)
	err := flags.NewIniParser(parser).ParseFile(configFile)
	if err != nil {
		if _, ok := err.(*os.PathError); !ok {
			parser.WriteHelp(os.Stderr)
			return nil, err
		}
	}

	// Parse command line options again to ensure they take precedence.
	_, err = parser.Parse()
	if err != nil {
		parser.WriteHelp(os.Stdout)
		os.Exit(0)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate checks if all required configuration fields are set
func (c *Config) validate() error {
	var defaultPort string
	var defaultRPCCookiePath string

	switch c.Chain {
	case "", "mainnet":
		network = &chaincfg.MainNetParams
		defaultPort = "8332"
		defaultRPCCookiePath = "~/.bitcoin/.cookie"
	case "testnet3":
		network = &chaincfg.TestNet3Params
		defaultPort = "18332"
		defaultRPCCookiePath = "~/.bitcoin/testnet3/.cookie"
	case "signet":
		network = &chaincfg.SigNetParams
		defaultPort = "38332"
		defaultRPCCookiePath = "~/.bitcoin/signet/.cookie"
	case "regtest":
		network = &chaincfg.RegressionNetParams
		defaultPort = "18443"
		defaultRPCCookiePath = "~/.bitcoin/regtest/.cookie"
	default:
		return fmt.Errorf("invalid chain: %s", c.Chain)
	}

	host, port, _ := net.SplitHostPort(c.RPCHost)
	if host == "" {
		host = "127.0.0.1"
	}
	if port == "" {
		port = defaultPort
	}
	c.RPCHost = fmt.Sprintf("%s:%s", host, port)
	_, _, err := net.SplitHostPort(c.RPCHost)
	if err != nil {
		return fmt.Errorf("invalid rpchost: %s", c.RPCHost)
	}

	if c.RPCCookiePath == "" {
		c.RPCCookiePath = defaultRPCCookiePath
	}
	c.RPCCookiePath = expandPath(c.RPCCookiePath)

	c.decodedDestinationAddress, err = btcutil.DecodeAddress(c.DestinationAddress, network)
	if err != nil {
		return fmt.Errorf("invalid destination address: %s", c.DestinationAddress)
	}

	return nil
}

// expandPath expands the ~ character to the user's home directory
func expandPath(path string) string {
	if strings.HasPrefix(path, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return strings.Replace(path, "~", homeDir, 1)
	}
	return path
}
