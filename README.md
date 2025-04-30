# rbfbattle

Engage in RBF battles with your own Bitcoin node.


## Different types of counterparts

There are many RBF battlebots running on the bitcoin mainnet. It's very unlikely that you will win any sats because some counterpart will most likely burn the full value of the UTXO and [leave an OP_RETURN output in the blockchain](https://mempool.space/tx/7f9735910e0012567953ede37bbf1032179bdc69c6f15cefbd018252f02fa06c
)

Some observed types of different strategies

### 1. Simple feebump

A regular transaction with one input and one output.
Will eventually hit the dust limit of 547 sats on the output and loose to someone burning the transaction or someone having a secondary input.

### 2. Feebump with another input

Transaction has 2 inputs and 1 output which makes the attacker able to use the full amount of the utxo and not hit the dust limit

Example transaction winning 7 sats in a RBF battle
https://mempool.space/tx/983046255053f27ee9164e9e371ad14e8a2e486f072110605b3b17164e9903c0

### 3. Burners

Spends full value of the utxo on fees with an empty OP_RETURN output with a message.

Example OP_RETURN: https://mempool.space/tx/7f9735910e0012567953ede37bbf1032179bdc69c6f15cefbd018252f02fa06c

## Usage

Any utxo in your specified rpcwallet with a reasonable value will be considered for use as an input along with the utxo we're trying to spend so we truly can try to spend very low satoshi values without hitting the 547 sats dust limit on an output.

The bot will try to increase the fee by at least 1 sat/vbyte + 10% of the counterpart feerate and if the new fee is higher than the utxo value, we're burning the transaction with an OP_RETURN.


## Options

```properties
# rbfbattle.conf

destinationaddress=bc1p...

# Optional
rpchost=127.0.0.1:18433
rpccookie=~/.bitcoin/regtest/.cookie
chain=regtest
rpcwallet=test
zmq=tcp://127.0.0.1:18502
addressfile=addresses.csv
burnmessage=rbfbattle
```

## Generating brain wallets from a password list

```
go run ./cmd/gen-addresses -f password-list.txt -chain=mainnet
```


## Resources

https://en.bitcoin.it/wiki/Replace_by_fee

https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md


### WHAT DOESN'T WORK?

Compressed addresses
Sending to taproot... (test)
TapRoot inputs

When watched tx vout index is more than 0 https://mempool.space/tx/89855f8e431916c0a9ed0c0388fb7992c35e5e531079937c9fe7c3c8ae1d7243#vin=1s