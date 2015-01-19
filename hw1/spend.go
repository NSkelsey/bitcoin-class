package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/btcsuite/btcec"
	"github.com/btcsuite/btcjson"
	"github.com/btcsuite/btcnet"
	"github.com/btcsuite/btcscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwire"
)

/*

For this program to execute correctly the following needs to be provided:

A private key
A receiving address
The raw json of the funding transaction

The output of the program will be a valid bitcoin transaction encoded as hex
which can be submitted to any bitcoin client or website that accepts raw hex
transactions. For example: https://blockchain.info/pushtx

*/

var a = flag.String("address", "", "The address to send Bitcoin to")
var k = flag.String("privkey", "", "The private key of the input tx")

// getArgs parses command line args and asserts that a private key and an
// address are present and correctly formatted.
func getArgs() (*btcec.PrivateKey, *btcutil.AddressPubKeyHash) {
	flag.Parse()
	if *a == "" || *k == "" {
		fmt.Println("You must provide a key and an address!")
		flag.PrintDefaults()
		os.Exit(0)
	}

	pkBytes, err := hex.DecodeString(*k)
	if err != nil {
		log.Fatal(err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), pkBytes)

	addr, err := btcutil.DecodeAddress(*a, &btcnet.MainNetParams)
	if err != nil {
		log.Fatal(err)
	}

	return privKey, addr.(*btcutil.AddressPubKeyHash)
}

func readJsonFile(path string) *btcjson.TxRawResult {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	rawTx := &btcjson.TxRawResult{}
	err = json.Unmarshal(b, rawTx)
	if err != nil {
		log.Fatal(err)
	}
	// Check to see if the version field was populated on the unmarshal.
	if rawTx.Version == 0 {
		log.Fatalf("The unmarshal failed and produced: %v\n", rawTx)
	}

	return rawTx
}

// getFundingParams pulls the relevant transaction information from TxRawResult.
// To generate a new valid transaction all of the parameters of the TxOut we are
// spending from must be used.
func getFundingParams(rawtx *btcjson.TxRawResult) (int64, *btcwire.OutPoint, []byte) {
	txout := rawtx.Vout[0]

	hash, err := btcwire.NewShaHashFromStr(rawtx.Txid)
	if err != nil {
		log.Fatal(err)
	}

	amnt, err := btcutil.NewAmount(txout.Value)
	if err != nil {
		log.Fatal(err)
	}

	outpoint := btcwire.NewOutPoint(hash, txout.N)

	subscript, err := hex.DecodeString(txout.ScriptPubKey.Hex)
	if err != nil {
		log.Fatal(err)
	}
	return int64(amnt), outpoint, subscript
}

func main() {
	// Pull the private key and the send to address off of the command line.
	privKey, addr := getArgs()

	// Load bitcoin tx json from a file. It must be in the raw RPC json format.
	rawFundingTx := readJsonFile("tx.json")

	// Get the parameters we need from the funding transaction
	inCoin, outpoint, scriptPubK := getFundingParams(rawFundingTx)

	// Formulate a new transaction from the provided parameters
	tx := btcwire.NewMsgTx()

	// Create the TxIn
	txin := createTxIn(outpoint)
	tx.AddTxIn(txin)

	// Create the TxOut
	txout := createTxOut(inCoin, addr)
	tx.AddTxOut(txout)

	// Generate a signature over the whole tx.
	sig := generateSig(tx, privKey, scriptPubK)
	tx.TxIn[0].SignatureScript = sig

	// Dump the bytes to stdout
	dumpHex(tx)
}

// createTxIn pulls the outpoint out of the funding TxOut and uses it as a reference
// for the txin that will be placed in a new transaction.
func createTxIn(outpoint *btcwire.OutPoint) *btcwire.TxIn {
	// The second arg is the txin's signature script, which we are leaving empty
	// until the entire transaction is ready.
	txin := btcwire.NewTxIn(outpoint, []byte{})
	return txin
}

// createTxOut generates a TxOut can be added to a transaction. Instead of sending
// every coin in the txin to the target address, a fee 10,000 Satoshi is set aside.
// If this fee is left out then, nodes on the network will ignore the transaction,
// since they would otherwise be providing you a service for free.
func createTxOut(inCoin int64, addr *btcutil.AddressPubKeyHash) *btcwire.TxOut {
	// Pay the minimum network fee so that nodes will broadcast the tx.
	outCoin = inCoin - 10000
	txout := btcwire.NewTxOut(outCoin, addr.ScriptAddress())
	return txout
}

// generateSig requires a transaction, a private key, and the bytes of the raw
// scriptPubKey. It will then generate a signature over all of the outputs of
// the provided tx. This is the last step of creating a valid transaction.
func generateSig(tx *btcwire.MsgTx, privkey *btcec.PrivateKey, scriptPubKey []byte) []byte {

	// The all important signature. Each input is documented below.
	scriptSig, err := btcscript.SignatureScript(
		tx,                   // The tx to be signed.
		0,                    // The index of the txin the signature is for.
		scriptPubKey,         // The other half of the script from the PubKeyHash.
		btcscript.SigHashAll, // The signature flags that indicate what the sig covers.
		privkey,              // The key to generate the signature with.
		true,                 // The compress sig flag. This saves space on the blockchain.
	)
	if err != nil {
		log.Fatal(err)
	}

	return scriptSig
}

// dumpHex dumps the raw bytes of a Bitcoin transaction to stdout. This is the
// format that Bitcoin wire's protocol accepts, so you could connect to a node,
// send them these bytes, and if the tx was valid, the node would forward the
// tx through the network.
func dumpHex(tx *btcwire.MsgTx) {
	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	tx.Serialize(buf)
	hexstr := hex.EncodeToString(buf.Bytes())
	fmt.Println(hexstr)
}
