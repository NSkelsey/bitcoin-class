package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/btcsuite/btcec"
	"github.com/btcsuite/btcjson"
	"github.com/btcsuite/btcnet"
	"github.com/btcsuite/btcscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwire"
)

/*

For this program to execute correctly the following needs to be provided:

tx Outpoint (prevTxHash, vout)
Value at the Outpoint
PrivateKey

The output of the program will be a valid bitcoin transaction encoded as hex
which can be submitted to any bitcoin client or website that accepts raw hex
transactions. For example: https://blockchain.info/pushtx

*/

func getArgs() (*btcec.PrivateKey, *btcutil.AddressPubKeyHash) {
	pkBytes, err := hex.DecodeString("22a47fa09a223f2aa079edf85a7c2d4f87" +
		"20ee63e502ee2869afab7de234b80c")
	if err != nil {
		log.Fatal(err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), pkBytes)

	s := "1DTFjSGeij6woxyaJFaYLMzciKCYP83ZNB"
	addr, err := btcutil.DecodeAddress(s, &btcnet.MainNetParams)
	if err != nil {
		log.Fatal(err)
	}

	return privKey, addr
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

func getFundingParams(rawtx *btcjson.TxRawResult) (int64, *btcwire.OutPoint, []byte) {
	txOut := rawTx.Vout[0]

	txHash, err := btcwire.NewShaHashFromStr(rawTx.Txid)
	if err != nil {
		log.Fatal(err)
	}

	amnt, err := btcutil.Amount(txOut.Value)
	if err != nil {
		log.Fatal(err)
	}

	outpoint := btcwire.NewOutPoint(txHash, txOut.N)

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
	inCoin, outpoint, subS := getFundingParams(rawFundingTx)

	// Formulate a new transaction from the provided parameters
	tx := btcwire.NewMsgTx()

	// Create the TxIn
	txin := createTxIn(outpoint)
	tx.AddTxIn(txin)

	// Create the TxOut
	txout := createTxOut(inCoin, addr)
	tx.AddTxOut(txout)

	// Generate a signature over the partially complete tx.
	sig := generateSig(tx, privkey, subS)
	tx.TxIn[0].SignatureScript = sig

	// Dump the bytes to stdout
	dumpHex(tx)
}

func createTxIn(outpoint *btcwire.OutPoint) *btcwire.TxIn {
	// The second arg is the txin's signature script, which we are leaving empty
	// until the entire transaction is ready.
	txin := btcwire.NewTxIn(outpoint, []byte{})
	return txin
}

func createTxOut(inCoin int32, addr *btcutil.AddressPubKeyHash) *btcwire.TxOut {
	txout := btcwire.NewTxOut(inCoin, addr.ScriptAddress())
	return txout
}

func generateSig(tx *btcwire.MsgTx, privkey *btcec.PrivateKey, subscript []byte) []byte {

	// The all important signature
	scriptSig, err := btcscript.SignatureScript(
		tx,
		0,
		subscript,
		btcscript.SigHashAll,
		privkey,
		true,
	)
	if err != nil {
		log.Fatal(err)
	}

	return scriptSig
}

func dumpHex(tx *btcwire.MsgTx) {
	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	tx.Serialize(buf)
	hexstr := hex.EncodeToString(buf.Bytes())
	fmt.Println(hexstr)
}
