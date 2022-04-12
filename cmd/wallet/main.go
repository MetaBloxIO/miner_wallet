package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"log"

	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	conn, err := ethclient.Dial("https://api.s0.b.hmny.io")
	if err != nil {
		log.Fatal("Whoops something went wrong!", err)
		return
	}

	ctx := context.Background()
	privateKey, err := crypto.HexToECDSA("fa4036001975229cdd22d3b02302b7282e21dcae04a0c1efe1844de8c8576b4f")
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	fmt.Println("SAVE BUT DO NOT SHARE THIS (Private Key):", hexutil.Encode(privateKeyBytes))

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	fmt.Println("Public Key:", hexutil.Encode(publicKeyBytes))

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	balance, err := conn.BalanceAt(ctx, address, nil)
	if err != nil {
		log.Fatal("Get balance error", err)
		return
	}

	log.Print("balance value ", balance)
}
