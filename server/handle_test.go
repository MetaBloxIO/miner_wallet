package server

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestSignNetwork(t *testing.T) {
	privKey, _ := crypto.HexToECDSA("0ceec339202427e5670793d2da294235f078232ce97c8040d36e85bf895cd0a6")

	pubKeyBytes := crypto.FromECDSAPub(&privKey.PublicKey)
	pubkeyStr := base64.StdEncoding.EncodeToString(pubKeyBytes)

	result := NetworkConfirmResult{
		Did:           "did:metablox:7w3VndqhPNrf5yzVfZnwTiGrctYULdRdnsEVZ5Zt5YWa",
		Target:        "did:metablox:7w3VndqhPNrf5yzVfZnwTiGrctYULdRdnsEVZ5Zt5YWa",
		LastBlockHash: "",
		PubKey:        pubkeyStr,
		Challenge:     "1",
	}

	for i := 1; i < 5; i++ {
		sigStr, err := signNetworkResult(&result, privKey)
		assert.Nil(t, err)

		sig, err := base64.StdEncoding.DecodeString(sigStr)
		assert.Nil(t, err)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])

		resultBytes, _ := serializeNetworkResult(&result)
		hashedData := sha256.Sum256(resultBytes)

		assert.Equal(t, ecdsa.Verify(&privKey.PublicKey, hashedData[:], r, s), true)
	}

}
