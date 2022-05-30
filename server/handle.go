package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/MetaBloxIO/metablox-foundation-services/credentials"
	"github.com/MetaBloxIO/metablox-foundation-services/did"
	"github.com/MetaBloxIO/metablox-foundation-services/key"
	"github.com/MetaBloxIO/metablox-foundation-services/models"
	"github.com/MetaBloxIO/metablox-foundation-services/presentations"
	"github.com/MetaBloxIO/miner_wallet/conf"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strconv"
)

const (
	Success int = iota
	ReqParamInvalid
	NonceInvalid
	VPInvalid
	SignatureInvalid
	ServerInnerError = 500
)

func InitRouter() *gin.Engine {
	conf, err := conf.LoadConf("./conf/config.json", "./conf/vc.json")
	if err != nil {
		log.Error("Load config file failed")
		return nil
	}

	pool := NewChallengePool()
	router := gin.New()

	router.POST("/challenge/:session", func(c *gin.Context) {
		session := c.Param("session")
		var req ChallengeRequest

		err := c.BindJSON(&req)
		if err != nil {
			sendError(ReqParamInvalid, nil, c)
			return
		}

		targetChallenge, err := strconv.ParseUint(req.Challenge, 10, 64)
		if err != nil {
			sendError(ReqParamInvalid, nil, c)
			return
		}

		challenge, _ := pool.ApplyChallenge(session, targetChallenge)

		resp := Response{Code: Success, Data: strconv.FormatUint(challenge, 10)}

		c.IndentedJSON(http.StatusOK, resp)
	})

	router.POST("/verifyVp", func(c *gin.Context) {
		var body models.VerifiablePresentation
		err := c.BindJSON(&body)
		session := c.GetHeader("session")
		challenge, err := strconv.ParseUint(body.Proof.Nonce, 10, 64)

		if err != nil {
			sendError(NonceInvalid, nil, c)
			return
		}

		pool.CheckChallenge(session, challenge)
		if err != nil {
			sendError(NonceInvalid, nil, c)
			return
		}

		if false == checkVcSubType(body.VerifiableCredential, models.TypeWifi) {
			sendError(VPInvalid, nil, c)
		}

		credentials.IssuerDID = body.VerifiableCredential[0].Issuer

		for i, _ := range body.VerifiableCredential {
			patchVCSubjects(&body.VerifiableCredential[i])
		}

		ret, err := presentations.VerifyVP(&body)
		if err != nil || ret == false {
			sendError(VPInvalid, nil, c)
			return
		}

		privKey, err := crypto.HexToECDSA(conf.PrivateKey)
		if err != nil {
			log.Error("Create key failed")
			sendError(ServerInnerError, nil, c)
			return
		}
		selfDoc := did.CreateDID(privKey)

		vcs := []models.VerifiableCredential{
			conf.MinerVC,
		}

		targetChallenge, err := pool.GetChallenge(session)
		if err != nil {
			log.Error("Get challenge failed")
			sendError(ServerInnerError, nil, c)
			return
		}

		respVp, err := presentations.CreatePresentation(vcs, *selfDoc, privKey, strconv.FormatUint(targetChallenge.TargetChallenge, 10))
		if err != nil {
			log.Error("Create vp failed")
			sendError(ServerInnerError, nil, c)
			return
		}

		pool.IncrTargetChallenge(session)
		pool.IncrSelfChallenge(session)

		resp := Response{Code: 0, Data: respVp}
		c.IndentedJSON(http.StatusOK, resp)
	})

	router.POST("/confirmNetwork", func(c *gin.Context) {
		var body NetworkConfirmRequest
		err := c.BindJSON(&body)
		if err != nil {
			sendError(ReqParamInvalid, nil, c)
			return
		}

		session := c.GetHeader("session")
		challenge, err := pool.GetChallenge(session)
		if err != nil {
			sendError(NonceInvalid, nil, c)
			return
		}

		//TODO Check Last blockchain

		result, err := verifyNetworkReq(&body, strconv.FormatUint(challenge.SelfChallenge, 10))
		if err != nil || result == false {
			sendError(ServerInnerError, nil, c)
			return
		}

		//TODO Get last blockchain

		privKey, err := crypto.HexToECDSA(conf.PrivateKey)
		if err != nil {
			sendError(ServerInnerError, nil, c)
			return
		}

		pubKeyBytes := crypto.FromECDSAPub(&privKey.PublicKey)
		pubkeyStr := base64.StdEncoding.EncodeToString(pubKeyBytes)

		respResult := NetworkConfirmResult{Did: conf.Did, Target: body.Did, PubKey: pubkeyStr, LastBlockHash: ""}
		signature, err := signNetworkResult(&respResult, privKey, strconv.FormatUint(challenge.TargetChallenge, 10))
		if err != nil || result == false {
			sendError(ServerInnerError, nil, c)
			return
		}
		respResult.Signature = signature

		resp := Response{Code: 0, Data: respResult}
		c.IndentedJSON(http.StatusOK, resp)
	})

	return router
}

func sendError(err int, data interface{}, c *gin.Context) {
	resp := Response{Code: err, Data: data}
	c.IndentedJSON(http.StatusOK, resp)
}

func checkVcSubType(credentials []models.VerifiableCredential, subType string) bool {
	for _, credential := range credentials {
		if credential.Type[1] == subType {
			return true
		}
	}

	return false
}

func patchVCSubjects(vc *models.VerifiableCredential) {
	subjectJsonStr, _ := json.Marshal(vc.CredentialSubject)
	if vc.Type[1] == models.TypeWifi {
		var wifiSubject models.WifiAccessInfo
		json.Unmarshal(subjectJsonStr, &wifiSubject)
		vc.CredentialSubject = wifiSubject
	} else if vc.Type[1] == models.TypeMining {
		var miningSubject models.MiningLicenseInfo
		json.Unmarshal(subjectJsonStr, &miningSubject)
		vc.CredentialSubject = miningSubject
	}
}

func verifyNetworkReq(req *NetworkConfirmRequest, challenge string) (bool, error) {
	bytes, err := serializeNetworkReq(req, challenge)

	if err != nil {
		log.Error("Serial")
		return false, err
	}

	resolutionMeta, holderDoc, _ := did.Resolve(req.Did, models.CreateResolutionOptions())
	if resolutionMeta.Error != "" {
		return false, errors.New(resolutionMeta.Error)
	}

	targetVM := holderDoc.VerificationMethod[0]

	hashedData := sha256.Sum256(bytes)
	pubData, err := base64.StdEncoding.DecodeString(req.PubKey)
	if err != nil {
		return false, err
	}

	pubKey, err := crypto.UnmarshalPubkey(pubData)
	if err != nil {
		return false, err
	}

	address := crypto.PubkeyToAddress(*pubKey)
	accountId := "eip155:1:" + address.Hex()

	if accountId != targetVM.BlockchainAccountId {
		return false, errors.New("pubkey and document mismatch")
	}

	return key.VerifyJWSSignature(req.Signature, pubKey, hashedData[:])
}

func serializeNetworkReq(req *NetworkConfirmRequest, challenge string) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString(req.Did)
	buffer.WriteString(req.Target)
	buffer.WriteString(req.LastBlockHash)
	buffer.WriteString(req.Quality)
	buffer.WriteString(req.PubKey)
	buffer.WriteString(challenge)

	return buffer.Bytes(), nil
}

func signNetworkResult(result *NetworkConfirmResult, privKey *ecdsa.PrivateKey, challenge string) (string, error) {
	bytes, err := serializeNetworkResult(result, challenge)

	if err != nil {
		log.Error("Serial")
		return "", err
	}

	hashedData := sha256.Sum256(bytes)

	return key.CreateJWSSignature(privKey, hashedData[:])
}

func serializeNetworkResult(result *NetworkConfirmResult, challenge string) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString(result.Did)
	buffer.WriteString(result.Target)
	buffer.WriteString(result.LastBlockHash)
	buffer.WriteString(result.PubKey)
	buffer.WriteString(challenge)

	return buffer.Bytes(), nil
}
