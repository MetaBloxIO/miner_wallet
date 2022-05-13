package server

import (
	"github.com/MetaBloxIO/metablox-foundation-services/did"
	"github.com/MetaBloxIO/metablox-foundation-services/models"
	"github.com/MetaBloxIO/metablox-foundation-services/presentations"
	"github.com/MetaBloxIO/miner_wallet/conf"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/multiformats/go-multibase"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"time"
)

const (
	Success int = iota
	ReqParamInvalid
	NonceInvalid
	VPInvalid
	ServerInnerError = 500
)

func InitRouter() *gin.Engine {
	conf, err := conf.LoadConf("./conf/config.json")
	if err != nil {
		log.Error("Load config file failed")
		return nil
	}

	pool := NewChallengePool()
	router := gin.New()

	router.GET("/challenge/:session", func(c *gin.Context) {
		session := c.Param("session")
		var req ChallengeRequest

		err := c.BindJSON(&req)
		if err != nil {
			sendError(ReqParamInvalid, nil, c)
			return
		}

		targetChallenge, err := strconv.ParseUint(req.challenge, 10, 64)
		if err != nil {
			sendError(ReqParamInvalid, nil, c)
			return
		}

		challenge, _ := pool.ApplyChallenge(session, targetChallenge)

		resp := Response{code: Success, data: challenge}

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

		ret, err := presentations.VerifyVP(&body)
		if err != nil || ret == false {
			sendError(VPInvalid, nil, c)
			return
		}

		//TODO 2. Create response vp

		selfDoc, err := createDid(conf.PrivateKey, conf.Did)
		if err != nil {
			log.Error("Create did document failed")
			sendError(ServerInnerError, nil, c)
			return
		}

		vcs := []models.VerifiableCredential{
			conf.MinerVC,
		}

		privKey, err := crypto.HexToECDSA(conf.PrivateKey)
		if err != nil {
			log.Error("Create key failed")
			sendError(ServerInnerError, nil, c)
			return
		}

		targetChallenge, err := pool.GetTargetChallenge(session)
		if err != nil {
			log.Error("Get challenge failed")
			sendError(ServerInnerError, nil, c)
			return
		}

		respVp, err := presentations.CreatePresentation(vcs, selfDoc, privKey, strconv.FormatUint(targetChallenge, 10))
		if err != nil {
			log.Error("Create vp failed")
			sendError(ServerInnerError, nil, c)
			return
		}

		pool.IncrTargetChallenge(session)
		pool.IncrSelfChallenge(session)

		resp := Response{code: 0, data: respVp}
		c.IndentedJSON(http.StatusOK, resp)
	})

	router.POST("/confirmNetwork", func(c *gin.Context) {
	})

	return router
}

func sendError(err int, data interface{}, c *gin.Context) {
	resp := Response{code: err, data: data}
	c.IndentedJSON(http.StatusOK, resp)
}

func checkVcSubType(credentials []models.VerifiableCredential, subType string) bool {
	for _, credential := range credentials {
		if credential.SubType == subType {
			return true
		}
	}

	return false
}

func createDid(privKeyHex string, didStr string) (*models.DIDDocument, error) {
	document := new(models.DIDDocument)
	privKey, err := crypto.HexToECDSA(privKeyHex)
	if err != nil {
		return nil, err
	}

	if len(didStr) > 0 {
		document.ID = didStr
	} else {
		document.ID = did.GenerateDIDString(privKey)
	}
	document.Context = make([]string, 0)
	document.Context = append(document.Context, models.ContextDID)
	document.Context = append(document.Context, models.ContextSecp256k1)
	document.Created = time.Now().Format(time.RFC3339)
	document.Updated = document.Created
	document.Version = 1

	pubData := crypto.FromECDSAPub(&privKey.PublicKey)

	VM := models.VerificationMethod{}
	VM.ID = document.ID + "#verification"
	VM.MultibaseKey, err = multibase.Encode(multibase.Base58BTC, pubData)
	if err != nil {
		return nil, err
	}
	VM.Controller = document.ID
	VM.MethodType = models.Secp256k1Key

	document.VerificationMethod = append(document.VerificationMethod, VM)
	document.Authentication = VM.ID

	//once blockchain is implemented, will also need to upload the document to the blockchain

	return document, nil
}
