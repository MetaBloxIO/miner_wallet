package server

import (
	"github.com/MetaBloxIO/metablox-foundation-services/models"
	"github.com/MetaBloxIO/metablox-foundation-services/presentations"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

const (
	Success int = iota
	NonceInvalid
	VPInvalid
)

func InitRouter() *gin.Engine {
	pool := NewChallengePool()
	router := gin.New()

	router.GET("/challenge/:session", func(c *gin.Context) {
		session := c.Param("session")
		challenge, _ := pool.ApplyChallenge(session)

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
		respVp := models.VerifiablePresentation{}

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
