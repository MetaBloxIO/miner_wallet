package server

import (
	"github.com/MetaBloxIO/miner_wallet/models"
	"github.com/gin-gonic/gin"
	"net/http"
)

func InitRouter() *gin.Engine {
	pool := NewChallengePool()
	router := gin.New()

	router.GET("/challenge/:session", func(c *gin.Context) {
		session := c.Param("session")
		challenge, _ := pool.ApplyChallenge(session)

		resp := Response{code: 0, data: challenge}

		c.IndentedJSON(http.StatusOK, resp)
	})

	router.POST("/verifyVp", func(c *gin.Context) {
		var body VerifyReqBody
		if err := c.BindJSON(&body); err != nil {
			return
		}
		//TODO 1. Verify VP Signature

		//TODO 2. Create response vp
		respVp := models.VerifiablePresentation{}

		resp := Response{code: 0, data: respVp}
		c.IndentedJSON(http.StatusOK, resp)
	})

	return router
}
