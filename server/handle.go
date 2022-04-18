package server

import (
	"github.com/MetaBloxIO/miner_wallet/models"
	"github.com/gin-gonic/gin"
	"net/http"
)

func InitRouter() {
	pool := NewChallengePool()
	router := gin.New()

	router.GET("/challenge/:session", func(c *gin.Context) {
		session := c.Param("session")
		challenge, _ := pool.ApplyChallenge(session)
		c.IndentedJSON(http.StatusOK, challenge)
	})

	router.POST("/verifyVp", func(c *gin.Context) {
		var vp models.VerifiablePresentation
		if err := c.BindJSON(&vp); err != nil {
			return
		}

	})
}
