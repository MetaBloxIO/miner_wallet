package main

import (
	conf2 "github.com/MetaBloxIO/miner_wallet/conf"
	"github.com/MetaBloxIO/miner_wallet/server"
	log "github.com/sirupsen/logrus"
)

func main() {
	_, err := conf2.LoadConf("./conf/config.json")

	if err != nil {
		log.Errorf("Read config file failed")
		return
	}

	//TODO create eth client using conf

	router := server.InitRouter()

	router.Run()
}
