package main

import (
	"github.com/MetaBloxIO/metablox-foundation-services/contract"
	"github.com/MetaBloxIO/miner_wallet/server"
	"github.com/spf13/viper"
)

func main() {
	//TODO create eth client using conf

	router := server.InitRouter()

	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()
	contract.Init()

	router.Run(":3000")
}
