package main

import (
	"github.com/MetaBloxIO/metablox-foundation-services/contract"
	"github.com/MetaBloxIO/miner_wallet/server"
)

func main() {
	//TODO create eth client using conf

	router := server.InitRouter()

	contract.Init()

	router.Run(":3000")
}
