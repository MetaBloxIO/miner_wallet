package main

import (
	"github.com/MetaBloxIO/miner_wallet/server"
)

func main() {
	//TODO create eth client using conf

	router := server.InitRouter()

	router.Run()
}
