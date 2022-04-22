package client

import (
	"github.com/MetaBloxIO/miner_wallet/conf"
	"github.com/MetaBloxIO/miner_wallet/did/resolver/registry"
	"github.com/MetaBloxIO/miner_wallet/models"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	log "github.com/sirupsen/logrus"
)

type Resolver struct {
	conn     *ethclient.Client
	instance *registry.Registry
}

func NewResolver(conf *conf.Conf) (*Resolver, error) {
	resolver := &Resolver{}

	conn, err := ethclient.Dial(conf.Node)
	if err != nil {
		log.WithFields(log.Fields{
			"node":  conf.Node,
			"error": err,
		}).Error("Connect to harmony node failed")

		return nil, err
	}

	resolver.conn = conn

	address := common.HexToAddress(conf.ContractAddress)
	instance, err := registry.NewRegistry(address, conn)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Create smart contract instance failed")
		return nil, err
	}
	resolver.instance = instance

	return resolver, nil
}

func (r *Resolver) DestroyResolver() {
	if r.conn != nil {
		r.conn.Close()
	}
}

func (r *Resolver) ResolveDID(did string) (*models.DIDDocument, error) {
	return nil, nil
}
