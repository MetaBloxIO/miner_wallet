package conf

import (
	"encoding/json"
	"github.com/MetaBloxIO/metablox-foundation-services/models"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
)

type Conf struct {
	Did             string                      `json:"did"`
	PrivateKey      string                      `json:"PrivateKey"`
	Node            string                      `json:"Node"`
	ContractAddress string                      `json:"ContractAddress"`
	MinerVC         models.VerifiableCredential `json:"MinerVC"`
}

func LoadConf(file string) (*Conf, error) {
	configFile, err := os.Open(file)
	if err != nil {
		log.WithFields(log.Fields{
			"path":  file,
			"error": err,
		}).Error("Open config file failed")
		return nil, err
	}
	defer configFile.Close()

	fileContents, err := ioutil.ReadAll(configFile)
	if err != nil {
		log.WithFields(log.Fields{
			"path":  file,
			"error": err,
		}).Error("read config file failed")
		return nil, err
	}

	var conf Conf
	err = json.Unmarshal(fileContents, &conf)
	if err != nil {
		log.WithFields(log.Fields{
			"path":  file,
			"error": err,
		}).Error("parser config file failed")
		return nil, err
	}

	return &conf, nil
}
