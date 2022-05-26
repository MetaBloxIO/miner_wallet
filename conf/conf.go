package conf

import (
	"encoding/json"
	"github.com/MetaBloxIO/metablox-foundation-services/models"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
)

type Conf struct {
	Did             string
	PrivateKey      string
	Node            string
	ContractAddress string
	MinerVC         models.VerifiableCredential
}

type ConfFile struct {
	Did             string `json:"did"`
	PrivateKey      string `json:"privateKey"`
	Node            string `json:"node"`
	ContractAddress string `json:"contractAddress"`
}

func LoadConf(confFile string, vcFile string) (*Conf, error) {
	confParam, err := loadConfFile(confFile)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"file":  confFile,
		}).Error("Load conf error")
		return nil, err
	}

	vc, err := loadVcFile(vcFile)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"file":  vcFile,
		}).Error("Load conf error")
		return nil, err
	}

	return &Conf{Did: confParam.Did, PrivateKey: confParam.PrivateKey,
		Node: confParam.Node, ContractAddress: confParam.ContractAddress, MinerVC: *vc}, nil
}

func loadVcFile(file string) (*models.VerifiableCredential, error) {
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

	var vc models.VerifiableCredential
	err = json.Unmarshal(fileContents, &vc)
	if err != nil {
		log.WithFields(log.Fields{
			"path":  file,
			"error": err,
		}).Error("parser config file failed")
		return nil, err
	}

	return &vc, nil
}

func loadConfFile(file string) (*ConfFile, error) {
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

	var confFile ConfFile
	err = json.Unmarshal(fileContents, &confFile)
	if err != nil {
		log.WithFields(log.Fields{
			"path":  file,
			"error": err,
		}).Error("parser config file failed")
		return nil, err
	}

	return &confFile, nil
}
