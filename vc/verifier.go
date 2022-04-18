package vc

import "github.com/MetaBloxIO/miner_wallet/models"

func VerifyVC(credential *models.VerifiableCredential) error {
	return nil
}

func VerifyVP(presentation *models.VerifiablePresentation) error {
	for _, vc := range presentation.Credentials {
		err := VerifyVC(&vc)
		if err != nil {
			return err
		}
	}

	return nil
}
