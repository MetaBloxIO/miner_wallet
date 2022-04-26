package server

import "github.com/MetaBloxIO/miner_wallet/models"

type Request struct {
}

type Response struct {
	code int         `json:"code"`
	data interface{} `json:"data"`
}

type VerifyReqBody struct {
	nonce string                        `json:"nonce"`
	vp    models.VerifiablePresentation `json:"vp"`
}
