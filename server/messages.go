package server

type Response struct {
	Code int         `json:"code"`
	Data interface{} `json:"data"`
}

type ChallengeRequest struct {
	Challenge string `json:"challenge"`
}

type NetworkConfirmRequest struct {
	Did           string `json:"did"`
	Target        string `json:"target"`
	LastBlockHash string `json:"lastBlockHash"`
	Quality       string `json:"Quality"`
	Signature     string `json:"Signature"`
}

type NetworkConfirmResult struct {
	Did           string `json:"did"`
	Target        string `json:"target"`
	LastBlockHash string `json:"lastBlockHash"`
	Signature     string `json:"Signature"`
}
