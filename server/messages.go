package server

type ChallengeRequest struct {
	challenge string `json:"challenge"`
}

type Response struct {
	code int         `json:"code"`
	data interface{} `json:"data"`
}
