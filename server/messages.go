package server

type Request struct {
}

type Response struct {
	code int         `json:"code"`
	data interface{} `json:"data"`
}
