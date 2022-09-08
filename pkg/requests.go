package pkg

import (
	"net/http"
)

func BuildPathRequest(path string, req http.Request) *http.Request {
	req.URL.Path = path
	return &req
}

func BuildHostRequest(u string, req http.Request) *http.Request {
	req.Host = u
	return &req
}
