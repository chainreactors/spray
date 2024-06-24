package ihttp

import (
	"bytes"
	"github.com/chainreactors/logs"
	"github.com/valyala/fasthttp"
	"io"
	"net/http"
	"strings"
)

type Response struct {
	StandardResponse *http.Response
	FastResponse     *fasthttp.Response
	ClientType       int
}

func (r *Response) StatusCode() int {
	if r.FastResponse != nil {
		return r.FastResponse.StatusCode()
	} else if r.StandardResponse != nil {
		return r.StandardResponse.StatusCode
	} else {
		return 0
	}
}

func (r *Response) Body() []byte {
	if r.FastResponse != nil {
		return r.FastResponse.Body()
	} else if r.StandardResponse != nil {
		if DefaultMaxBodySize == -1 {
			body, err := io.ReadAll(r.StandardResponse.Body)
			if err != nil {
				return nil
			}
			return body
		} else {
			var body []byte
			if r.StandardResponse.ContentLength > 0 && CheckBodySize(r.StandardResponse.ContentLength) {
				body = make([]byte, r.StandardResponse.ContentLength)
			} else {
				return nil
			}

			n, err := io.ReadFull(r.StandardResponse.Body, body)
			_ = r.StandardResponse.Body.Close()
			if err == nil {
				return body
			} else if err == io.ErrUnexpectedEOF {
				return body[:n]
			} else if err == io.EOF {
				return nil
			} else {
				logs.Log.Error("readfull failed, " + err.Error())
				return nil
			}
		}
		return nil
	} else {
		return nil
	}
}

func (r *Response) ContentLength() int64 {
	if r.FastResponse != nil {
		return int64(r.FastResponse.Header.ContentLength())
	} else if r.StandardResponse != nil {
		return r.StandardResponse.ContentLength
	} else {
		return 0
	}
}

func (r *Response) ContentType() string {
	var t string
	if r.FastResponse != nil {
		t = string(r.FastResponse.Header.ContentType())
	} else if r.StandardResponse != nil {
		t = r.StandardResponse.Header.Get("Content-Type")
	} else {
		return ""
	}

	if i := strings.Index(t, ";"); i > 0 {
		return t[:i]
	} else {
		return t
	}
}

func (r *Response) Header() []byte {
	if r.FastResponse != nil {
		return r.FastResponse.Header.Header()
	} else if r.StandardResponse != nil {
		var header bytes.Buffer
		header.WriteString(r.StandardResponse.Proto + " " + r.StandardResponse.Status)
		for k, v := range r.StandardResponse.Header {
			for _, i := range v {
				header.WriteString(k + ": " + i + "\r\n")
			}
		}
		header.WriteString("\r\n")
		return header.Bytes()
	} else {
		return nil
	}
}

func (r *Response) GetHeader(key string) string {
	if r.FastResponse != nil {
		return string(r.FastResponse.Header.Peek(key))
	} else if r.StandardResponse != nil {
		return r.StandardResponse.Header.Get(key)
	} else {
		return ""
	}
}
