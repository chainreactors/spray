package pkg

import (
	"github.com/chainreactors/utils/encode"
)

func LoadConfig(typ string) []byte {
	if typ == "http" {
		return encode.MustDeflateDeCompress(encode.Base64Decode(""))
	}
	return []byte{}
}
