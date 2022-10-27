package pkg

import (
	"github.com/chainreactors/files"
	"github.com/chainreactors/parsers"
)

func LoadConfig(typ string) []byte {
	if typ == "http" {
		return files.UnFlate(parsers.Base64Decode(""))
	}
	return []byte{}
}
