//go:build !emptytemplates
// +build !emptytemplates

package pkg

import (
	_ "embed"

	"github.com/chainreactors/utils/encode"
)

//go:embed data/spray_rule.bin
var sprayRuleData []byte

//go:embed data/spray_common.bin
var sprayCommonData []byte

//go:embed data/spray_dict.bin
var sprayDictData []byte

//go:embed data/extract.bin
var extractData []byte

//go:embed data/port.bin
var portData []byte


func loadEmbeddedConfig(typ string) []byte {
	if typ == "spray_rule" {
		return encode.MustDeflateDeCompress(sprayRuleData)
	}else if typ == "spray_common" {
		return encode.MustDeflateDeCompress(sprayCommonData)
	}else if typ == "spray_dict" {
		return encode.MustDeflateDeCompress(sprayDictData)
	}else if typ == "extract" {
		return encode.MustDeflateDeCompress(extractData)
	}else if typ == "port" {
		return encode.MustDeflateDeCompress(portData)
	}
	return nil
}
