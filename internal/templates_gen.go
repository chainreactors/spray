//go:build ignore
// +build ignore

package main

import (
	"encoding/json"
	"fmt"
	"github.com/chainreactors/files"
	"github.com/chainreactors/parsers"
	"io"
	"os"
	"path/filepath"
	"sigs.k8s.io/yaml"
)

func Encode(input []byte) string {
	return parsers.Base64Encode(files.Flate(input))
}

func loadYamlFile2JsonString(filename string) string {
	var err error
	file, err := os.Open("templates/" + filename)
	if err != nil {
		panic(err.Error())
	}

	bs, _ := io.ReadAll(file)
	jsonstr, err := yaml.YAMLToJSON(bs)
	if err != nil {
		panic(filename + err.Error())
	}

	return Encode(jsonstr)
}

func visit(files *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			panic(err)
		}
		if !info.IsDir() {
			*files = append(*files, path)
		}
		return nil
	}
}

func recuLoadYamlFiles2JsonString(dir string, single bool) string {
	var files []string
	err := filepath.Walk("templates/"+dir, visit(&files))
	if err != nil {
		panic(err)
	}
	var pocs []interface{}
	for _, file := range files {
		var tmp interface{}
		bs, err := os.ReadFile(file)
		if err != nil {
			panic(err)
		}

		err = yaml.Unmarshal(bs, &tmp)
		if err != nil {
			print(file)
			panic(err)
		}

		if tmp == nil {
			continue
		}

		if single {
			pocs = append(pocs, tmp)
		} else {
			pocs = append(pocs, tmp.([]interface{})...)
		}

	}

	jsonstr, err := json.Marshal(pocs)
	if err != nil {
		panic(err)
	}

	return Encode(jsonstr)
}

func main() {
	template := `package internal

import (
	"github.com/chainreactors/files"
	"github.com/chainreactors/parsers"
)

func LoadConfig(typ string) []byte {
	if typ == "http" {
		return files.UnFlate(parsers.Base64Decode("%s"))
	}
	return []byte{}
}

`
	template = fmt.Sprintf(template,
		recuLoadYamlFiles2JsonString("fingers/http", false),
	)
	f, err := os.OpenFile("internal/templates.go", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	f.WriteString(template)
	f.Sync()
	f.Close()
	println("generate templates.go successfully")
}
