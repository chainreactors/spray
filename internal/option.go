package internal

import (
	"fmt"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words/mask"
	"github.com/gosuri/uiprogress"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

type Option struct {
	InputOptions
	OutputOptions
	RequestOptions
	MiscOptions
}

type InputOptions struct {
	URL               string            `short:"u" long:"url" description:"String, input baseurl (separated by commas), e.g.: http://google.com, http://baidu.com"`
	URLFile           string            `short:"l" long:"list" description:"File, input filename"`
	Offset            int               `long:"offset" description:"Int, wordlist offset"`
	Limit             int               `long:"limit" description:"Int, wordlist limit, start with offset. e.g.: --offset 1000 --limit 100"`
	Dictionaries      []string          `short:"d" long:"dict" description:"Files, dict files, e.g.: -d 1.txt -d 2.txt"`
	Word              string            `short:"w" long:"word" description:"String, word generate dsl, e.g.: -w test{?ld#4}"`
	Extensions        string            `short:"e" long:"extension" description:"String, add extensions (separated by commas), e.g.: -e jsp,jspx"`
	ExcludeExtensions string            `long:"exclude-extension" description:"String, exclude extensions (separated by commas), e.g.: --exclude-extension jsp,jspx"`
	RemoveExtensions  string            `long:"remove-extension" description:"String, remove extensions (separated by commas), e.g.: --remove-extension jsp,jspx"`
	Uppercase         bool              `short:"U" long:"uppercase" description:"Bool, upper wordlist, e.g.: --uppercase"`
	Lowercase         bool              `short:"L" long:"lowercase" description:"Bool, lower wordlist, e.g.: --lowercase"`
	Prefixes          []string          `long:"prefix" description:"Strings, add prefix, e.g.: --prefix aaa --prefix bbb"`
	Suffixes          []string          `long:"suffix" description:"Strings, add suffix, e.g.: --suffix aaa --suffix bbb"`
	Replaces          map[string]string `long:"replace" description:"Strings, replace string, e.g.: --replace aaa:bbb --replace ccc:ddd"`
}

type OutputOptions struct {
	Matches     map[string]string `short:"m" long:"match" description:"String, "`
	Filters     map[string]string `long:"filter" description:"String, "`
	Extracts    []string          `long:"extract" description:"String, "`
	OutputFile  string            `short:"f" description:"String, output filename"`
	OutputProbe string            `long:"probe" description:"String, output format"`
}

type RequestOptions struct {
	Headers []string `long:"header"`
	Method  string   `long:"method"`
	Cookie  string   `long:"cookie"`
}

type MiscOptions struct {
	Deadline int    `long:"deadline" default:"600" description:"Int, deadline (seconds)"` // todo 总的超时时间,适配云函数的deadline
	Timeout  int    `long:"timeout" default:"2" description:"Int, timeout with request (seconds)"`
	PoolSize int    `short:"p" long:"pool" default:"5" description:"Int, Pool size"`
	Threads  int    `short:"t" long:"thread" default:"20" description:"Int, number of threads per pool (seconds)"`
	Debug    bool   `long:"debug" description:"Bool, output debug info"`
	Quiet    bool   `short:"q" long:"quiet" description:"Bool, Quiet"`
	Mod      string `short:"m" long:"mod" default:"path" choice:"path" choice:"host" description:"String, path/host spray"`
	Client   string `short:"c" long:"client" default:"auto" choice:"fast" choice:"standard" choice:"auto" description:"String, Client type"`
}

func (opt *Option) PrepareRunner() (*Runner, error) {
	ok := opt.Validate()
	if !ok {
		return nil, fmt.Errorf("validate failed")
	}
	var err error
	r := &Runner{
		Progress: uiprogress.New(),
		Threads:  opt.Threads,
		PoolSize: opt.PoolSize,
		Mod:      opt.Mod,
		Timeout:  opt.Timeout,
		Probes:   strings.Split(opt.OutputProbe, ","),
	}

	err = pkg.LoadTemplates()
	if err != nil {
		return nil, err
	}

	// 一些全局变量初始化
	if opt.Debug {
		logs.Log.Level = logs.Debug
	}
	if !opt.Quiet {
		r.Progress.Start()
		logs.Log.Writer = r.Progress.Bypass()
	}

	// prepare url
	var file *os.File
	urlfrom := opt.URLFile
	if opt.URL != "" {
		r.URLList = append(r.URLList, opt.URL)
		urlfrom = "cmd"
	} else if opt.URLFile != "" {
		file, err = os.Open(opt.URLFile)
		if err != nil {
			return nil, err
		}
	} else if pkg.HasStdin() {
		file = os.Stdin
		urlfrom = "stdin"
	}

	if file != nil {
		content, err := ioutil.ReadAll(file)
		if err != nil {
			return nil, err
		}
		r.URLList = strings.Split(string(content), "\n")
	}

	for i, u := range r.URLList {
		r.URLList[i] = strings.TrimSpace(u)
	}
	logs.Log.Importantf("load %d urls from %s", len(r.URLList), urlfrom)

	// prepare word
	dicts := make([][]string, len(opt.Dictionaries))
	for i, f := range opt.Dictionaries {
		dicts[i], err = loadFileToSlice(f)
		if err != nil {
			return nil, err
		}
		logs.Log.Importantf("load %d word from %s", len(dicts[i]), f)
	}

	if opt.Word == "" {
		opt.Word = "{?"
		for i, _ := range dicts {
			opt.Word += strconv.Itoa(i)
		}
		opt.Word = "}"
	}

	if opt.Suffixes == nil {
		dicts = append(dicts, opt.Suffixes)
		opt.Word += fmt.Sprintf("{?%d}", len(dicts)-1)
	}
	if opt.Prefixes != nil {
		dicts = append(dicts, opt.Prefixes)
		opt.Word = fmt.Sprintf("{?%d}", len(dicts)-1) + opt.Word
	}

	if opt.Extensions != "" {
		dicts = append(dicts, strings.Split(opt.Extensions, ","))
		opt.Word += fmt.Sprintf("{?%d}", len(dicts)-1)
	}

	mask.CustomWords = dicts
	r.Wordlist, err = mask.Run(opt.Word)
	if err != nil {
		return nil, err
	}

	if opt.Uppercase {
		r.Fns = append(r.Fns, strings.ToUpper)
	}
	if opt.Lowercase {
		r.Fns = append(r.Fns, strings.ToLower)
	}

	if opt.RemoveExtensions != "" {
		rexts := strings.Split(opt.ExcludeExtensions, ",")
		r.Fns = append(r.Fns, func(s string) string {
			if ext := parseExtension(s); SliceContains(rexts, ext) {
				return strings.TrimSuffix(s, "."+ext)
			}
			return s
		})
	}

	if opt.ExcludeExtensions != "" {
		exexts := strings.Split(opt.ExcludeExtensions, ",")
		r.Fns = append(r.Fns, func(s string) string {
			if ext := parseExtension(s); SliceContains(exexts, ext) {
				return ""
			}
			return s
		})
	}

	if opt.Replaces != nil {
		r.Fns = append(r.Fns, func(s string) string {
			for k, v := range opt.Replaces {
				s = strings.Replace(s, k, v, -1)
			}
			return s
		})
	}

	// prepare header
	for _, h := range opt.Headers {
		i := strings.Index(h, ":")
		if i == -1 {
			logs.Log.Warn("invalid header")
		} else {
			r.Headers.Add(h[:i], h[i+2:])
		}
	}

	return r, nil
}

func (opt *Option) Validate() bool {
	if opt.Uppercase && opt.Lowercase {
		logs.Log.Error("Cannot set -U and -L at the same time")
		return false
	}
	return true
}

func loadFileToSlice(filename string) ([]string, error) {
	var ss []string
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ss = strings.Split(string(content), "\n")

	// 统一windows与linux的回车换行差异
	for i, word := range ss {
		ss[i] = strings.TrimSpace(word)
	}

	return ss, nil
}

func parseExtension(s string) string {
	if i := strings.Index(s, "."); i != -1 {
		return s[i+1:]
	}
	return ""
}

func SliceContains(s []string, e string) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}
