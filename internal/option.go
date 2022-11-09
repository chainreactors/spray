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
	URL               string            `short:"u" long:"url"`
	URLFile           string            `short:"l" long:"list"`
	Dictionaries      []string          `short:"d" long:"dict"`
	Word              string            `short:"w" long:"word"`
	Extensions        string            `short:"e" long:"extension"`
	ExcludeExtensions string            `long:"exclude-extension"`
	RemoveExtensions  string            `long:"remove-extension"`
	Uppercase         bool              `short:"U" long:"uppercase"`
	Lowercase         bool              `short:"L" long:"lowercase"`
	Prefixes          []string          `long:"prefix"`
	Suffixes          []string          `long:"suffix"`
	Replaces          map[string]string `long:"replace"`
	Deadline          int               `long:"deadline" default:"600"` // todo 总的超时时间,适配云函数的deadline
	Timeout           int               `long:"timeout" default:"2"`
	Headers           []string          `long:"header"`
	OutputFile        string            `short:"f"`
	OutputProbe       string            `long:"probe"`
	Offset            int               `long:"offset"`
	Limit             int               `long:"limit"`
	Threads           int               `short:"t" long:"thread" default:"20"`
	PoolSize          int               `short:"p" long:"pool" default:"5"`
	Debug             bool              `long:"debug"`
	Quiet             bool              `short:"q" long:"quiet"`
	Mod               string            `short:"m" long:"mod" default:"path"`
	Client            string            `short:"c" long:"client" default:"auto"`
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
