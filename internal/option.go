package internal

import (
	"fmt"
	"github.com/antonmedv/expr"
	"github.com/chainreactors/files"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/words/mask"
	"github.com/gosuri/uiprogress"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Option struct {
	InputOptions
	OutputOptions
	RequestOptions
	ModeOptions
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
	Match       string   `long:"match" description:"String, "`
	Filter      string   `long:"filter" description:"String, "`
	Extracts    []string `long:"extract" description:"String, "`
	OutputFile  string   `short:"f" description:"String, output filename"`
	FuzzyFile   string   `long:"fuzzy-file" description:"String, fuzzy output filename"`
	Fuzzy       bool     `long:"fuzzy" description:"String, open fuzzy output"`
	OutputProbe string   `long:"probe" description:"String, output format"`
}

type RequestOptions struct {
	Headers         []string `long:"header"`
	Method          string   `long:"method"`
	Cookie          string   `long:"cookie"`
	SimhashDistance int      `long:"distance" default:"5"`
}

type ModeOptions struct {
	Force          bool   `long:"force"`
	CheckOnly      bool   `long:"check-only"`
	CheckPeriod    int    `long:"check-period" default:"100"`
	ErrPeriod      int    `long:"error-period" default:"10"`
	BreakThreshold int    `long:"error-threshold" default:"20"`
	BlackStatus    string `long:"black-status" default:"404,400,410"`
	WhiteStatus    string `long:"white-status" default:"200"`
	FuzzyStatus    string `long:"fuzzy-status" default:"403,500,501,502,503"`
}

type MiscOptions struct {
	Deadline int    `long:"deadline" default:"999999" description:"Int, deadline (seconds)"` // todo 总的超时时间,适配云函数的deadline
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
		Progress:       uiprogress.New(),
		Threads:        opt.Threads,
		PoolSize:       opt.PoolSize,
		Mod:            opt.Mod,
		Timeout:        opt.Timeout,
		Deadline:       opt.Deadline,
		Offset:         opt.Offset,
		Limit:          opt.Limit,
		urlCh:          make(chan string),
		OutputCh:       make(chan *pkg.Baseline, 100),
		FuzzyCh:        make(chan *pkg.Baseline, 100),
		Fuzzy:          opt.Fuzzy,
		Force:          opt.Force,
		CheckOnly:      opt.CheckOnly,
		CheckPeriod:    opt.CheckPeriod,
		ErrPeriod:      opt.ErrPeriod,
		BreakThreshold: opt.BreakThreshold,
	}

	err = pkg.LoadTemplates()
	if err != nil {
		return nil, err
	}

	if opt.Extracts != nil {
		for _, e := range opt.Extracts {
			if reg, ok := fingers.PresetExtracts[e]; ok {
				pkg.Extractors[e] = reg
			} else {
				pkg.Extractors[e] = regexp.MustCompile(e)
			}
		}
	}
	// 一些全局变量初始化
	if opt.Debug {
		logs.Log.Level = logs.Debug
	}
	if !opt.Quiet {
		r.Progress.Start()
		logs.Log.Writer = r.Progress.Bypass()
	} else {
		logs.Log.Quiet = true
	}

	if opt.SimhashDistance != 0 {
		pkg.Distance = uint8(opt.SimhashDistance)
	}

	if opt.Force {
		// 如果开启了force模式, 将关闭check机制, err积累到一定数量自动退出机制
		r.BreakThreshold = max
		r.CheckPeriod = max
		r.ErrPeriod = max
	}

	if opt.BlackStatus != "" {
		for _, s := range strings.Split(opt.BlackStatus, ",") {
			si, err := strconv.Atoi(s)
			if err != nil {
				return nil, err
			}
			BlackStatus = append(BlackStatus, si)
		}
	}

	if opt.WhiteStatus != "" {
		for _, s := range strings.Split(opt.WhiteStatus, ",") {
			si, err := strconv.Atoi(s)
			if err != nil {
				return nil, err
			}
			WhiteStatus = append(WhiteStatus, si)
		}
	}

	if opt.FuzzyStatus != "" {
		for _, s := range strings.Split(opt.FuzzyStatus, ",") {
			si, err := strconv.Atoi(s)
			if err != nil {
				return nil, err
			}
			FuzzyStatus = append(FuzzyStatus, si)
		}
	}

	// prepare url
	var urls []string
	var file *os.File
	urlfrom := opt.URLFile
	if opt.URL != "" {
		urls = append(urls, opt.URL)
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
		urls = strings.Split(strings.TrimSpace(string(content)), "\n")
	}

	r.URLList = urls
	logs.Log.Importantf("Loaded %d urls from %s", len(urls), urlfrom)

	// prepare word
	dicts := make([][]string, len(opt.Dictionaries))
	for i, f := range opt.Dictionaries {
		dicts[i], err = loadFileToSlice(f)
		if err != nil {
			return nil, err
		}
		logs.Log.Importantf("Loaded %d word from %s", len(dicts[i]), f)
	}

	if opt.Word == "" {
		opt.Word = "{?"
		for i, _ := range dicts {
			opt.Word += strconv.Itoa(i)
		}
		opt.Word += "}"
	}

	if opt.Suffixes != nil {
		mask.SpecialWords["suffix"] = opt.Suffixes
		opt.Word += "{@suffix}"
	}
	if opt.Prefixes != nil {
		mask.SpecialWords["prefix"] = opt.Prefixes
		opt.Word = "{@prefix}" + opt.Word
	}

	if opt.Extensions != "" {
		exts := strings.Split(opt.Extensions, ",")
		for i, e := range exts {
			if !strings.HasPrefix(e, ".") {
				exts[i] = "." + e
			}
		}
		mask.SpecialWords["ext"] = exts
		opt.Word += "{@ext}"
	}

	mask.CustomWords = dicts
	r.Wordlist, err = mask.Run(opt.Word)
	if err != nil {
		return nil, err
	}
	logs.Log.Importantf("Parsed %d words by %s", len(r.Wordlist), opt.Word)
	pkg.DefaultStatistor.Total = len(r.Wordlist)
	pkg.DefaultStatistor.Word = opt.Word
	pkg.DefaultStatistor.Dictionaries = opt.Dictionaries

	if r.Limit == 0 {
		if r.CheckOnly {
			r.Limit = len(r.URLList)
		} else {
			r.Limit = len(r.Wordlist)
		}
	} else {
		r.Limit = r.Offset + opt.Limit
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
			if ext := parseExtension(s); StringsContains(rexts, ext) {
				return strings.TrimSuffix(s, "."+ext)
			}
			return s
		})
	}

	if opt.ExcludeExtensions != "" {
		exexts := strings.Split(opt.ExcludeExtensions, ",")
		r.Fns = append(r.Fns, func(s string) string {
			if ext := parseExtension(s); StringsContains(exexts, ext) {
				return ""
			}
			return s
		})
	}

	if len(opt.Replaces) > 0 {
		r.Fns = append(r.Fns, func(s string) string {
			for k, v := range opt.Replaces {
				s = strings.Replace(s, k, v, -1)
			}
			return s
		})
	}
	logs.Log.Importantf("Loaded %d dictionaries and %d decorators", len(opt.Dictionaries), len(r.Fns))

	if opt.Match != "" {
		exp, err := expr.Compile(opt.Match)
		if err != nil {
			return nil, err
		}
		r.MatchExpr = exp
	}

	if opt.Filter != "" {
		exp, err := expr.Compile(opt.Filter)
		if err != nil {
			return nil, err
		}
		r.FilterExpr = exp
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

	if opt.OutputProbe != "" {
		r.Probes = strings.Split(opt.OutputProbe, ",")
	}

	if opt.OutputFile != "" {
		r.OutputFile, err = files.NewFile(opt.OutputFile, false, false, true)
		if err != nil {
			return nil, err
		}
	}

	if opt.FuzzyFile != "" {
		r.FuzzyFile, err = files.NewFile(opt.FuzzyFile, false, false, true)
		if err != nil {
			return nil, err
		}
	}

	r.StatFile, err = files.NewFile("stat.json", false, false, true)
	if err != nil {
		return nil, err
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

func StringsContains(s []string, e string) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func IntsContains(s []int, e int) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}
