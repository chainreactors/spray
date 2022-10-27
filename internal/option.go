package internal

import (
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/gosuri/uiprogress"
	"io/ioutil"
	"os"
	"strings"
)

type Option struct {
	URL               string   `short:"u" long:"url"`
	URLFile           string   `short:"l" long:"list"`
	WordLists         []string `short:"w" long:"word"`
	Extension         string   `short:"e" long:"extensions"`
	ExcludeExtensions bool     `long:"exclude-extensions"`
	RemoveExtensions  bool     `long:"remove-extensions"`
	Uppercase         bool     `short:"U" long:"uppercase"`
	Lowercase         bool     `short:"L" long:"lowercase"`

	Deadline    int      `long:"deadline" default:"600"` // todo 总的超时时间,适配云函数的deadline
	Timeout     int      `long:"timeout" default:"2"`
	Headers     []string `long:"header"`
	OutputFile  string   `short:"f"`
	OutputProbe string   `long:"probe"`
	Offset      int      `long:"offset"`
	Limit       int      `long:"limit"`
	Threads     int      `short:"t" long:"thread" default:"20"`
	PoolSize    int      `short:"p" long:"pool" default:"5"`
	Debug       bool     `long:"debug"`
	Quiet       bool     `short:"q" long:"quiet"`
	Mod         string   `short:"m" long:"mod" default:"path"`
	Client      string   `short:"c" long:"client" default:"auto"`
}

func (opt *Option) PrepareRunner() (*Runner, error) {
	r := &Runner{
		Progress: uiprogress.New(),
		Threads:  opt.Threads,
		PoolSize: opt.PoolSize,
		Mod:      opt.Mod,
		Timeout:  opt.Timeout,
	}

	if opt.Debug {
		logs.Log.Level = logs.Debug
	}
	if !opt.Quiet {
		r.Progress.Start()
		logs.Log.Writer = r.Progress.Bypass()
	}

	// prepare url
	var file *os.File
	var err error
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
	words := make([][]string, len(opt.WordLists))
	for i, f := range opt.WordLists {
		words[i], err = loadFileToSlice(f)
		if err != nil {
			return nil, err
		}
		logs.Log.Importantf("load %d word from %s", len(r.Wordlist), f)
	}

	for _, w := range words {
		r.Wordlist = append(r.Wordlist, w...)
	}
	// todo mask

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
