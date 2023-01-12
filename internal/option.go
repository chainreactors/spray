package internal

import (
	"fmt"
	"github.com/antonmedv/expr"
	"github.com/chainreactors/files"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"github.com/chainreactors/words/mask"
	"github.com/chainreactors/words/rule"
	"github.com/gosuri/uiprogress"
	"io/ioutil"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Option struct {
	InputOptions    `group:"Input Options"`
	FunctionOptions `group:"Function Options"`
	OutputOptions   `group:"Output Options"`
	RequestOptions  `group:"Request Options"`
	ModeOptions     `group:"Modify Options"`
	MiscOptions     `group:"Miscellaneous Options"`
}

type InputOptions struct {
	ResumeFrom   string   `long:"resume"`
	URL          []string `short:"u" long:"url" description:"String, Multi, input baseurl, e.g.: http://google.com"`
	URLFile      string   `short:"l" long:"list" description:"File, input filename"`
	Raw          string   `long:"raw" description:"File, input raw request filename"`
	Offset       int      `long:"offset" description:"Int, wordlist offset"`
	Limit        int      `long:"limit" description:"Int, wordlist limit, start with offset. e.g.: --offset 1000 --limit 100"`
	Dictionaries []string `short:"d" long:"dict" description:"Files, Multi,dict files, e.g.: -d 1.txt -d 2.txt"`
	Word         string   `short:"w" long:"word" description:"String, word generate dsl, e.g.: -w test{?ld#4}"`
	Rules        []string `short:"r" long:"rules" description:"Files, Multi, rule files, e.g.: -r rule1.txt -r rule2.txt"`
	AppendRule   []string `long:"append-rule" description:"File, when found valid path , use append rule generator new word with current path"`
	FilterRule   string   `long:"filter-rule" description:"String, filter rule, e.g.: --rule-filter '>8 <4'"`
}

type FunctionOptions struct {
	Extensions        string            `short:"e" long:"extension" description:"String, add extensions (separated by commas), e.g.: -e jsp,jspx"`
	ExcludeExtensions string            `long:"exclude-extension" description:"String, exclude extensions (separated by commas), e.g.: --exclude-extension jsp,jspx"`
	RemoveExtensions  string            `long:"remove-extension" description:"String, remove extensions (separated by commas), e.g.: --remove-extension jsp,jspx"`
	Uppercase         bool              `short:"U" long:"uppercase" desvcription:"Bool, upper wordlist, e.g.: --uppercase"`
	Lowercase         bool              `short:"L" long:"lowercase" description:"Bool, lower wordlist, e.g.: --lowercase"`
	Prefixes          []string          `long:"prefix" description:"Strings, Multi, add prefix, e.g.: --prefix aaa --prefix bbb"`
	Suffixes          []string          `long:"suffix" description:"Strings, Multi, add suffix, e.g.: --suffix aaa --suffix bbb"`
	Replaces          map[string]string `long:"replace" description:"Strings, Multi, replace string, e.g.: --replace aaa:bbb --replace ccc:ddd"`
}

type OutputOptions struct {
	Match       string   `long:"match" description:"String, custom match function, e.g.: --match current.Status != 200" json:"match,omitempty"`
	Filter      string   `long:"filter" description:"String, custom filter function, e.g.: --filter current.Body contains 'hello'" json:"filter,omitempty"`
	Extracts    []string `long:"extract" description:"String, Multi, extract response, e.g.: --extract js --extract ip --extract version:(.*?)" json:"extracts,omitempty"`
	OutputFile  string   `short:"f" long:"file" description:"String, output filename" json:"output_file,omitempty"`
	Format      string   `short:"F" long:"format" description:"String, output format, e.g.: --format 1.json"`
	FuzzyFile   string   `long:"fuzzy-file" description:"String, fuzzy output filename" json:"fuzzy_file,omitempty"`
	DumpFile    string   `long:"dump-file" description:"String, dump all request, and write to filename"`
	Dump        bool     `long:"dump" description:"Bool, dump all request"`
	AutoFile    bool     `long:"auto-file" description:"Bool, auto generator output and fuzzy filename" `
	Fuzzy       bool     `long:"fuzzy" description:"String, open fuzzy output" json:"fuzzy,omitempty"`
	OutputProbe string   `short:"o" long:"probe" description:"String, output format" json:"output_probe,omitempty"`
}

type RequestOptions struct {
	Headers         []string `long:"header" description:"String, Multi, custom headers, e.g.: --headers 'Auth: example_auth'"`
	UserAgent       string   `long:"user-agent" description:"String, custom user-agent, e.g.: --user-agent Custom"`
	RandomUserAgent bool     `long:"random-agent" description:"Bool, use random with default user-agent"`
	Cookie          []string `long:"cookie" description:"String, Multi, custom cookie"`
	ReadAll         bool     `long:"read-all" description:"Bool, read all response body"`
	MaxBodyLength   int      `long:"max-length" default:"100" description:"Int, max response body length (kb), default 100k, e.g. -max-length 1000"`
}

type ModeOptions struct {
	Advance         bool   `short:"a" long:"advance" description:"Bool, enable crawl and active"`
	Active          bool   `long:"active" description:"Bool, enable active finger detect"`
	Crawl           bool   `long:"crawl" description:"Bool, enable crawl"`
	Bak             bool   `long:"bak" description:"Bool, enable bak found"`
	FileBak         bool   `long:"file-bak" description:"Bool, enable valid result bak found, equal --append-rule rule/filebak.txt"`
	Common          bool   `long:"common" description:"Bool, enable common file found"`
	Force           bool   `long:"force" description:"Bool, skip error break"`
	CheckOnly       bool   `long:"check-only" description:"Bool, check only"`
	Recursive       string `long:"recursive" default:"current.IsDir()" description:"String,custom recursive rule, e.g.: --recursive current.IsDir()"`
	Depth           int    `long:"depth" default:"0" description:"Int, recursive depth"`
	CrawlDepth      int    `long:"crawl-depth" default:"3" description:"Int, crawl depth"`
	CrawlScope      string `long:"crawl-scope" description:"Int, crawl scope (todo)"`
	CheckPeriod     int    `long:"check-period" default:"200" description:"Int, check period when request"`
	ErrPeriod       int    `long:"error-period" default:"10" description:"Int, check period when error"`
	BreakThreshold  int    `long:"error-threshold" default:"20" description:"Int, break when the error exceeds the threshold "`
	BlackStatus     string `long:"black-status" default:"404,400,410" description:"Strings (comma split),custom black status, "`
	WhiteStatus     string `long:"white-status" default:"200" description:"Strings (comma split), custom white status"`
	FuzzyStatus     string `long:"fuzzy-status" default:"403,500,501,502,503" description:"Strings (comma split), custom fuzzy status"`
	SimhashDistance int    `long:"distance" default:"5"`
}

type MiscOptions struct {
	Deadline int    `long:"deadline" default:"999999" description:"Int, deadline (seconds)"` // todo 总的超时时间,适配云函数的deadline
	Timeout  int    `long:"timeout" default:"2" description:"Int, timeout with request (seconds)"`
	PoolSize int    `short:"p" long:"pool" default:"5" description:"Int, Pool size"`
	Threads  int    `short:"t" long:"thread" default:"20" description:"Int, number of threads per pool"`
	Debug    bool   `long:"debug" description:"Bool, output debug info"`
	Quiet    bool   `short:"q" long:"quiet" description:"Bool, Quiet"`
	NoColor  bool   `long:"no-color" description:"Bool, no color"`
	NoBar    bool   `long:"no-bar" description:"Bool, No progress bar"`
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
		Headers:        make(map[string]string),
		Offset:         opt.Offset,
		Total:          opt.Limit,
		taskCh:         make(chan *Task),
		OutputCh:       make(chan *pkg.Baseline, 100),
		FuzzyCh:        make(chan *pkg.Baseline, 100),
		Fuzzy:          opt.Fuzzy,
		Force:          opt.Force,
		CheckOnly:      opt.CheckOnly,
		CheckPeriod:    opt.CheckPeriod,
		ErrPeriod:      opt.ErrPeriod,
		BreakThreshold: opt.BreakThreshold,
		Crawl:          opt.Crawl,
		Active:         opt.Active,
		Bak:            opt.Bak,
		Common:         opt.Common,
	}

	// log and bar
	if !opt.NoColor {
		logs.Log.Color = true
		r.Color = true
	}
	if opt.Quiet {
		logs.Log.Quiet = true
		logs.Log.Color = false
		r.Color = false
	}
	if !(opt.Quiet || opt.NoBar) {
		r.Progress.Start()
		logs.Log.Writer = r.Progress.Bypass()
	}

	// configuration
	if opt.Force {
		// 如果开启了force模式, 将关闭check机制, err积累到一定数量自动退出机制
		r.BreakThreshold = max
		r.CheckPeriod = max
		r.ErrPeriod = max
	}

	if opt.Client == "auto" {
		r.ClientType = ihttp.Auto
	} else if opt.Client == "fast" {
		r.ClientType = ihttp.FAST
	} else if opt.Client == "standard" {
		r.ClientType = ihttp.STANDARD
	}

	if opt.Advance {
		r.Crawl = true
		r.Active = true
		r.Bak = true
		r.Common = true
		opt.AppendRule = append(opt.AppendRule, "filebak")
	} else if opt.FileBak {
		opt.AppendRule = append(opt.AppendRule, "filebak")
	}
	var s strings.Builder
	if r.Crawl {
		s.WriteString("crawl enable; ")
	}
	if r.Active {
		s.WriteString("active fingerprint enable; ")
	}
	if r.Bak {
		s.WriteString("bak file enable; ")
	}
	if r.Common {
		s.WriteString("common file enable; ")
	}
	if len(opt.AppendRule) > 0 {
		s.WriteString("file bak enable; ")
	}
	if s.Len() > 0 {
		logs.Log.Important("Advance Mod: " + s.String())
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

	// prepare word
	dicts := make([][]string, len(opt.Dictionaries))
	for i, f := range opt.Dictionaries {
		dicts[i], err = loadFileToSlice(f)
		if opt.ResumeFrom != "" {
			dictCache[f] = dicts[i]
		}
		if err != nil {
			return nil, err
		}
		logs.Log.Importantf("Loaded %d word from %s", len(dicts[i]), f)
	}

	if opt.Word == "" {
		if len(opt.Dictionaries) == 0 {
			opt.Word = "/"
		} else {
			opt.Word = "{?"
			for i, _ := range dicts {
				opt.Word += strconv.Itoa(i)
			}
			opt.Word += "}"
		}
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

	r.Wordlist, err = mask.Run(opt.Word, dicts, nil)
	if err != nil {
		return nil, err
	}
	if len(r.Wordlist) > 0 {
		logs.Log.Importantf("Parsed %d words by %s", len(r.Wordlist), opt.Word)
	}

	if opt.Rules != nil {
		rules, err := loadFileAndCombine(opt.Rules)
		if err != nil {
			return nil, err
		}
		r.Rules = rule.Compile(rules, opt.FilterRule)
	} else if opt.FilterRule != "" {
		// if filter rule is not empty, set rules to ":", force to open filter mode
		r.Rules = rule.Compile(":", opt.FilterRule)
	} else {
		r.Rules = new(rule.Program)
	}

	if len(r.Rules.Expressions) > 0 {
		r.Total = len(r.Wordlist) * len(r.Rules.Expressions)
	} else {
		r.Total = len(r.Wordlist)
	}

	pkg.DefaultStatistor = pkg.Statistor{
		Word:         opt.Word,
		WordCount:    len(r.Wordlist),
		Dictionaries: opt.Dictionaries,
		Offset:       opt.Offset,
		RuleFiles:    opt.Rules,
		RuleFilter:   opt.FilterRule,
		Total:        r.Total,
	}

	if opt.AppendRule != nil {
		content, err := loadFileAndCombine(opt.AppendRule)
		if err != nil {
			return nil, err
		}
		r.AppendRules = rule.Compile(string(content), "")
	}
	// prepare task
	var tasks []*Task
	var taskfrom string
	if opt.ResumeFrom != "" {
		stats, err := pkg.ReadStatistors(opt.ResumeFrom)
		if err != nil {
			return nil, err
		}
		taskfrom = "resume " + opt.ResumeFrom
		for _, stat := range stats {
			task := &Task{baseUrl: stat.BaseUrl, origin: stat}
			tasks = append(tasks, task)
		}
	} else {
		var file *os.File
		var urls []string
		if len(opt.URL) == 1 {
			u, err := url.Parse(opt.URL[0])
			if err != nil {
				u, _ = url.Parse("http://" + opt.URL[0])
			}
			urls = append(urls, u.String())
			tasks = append(tasks, &Task{baseUrl: opt.URL[0]})
			taskfrom = u.Host
		} else if len(opt.URL) > 1 {
			for _, u := range opt.URL {
				urls = append(urls, u)
				tasks = append(tasks, &Task{baseUrl: u})
			}
			taskfrom = "cmd"
		} else if opt.URLFile != "" {
			file, err = os.Open(opt.URLFile)
			if err != nil {
				return nil, err
			}
			taskfrom = opt.URLFile
		} else if pkg.HasStdin() {
			file = os.Stdin
			taskfrom = "stdin"
		}

		if file != nil {
			content, err := ioutil.ReadAll(file)
			if err != nil {
				return nil, err
			}
			urls := strings.Split(strings.TrimSpace(string(content)), "\n")
			for _, u := range urls {
				tasks = append(tasks, &Task{baseUrl: strings.TrimSpace(u)})
			}
		}
		if opt.CheckOnly {
			r.URLList = urls
			r.Total = len(r.URLList)
		}
	}

	r.Tasks = tasks
	logs.Log.Importantf("Loaded %d urls from %s", len(tasks), taskfrom)

	if opt.Uppercase {
		r.Fns = append(r.Fns, strings.ToUpper)
	}
	if opt.Lowercase {
		r.Fns = append(r.Fns, strings.ToLower)
	}

	if opt.RemoveExtensions != "" {
		rexts := strings.Split(opt.ExcludeExtensions, ",")
		r.Fns = append(r.Fns, func(s string) string {
			if ext := parseExtension(s); pkg.StringsContains(rexts, ext) {
				return strings.TrimSuffix(s, "."+ext)
			}
			return s
		})
	}

	if opt.ExcludeExtensions != "" {
		exexts := strings.Split(opt.ExcludeExtensions, ",")
		r.Fns = append(r.Fns, func(s string) string {
			if ext := parseExtension(s); pkg.StringsContains(exexts, ext) {
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

	if opt.Recursive != "current.IsDir()" {
		MaxRecursion = 1
		exp, err := expr.Compile(opt.Recursive)
		if err != nil {
			return nil, err
		}
		r.RecursiveExpr = exp
	}
	if opt.Depth != 0 {
		MaxRecursion = opt.Depth
	}

	// prepare header
	for _, h := range opt.Headers {
		i := strings.Index(h, ":")
		if i == -1 {
			logs.Log.Warn("invalid header")
		} else {
			r.Headers[h[:i]] = h[i+2:]
		}
	}

	if opt.UserAgent != "" {
		r.Headers["User-Agent"] = opt.UserAgent
	}
	if opt.Cookie != nil {
		r.Headers["Cookie"] = strings.Join(opt.Cookie, "; ")
	}

	if opt.OutputProbe != "" {
		r.Probes = strings.Split(opt.OutputProbe, ",")
	}

	if opt.OutputFile != "" {
		r.OutputFile, err = files.NewFile(opt.OutputFile, false, false, true)
		if err != nil {
			return nil, err
		}
	} else if opt.AutoFile {
		r.OutputFile, err = files.NewFile("result.json", true, false, true)
		if err != nil {
			return nil, err
		}
	}

	if opt.FuzzyFile != "" {
		r.FuzzyFile, err = files.NewFile(opt.FuzzyFile, false, false, true)
		if err != nil {
			return nil, err
		}
	} else if opt.AutoFile {
		r.FuzzyFile, err = files.NewFile("fuzzy.json", true, false, true)
		if err != nil {
			return nil, err
		}
	}

	if opt.DumpFile != "" {
		r.DumpFile, err = files.NewFile(opt.DumpFile, false, false, true)
		if err != nil {
			return nil, err
		}
	} else if opt.Dump {
		r.DumpFile, err = files.NewFile("dump.json", true, false, true)
		if err != nil {
			return nil, err
		}
	}
	if opt.ResumeFrom != "" {
		r.StatFile, err = files.NewFile(opt.ResumeFrom, false, true, true)
	} else {
		r.StatFile, err = files.NewFile(taskfrom+".stat", false, true, true)
	}
	if err != nil {
		return nil, err
	}
	r.StatFile.Mod = os.O_WRONLY | os.O_CREATE
	err = r.StatFile.Init()
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

	if (opt.Offset != 0 || opt.Limit != 0) && opt.Depth > 0 {
		// 偏移和上限与递归同时使用时也会造成混淆.
		logs.Log.Error("--offset and --limit cannot be used with --depth at the same time")
		return false
	}

	if opt.Depth > 0 && opt.ResumeFrom != "" {
		// 递归与断点续传会造成混淆, 断点续传的word与rule不是通过命令行获取的
		logs.Log.Error("--resume and --depth cannot be used at the same time")
		return false
	}
	return true
}
