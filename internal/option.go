package internal

import (
	"fmt"
	"github.com/antonmedv/expr"
	"github.com/chainreactors/files"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers/iutils"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/spray/pkg/ihttp"
	"github.com/chainreactors/utils"
	"github.com/chainreactors/words/mask"
	"github.com/chainreactors/words/rule"
	"github.com/gosuri/uiprogress"
	"io/ioutil"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var (
	DefaultThreads = 20
	//DefaultTimeout = 5
	//DefaultPoolSize = 5
	//DefaultRateLimit = 0
)

type Option struct {
	InputOptions    `group:"Input Options"`
	FunctionOptions `group:"Function Options"`
	OutputOptions   `group:"Output Options"`
	PluginOptions   `group:"Plugin Options"`
	RequestOptions  `group:"Request Options"`
	ModeOptions     `group:"Modify Options"`
	MiscOptions     `group:"Miscellaneous Options"`
}

type InputOptions struct {
	ResumeFrom   string   `long:"resume"`
	URL          []string `short:"u" long:"url" description:"Strings, input baseurl, e.g.: http://google.com"`
	URLFile      string   `short:"l" long:"list" description:"File, input filename"`
	PortRange    string   `short:"p" long:"port" description:"String, input port range, e.g.: 80,8080-8090,db"`
	CIDRs        string   `short:"c" long:"cidr" description:"String, input cidr, e.g.: 1.1.1.1/24 "`
	Raw          string   `long:"raw" description:"File, input raw request filename"`
	Dictionaries []string `short:"d" long:"dict" description:"Files, Multi,dict files, e.g.: -d 1.txt -d 2.txt"`
	Offset       int      `long:"offset" description:"Int, wordlist offset"`
	Limit        int      `long:"limit" description:"Int, wordlist limit, start with offset. e.g.: --offset 1000 --limit 100"`
	Word         string   `short:"w" long:"word" description:"String, word generate dsl, e.g.: -w test{?ld#4}"`
	Rules        []string `short:"r" long:"rules" description:"Files, rule files, e.g.: -r rule1.txt -r rule2.txt"`
	AppendRule   []string `long:"append-rule" description:"Files, when found valid path , use append rule generator new word with current path"`
	FilterRule   string   `long:"filter-rule" description:"String, filter rule, e.g.: --rule-filter '>8 <4'"`
}

type FunctionOptions struct {
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
	Match       string `long:"match" description:"String, custom match function, e.g.: --match current.Status != 200" json:"match,omitempty"`
	Filter      string `long:"filter" description:"String, custom filter function, e.g.: --filter current.Body contains 'hello'" json:"filter,omitempty"`
	OutputFile  string `short:"f" long:"file" description:"String, output filename" json:"output_file,omitempty"`
	Format      string `short:"F" long:"format" description:"String, output format, e.g.: --format 1.json"`
	FuzzyFile   string `long:"fuzzy-file" description:"String, fuzzy output filename" json:"fuzzy_file,omitempty"`
	DumpFile    string `long:"dump-file" description:"String, dump all request, and write to filename"`
	Dump        bool   `long:"dump" description:"Bool, dump all request"`
	AutoFile    bool   `long:"auto-file" description:"Bool, auto generator output and fuzzy filename" `
	Fuzzy       bool   `long:"fuzzy" description:"String, open fuzzy output" json:"fuzzy,omitempty"`
	OutputProbe string `short:"o" long:"probe" description:"String, output format" json:"output_probe,omitempty"`
}

type RequestOptions struct {
	Headers         []string `long:"header" description:"Strings, custom headers, e.g.: --headers 'Auth: example_auth'"`
	UserAgent       string   `long:"user-agent" description:"String, custom user-agent, e.g.: --user-agent Custom"`
	RandomUserAgent bool     `long:"random-agent" description:"Bool, use random with default user-agent"`
	Cookie          []string `long:"cookie" description:"Strings, custom cookie"`
	ReadAll         bool     `long:"read-all" description:"Bool, read all response body"`
	MaxBodyLength   int      `long:"max-length" default:"100" description:"Int, max response body length (kb), default 100k, e.g. -max-length 1000"`
}

type PluginOptions struct {
	Advance    bool     `short:"a" long:"advance" description:"Bool, enable crawl and active"`
	Extracts   []string `long:"extract" description:"Strings, extract response, e.g.: --extract js --extract ip --extract version:(.*?)"`
	Recon      bool     `long:"recon" description:"Bool, enable recon"`
	Active     bool     `long:"active" description:"Bool, enable active finger detect"`
	Bak        bool     `long:"bak" description:"Bool, enable bak found"`
	FileBak    bool     `long:"file-bak" description:"Bool, enable valid result bak found, equal --append-rule rule/filebak.txt"`
	Common     bool     `long:"common" description:"Bool, enable common file found"`
	Crawl      bool     `long:"crawl" description:"Bool, enable crawl"`
	CrawlDepth int      `long:"crawl-depth" default:"3" description:"Int, crawl depth"`
	CrawlScope string   `long:"crawl-scope" description:"Int, crawl scope (todo)"`
}

type ModeOptions struct {
	RateLimit      int    `long:"rate-limit" default:"0" description:"Int, request rate limit (rate/s), e.g.: --rate-limit 100"`
	Force          bool   `long:"force" description:"Bool, skip error break"`
	CheckOnly      bool   `long:"check-only" description:"Bool, check only"`
	Recursive      string `long:"recursive" default:"current.IsDir()" description:"String,custom recursive rule, e.g.: --recursive current.IsDir()"`
	Depth          int    `long:"depth" default:"0" description:"Int, recursive depth"`
	CheckPeriod    int    `long:"check-period" default:"200" description:"Int, check period when request"`
	ErrPeriod      int    `long:"error-period" default:"10" description:"Int, check period when error"`
	BreakThreshold int    `long:"error-threshold" default:"20" description:"Int, break when the error exceeds the threshold "`
	BlackStatus    string `long:"black-status" default:"400,410" description:"Strings (comma split),custom black status, "`
	WhiteStatus    string `long:"white-status" default:"200" description:"Strings (comma split), custom white status"`
	FuzzyStatus    string `long:"fuzzy-status" default:"404,403,500,501,502,503" description:"Strings (comma split), custom fuzzy status"`
	UniqueStatus   string `long:"unique-status" default:"403" description:"Strings (comma split), custom unique status"`
	Unique         bool   `long:"unique" description:"Bool, unique response"`

	SimhashDistance int `long:"distance" default:"5"`
}

type MiscOptions struct {
	Deadline int    `long:"deadline" default:"999999" description:"Int, deadline (seconds)"` // todo 总的超时时间,适配云函数的deadline
	Timeout  int    `long:"timeout" default:"5" description:"Int, timeout with request (seconds)"`
	PoolSize int    `short:"P" long:"pool" default:"5" description:"Int, Pool size"`
	Threads  int    `short:"t" long:"thread" default:"20" description:"Int, number of threads per pool"`
	Debug    bool   `long:"debug" description:"Bool, output debug info"`
	Quiet    bool   `short:"q" long:"quiet" description:"Bool, Quiet"`
	NoColor  bool   `long:"no-color" description:"Bool, no color"`
	NoBar    bool   `long:"no-bar" description:"Bool, No progress bar"`
	Mod      string `short:"m" long:"mod" default:"path" choice:"path" choice:"host" description:"String, path/host spray"`
	Client   string `short:"C" long:"client" default:"auto" choice:"fast" choice:"standard" choice:"auto" description:"String, Client type"`
}

func (opt *Option) PrepareRunner() (*Runner, error) {
	ok := opt.Validate()
	if !ok {
		return nil, fmt.Errorf("validate failed")
	}
	var err error
	r := &Runner{
		Progress:        uiprogress.New(),
		Threads:         opt.Threads,
		PoolSize:        opt.PoolSize,
		Mod:             opt.Mod,
		Timeout:         opt.Timeout,
		RateLimit:       opt.RateLimit,
		Deadline:        opt.Deadline,
		Headers:         make(map[string]string),
		Offset:          opt.Offset,
		Total:           opt.Limit,
		taskCh:          make(chan *Task),
		OutputCh:        make(chan *pkg.Baseline, 100),
		FuzzyCh:         make(chan *pkg.Baseline, 100),
		Fuzzy:           opt.Fuzzy,
		Force:           opt.Force,
		CheckOnly:       opt.CheckOnly,
		CheckPeriod:     opt.CheckPeriod,
		ErrPeriod:       opt.ErrPeriod,
		BreakThreshold:  opt.BreakThreshold,
		Crawl:           opt.Crawl,
		Active:          opt.Active,
		Bak:             opt.Bak,
		Common:          opt.Common,
		RandomUserAgent: opt.RandomUserAgent,
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

	if opt.Threads == DefaultThreads && opt.CheckOnly {
		r.Threads = 1000
	}
	if opt.Recon {
		pkg.Extractors["recon"] = pkg.ExtractRegexps["pentest"]
	}

	if opt.Advance {
		r.Crawl = true
		r.Active = true
		r.Bak = true
		r.Common = true
		pkg.Extractors["recon"] = pkg.ExtractRegexps["pentest"]
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
	if opt.Recon {
		s.WriteString("recon enable; ")
	}
	if len(opt.AppendRule) > 0 {
		s.WriteString("file bak enable; ")
	}
	if s.Len() > 0 {
		logs.Log.Important("Advance Mod: " + s.String())
	}

	BlackStatus = parseStatus(BlackStatus, opt.BlackStatus)
	WhiteStatus = parseStatus(WhiteStatus, opt.WhiteStatus)
	if opt.FuzzyStatus == "all" {
		enableAllFuzzy = true
	} else {
		FuzzyStatus = parseStatus(FuzzyStatus, opt.FuzzyStatus)
	}

	if opt.Unique {
		enableAllUnique = true
	} else {
		UniqueStatus = parseStatus(UniqueStatus, opt.UniqueStatus)
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
		return nil, fmt.Errorf("%s %w", opt.Word, err)
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

	ports := utils.ParsePort(opt.PortRange)

	// prepare task
	tasks := make(chan *Task, opt.PoolSize)
	var taskfrom string
	if opt.ResumeFrom != "" {
		stats, err := pkg.ReadStatistors(opt.ResumeFrom)
		if err != nil {
			logs.Log.Error(err.Error())
		}
		r.Count = len(stats)
		taskfrom = "resume " + opt.ResumeFrom
		go func() {
			for _, stat := range stats {
				tasks <- &Task{baseUrl: stat.BaseUrl, origin: stat}
			}
			close(tasks)
		}()
	} else {
		var file *os.File

		// 根据不同的输入类型生成任务
		if len(opt.URL) == 1 {
			u, err := url.Parse(opt.URL[0])
			if err != nil {
				u, _ = url.Parse("http://" + opt.URL[0])
			}
			go opt.GenerateTasks(tasks, u.Hostname(), ports)
			taskfrom = u.Host
			r.Count = 1
		} else if len(opt.URL) > 1 {
			go func() {
				for _, u := range opt.URL {
					opt.GenerateTasks(tasks, u, ports)
				}
				close(tasks)
			}()

			taskfrom = "cmd"
			r.Count = len(opt.URL)
		} else if opt.CIDRs != "" {
			if len(ports) == 0 {
				ports = []string{"80", "443"}
			}

			for _, cidr := range strings.Split(opt.CIDRs, ",") {
				ips := utils.ParseCIDR(cidr)
				if ips != nil {
					r.Count += ips.Count()
				}
			}
			go func() {
				for _, cidr := range strings.Split(opt.CIDRs, ",") {
					ips := utils.ParseCIDR(cidr)
					if ips == nil {
						logs.Log.Error("cidr format error: " + cidr)
					}
					for ip := range ips.Range() {
						opt.GenerateTasks(tasks, ip.String(), ports)
					}
				}
				close(tasks)
			}()
			taskfrom = "cidr"
		} else if opt.URLFile != "" {
			file, err = os.Open(opt.URLFile)
			if err != nil {
				logs.Log.Error(err.Error())
			}
			taskfrom = opt.URLFile
		} else if pkg.HasStdin() {
			file = os.Stdin
			taskfrom = "stdin"
		}

		if file != nil {
			content, err := ioutil.ReadAll(file)
			if err != nil {
				logs.Log.Error(err.Error())
			}
			urls := strings.Split(strings.TrimSpace(string(content)), "\n")
			for _, u := range urls {
				if _, err := url.Parse(u); err != nil {
					r.Count++
				} else if ip := utils.ParseIP(u); ip != nil {
					r.Count++
				} else if cidr := utils.ParseCIDR(u); cidr != nil {
					r.Count += cidr.Count()
				}
			}

			go func() {
				for _, u := range urls {
					if _, err := url.Parse(u); err != nil {
						opt.GenerateTasks(tasks, u, ports)
					} else if ip := utils.ParseIP(u); ip != nil {
						opt.GenerateTasks(tasks, u, ports)
					} else if cidr := utils.ParseCIDR(u); cidr != nil {
						for ip := range cidr.Range() {
							opt.GenerateTasks(tasks, ip.String(), ports)
						}
					}
				}
				close(tasks)
			}()
		}
	}

	r.Count = r.Count * len(ports)
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
			if ext := parseExtension(s); iutils.StringsContains(rexts, ext) {
				return strings.TrimSuffix(s, "."+ext)
			}
			return s
		})
	}

	if opt.ExcludeExtensions != "" {
		exexts := strings.Split(opt.ExcludeExtensions, ",")
		r.Fns = append(r.Fns, func(s string) string {
			if ext := parseExtension(s); iutils.StringsContains(exexts, ext) {
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
		r.OutputFile, err = files.NewFile("result.json", false, false, true)
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
		r.FuzzyFile, err = files.NewFile("fuzzy.json", false, false, true)
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
		r.DumpFile, err = files.NewFile("dump.json", false, false, true)
		if err != nil {
			return nil, err
		}
	}
	if opt.ResumeFrom != "" {
		r.StatFile, err = files.NewFile(opt.ResumeFrom, false, true, true)
	} else {
		r.StatFile, err = files.NewFile(strings.ReplaceAll(taskfrom, ":", "_")+".stat", false, true, true)
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

// Generate Tasks
func (opt *Option) GenerateTasks(ch chan *Task, u string, ports []string) {
	parsed, err := url.Parse(u)
	if err != nil {
		logs.Log.Warn(err.Error())
		return
	}

	if parsed.Scheme == "" {
		if parsed.Port() == "443" {
			parsed.Scheme = "https"
		} else {
			parsed.Scheme = "http"
		}
	}

	if len(ports) == 0 {
		ch <- &Task{baseUrl: u}
		return
	}

	for _, p := range ports {
		if parsed.Host == "" {
			ch <- &Task{baseUrl: fmt.Sprintf("%s://%s:%s", parsed.Scheme, parsed.Path, p)}
		} else {
			ch <- &Task{baseUrl: fmt.Sprintf("%s://%s:%s/%s", parsed.Scheme, parsed.Host, p, parsed.Path)}
		}
	}
}
