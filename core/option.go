package core

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/chainreactors/files"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/proxyclient"
	"github.com/chainreactors/spray/core/baseline"
	"github.com/chainreactors/spray/core/ihttp"
	"github.com/chainreactors/spray/core/pool"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/utils"
	"github.com/chainreactors/utils/iutils"
	"github.com/chainreactors/words/mask"
	"github.com/chainreactors/words/rule"
	"github.com/charmbracelet/lipgloss"
	"github.com/expr-lang/expr"
	"github.com/vbauerster/mpb/v8"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	DefaultThreads = 20
	defaultInited  = false
)

// NewDefaultRunnerConfig 创建并返回一个带有默认值且已初始化的 Runner 配置
// 这个函数统一处理所有的默认配置和基础初始化，对外部 SDK 隐藏内部细节
// 返回的 Option 已经完成了 pkg.Load() 等基础初始化
func NewDefaultRunnerConfig() (*Option, error) {
	opt := &Option{}

	// Request 配置
	opt.Method = "GET"
	opt.MaxBodyLength = 100
	opt.RandomUserAgent = false

	// Status 配置
	opt.BlackStatus = "400,410"
	opt.WhiteStatus = "200"
	opt.FuzzyStatus = "500,501,502,503,301,302,404"
	opt.UniqueStatus = "403,200,404"

	// 检查配置
	opt.CheckPeriod = 200
	opt.ErrPeriod = 10
	opt.BreakThreshold = 20

	// 递归配置
	opt.Recursive = "current.IsDir()"
	opt.Depth = 0
	opt.Index = "/"
	opt.Random = ""

	// 重试配置
	opt.RetryCount = 0
	opt.SimhashDistance = 8

	// 运行模式配置
	opt.Mod = "path"
	opt.Client = "auto"
	opt.Timeout = 5
	opt.Threads = 20
	opt.PoolSize = 1
	opt.Deadline = 999999

	// 输出配置 (SDK 模式下默认静默)
	opt.Quiet = true
	opt.NoBar = true
	opt.NoStat = true
	opt.NoColor = false
	opt.Json = false
	opt.FileOutput = "json"

	// 插件配置
	opt.Advance = false
	opt.Finger = false
	opt.CrawlPlugin = false
	opt.BakPlugin = false
	opt.FuzzuliPlugin = false
	opt.CommonPlugin = false
	opt.ActivePlugin = false
	opt.ReconPlugin = false
	opt.CrawlDepth = 3
	opt.AppendDepth = 2

	// 指纹引擎配置
	opt.FingerEngines = "all"

	// 执行基础初始化（只执行一次）
	if !defaultInited {
		if err := pkg.Load(); err != nil {
			return nil, fmt.Errorf("load config failed: %w", err)
		}
		if err := pkg.LoadFingers(); err != nil {
			return nil, fmt.Errorf("load fingers failed: %w", err)
		}
		defaultInited = true
	}

	// 初始化全局变量
	baseline.Distance = uint8(opt.SimhashDistance)
	if opt.MaxBodyLength == -1 {
		ihttp.DefaultMaxBodySize = -1
	} else {
		ihttp.DefaultMaxBodySize = opt.MaxBodyLength * 1024
	}

	pkg.BlackStatus = pkg.ParseStatus(pkg.DefaultBlackStatus, opt.BlackStatus)
	pkg.WhiteStatus = pkg.ParseStatus(pkg.DefaultWhiteStatus, opt.WhiteStatus)
	pkg.FuzzyStatus = pkg.ParseStatus(pkg.DefaultFuzzyStatus, opt.FuzzyStatus)
	pkg.UniqueStatus = pkg.ParseStatus(pkg.DefaultUniqueStatus, opt.UniqueStatus)

	return opt, nil
}

// ========================================
// 链式配置方法 (With***)
// ========================================

// WithThreads 设置并发线程数
func (opt *Option) WithThreads(n int) *Option {
	opt.Threads = n
	return opt
}

// WithTimeout 设置请求超时时间（秒）
func (opt *Option) WithTimeout(n int) *Option {
	opt.Timeout = n
	return opt
}

// WithMethod 设置 HTTP 请求方法
func (opt *Option) WithMethod(method string) *Option {
	opt.Method = method
	return opt
}

// WithHeaders 设置自定义请求头
func (opt *Option) WithHeaders(headers []string) *Option {
	opt.Headers = headers
	return opt
}

// WithProxy 设置代理
func (opt *Option) WithProxy(proxy string) *Option {
	opt.Proxies = []string{proxy}
	return opt
}

// WithFinger 启用/禁用指纹识别
func (opt *Option) WithFinger(enable bool) *Option {
	opt.Finger = enable
	return opt
}

// WithCrawl 启用/禁用爬虫
func (opt *Option) WithCrawl(enable bool) *Option {
	opt.CrawlPlugin = enable
	return opt
}

// WithDepth 设置递归深度
func (opt *Option) WithDepth(depth int) *Option {
	opt.Depth = depth
	return opt
}

type Option struct {
	InputOptions    `group:"Input Options" config:"input" `
	FunctionOptions `group:"Function Options" config:"functions" `
	OutputOptions   `group:"Output Options" config:"output"`
	PluginOptions   `group:"Plugin Options" config:"plugins"`
	FingerOptions   `group:"Finger Options" config:"finger"`
	RequestOptions  `group:"Request Options" config:"request"`
	ModeOptions     `group:"Modify Options" config:"mode"`
	MiscOptions     `group:"Miscellaneous Options" config:"misc"`
}

type InputOptions struct {
	ResumeFrom   string   `long:"resume" description:"File, resume filename" `
	Config       string   `short:"c" long:"config" description:"File, config filename"`
	URL          []string `short:"u" long:"url" description:"Strings, input baseurl, e.g.: http://google.com"`
	URLFile      string   `short:"l" long:"list" description:"File, input filename"`
	PortRange    string   `short:"p" long:"port" description:"String, input port range, e.g.: 80,8080-8090,db"`
	CIDRs        []string `short:"i" long:"cidr" description:"String, input cidr, e.g.: 1.1.1.1/24 "`
	RawFile      string   `long:"raw" description:"File, input raw request filename"`
	Dictionaries []string `short:"d" long:"dict" description:"Files, Multi,dict files, e.g.: -d 1.txt -d 2.txt" config:"dictionaries"`
	DefaultDict  bool     `short:"D" long:"default" description:"Bool, use default dictionary" config:"default"`
	Word         string   `short:"w" long:"word" description:"String, word generate dsl, e.g.: -w test{?ld#4}" config:"word"`
	Rules        []string `short:"r" long:"rules" description:"Files, rule files, e.g.: -r rule1.txt -r rule2.txt" config:"rules"`
	AppendRule   []string `short:"R" long:"append-rule" description:"Files, when found valid path , use append rule generator new word with current path" config:"append-rules"`
	FilterRule   string   `long:"filter-rule" description:"String, filter rule, e.g.: --rule-filter '>8 <4'" config:"filter-rule"`
	AppendFile   []string `long:"append" description:"Files, when found valid path , use append file new word with current path" config:"append-files"`
	Offset       int      `long:"offset" description:"Int, wordlist offset"`
	Limit        int      `long:"limit" description:"Int, wordlist limit, start with offset. e.g.: --offset 1000 --limit 100"`
}

type FunctionOptions struct {
	Extensions        string            `short:"e" long:"extension" description:"String, add extensions (separated by commas), e.g.: -e jsp,jspx" config:"extension"`
	ForceExtension    bool              `long:"force-extension" description:"Bool, force add extensions" config:"force-extension"`
	ExcludeExtensions string            `long:"exclude-extension" description:"String, exclude extensions (separated by commas), e.g.: --exclude-extension jsp,jspx" config:"exclude-extension"`
	RemoveExtensions  string            `long:"remove-extension" description:"String, remove extensions (separated by commas), e.g.: --remove-extension jsp,jspx" config:"remove-extension"`
	Uppercase         bool              `short:"U" long:"uppercase" description:"Bool, upper wordlist, e.g.: --uppercase" config:"upper"`
	Lowercase         bool              `short:"L" long:"lowercase" description:"Bool, lower wordlist, e.g.: --lowercase" config:"lower"`
	Prefixes          []string          `long:"prefix" description:"Strings, add prefix, e.g.: --prefix aaa --prefix bbb" config:"prefix"`
	Suffixes          []string          `long:"suffix" description:"Strings, add suffix, e.g.: --suffix aaa --suffix bbb" config:"suffix"`
	Replaces          map[string]string `long:"replace" description:"Strings, replace string, e.g.: --replace aaa:bbb --replace ccc:ddd" config:"replace"`
	Skips             []string          `long:"skip" description:"String, skip word when generate. rule, e.g.: --skip aaa" config:"skip"`
	//SkipEval          string            `long:"skip-eval" description:"String, skip word when generate. rule, e.g.: --skip-eval 'current.Length < 4'"`
}

type OutputOptions struct {
	Match       string `long:"match" description:"String, custom match function, e.g.: --match 'current.Status != 200''" config:"match" `
	Filter      string `long:"filter" description:"String, custom filter function, e.g.: --filter 'current.Body contains \"hello\"'" config:"filter"`
	Fuzzy       bool   `long:"fuzzy" description:"String, open fuzzy output" config:"fuzzy"`
	OutputFile  string `short:"f" long:"file" description:"String, output filename" json:"output_file,omitempty" config:"output-file"`
	DumpFile    string `long:"dump-file" description:"String, dump all request, and write to filename" config:"dump-file"`
	Dump        bool   `long:"dump" description:"Bool, dump all request" config:"dump"`
	AutoFile    bool   `long:"auto-file" description:"Bool, auto generator output and fuzzy filename" config:"auto-file"`
	Format      string `short:"F" long:"format" description:"String, output format, e.g.: --format 1.json" config:"format"`
	Json        bool   `short:"j" long:"json" description:"Bool, output json" config:"json"`
	FileOutput  string `short:"O" long:"file-output" default:"json" description:"Bool, file output format" config:"file_output"`
	OutputProbe string `short:"o" long:"probe" description:"String, output format" config:"output"`
	Quiet       bool   `short:"q" long:"quiet" description:"Bool, Quiet" config:"quiet"`
	NoColor     bool   `long:"no-color" description:"Bool, no color" config:"no-color"`
	NoBar       bool   `long:"no-bar" description:"Bool, No progress bar" config:"no-bar"`
	NoStat      bool   `long:"no-stat" description:"Bool, No stat file output" config:"no-stat"`
}

type RequestOptions struct {
	Method          string   `short:"X" long:"method" default:"GET" description:"String, request method, e.g.: --method POST" config:"method"`
	Headers         []string `short:"H" long:"header" description:"Strings, custom headers, e.g.: --header 'Auth: example_auth'" config:"headers"`
	UserAgent       string   `long:"user-agent" description:"String, custom user-agent, e.g.: --user-agent Custom" config:"useragent"`
	RandomUserAgent bool     `long:"random-agent" description:"Bool, use random with default user-agent" config:"random-useragent"`
	Cookie          []string `long:"cookie" description:"Strings, custom cookie" config:"cookies"`
	ReadAll         bool     `long:"read-all" description:"Bool, read all response body" config:"read-all"`
	MaxBodyLength   int64    `long:"max-length" default:"100" description:"Int, max response body length (kb), -1 read-all, 0 not read body, default 100k, e.g. --max-length 1000" config:"max-length"`
}

type PluginOptions struct {
	Advance       bool     `short:"a" long:"advance" description:"Bool, enable all plugin" config:"all" `
	Extracts      []string `long:"extract" description:"Strings, extract response, e.g.: --extract js --extract ip --extract version:(.*?)" config:"extract"`
	ExtractConfig string   `long:"extract-config" description:"String, extract config filename" config:"extract-config"`
	ActivePlugin  bool     `long:"active" description:"Bool, enable active finger path"`
	ReconPlugin   bool     `long:"recon" description:"Bool, enable recon" config:"recon"`
	BakPlugin     bool     `long:"bak" description:"Bool, enable bak found" config:"bak"`
	FuzzuliPlugin bool     `long:"fuzzuli" description:"Bool, enable fuzzuli plugin" config:"fuzzuli"`
	CommonPlugin  bool     `long:"common" description:"Bool, enable common file found" config:"common"`
	CrawlPlugin   bool     `long:"crawl" description:"Bool, enable crawl" config:"crawl"`
	CrawlDepth    int      `long:"crawl-depth" default:"3" description:"Int, crawl depth" config:"crawl-depth"`
	AppendDepth   int      `long:"append-depth" default:"2" description:"Int, append depth" config:"append-depth"`
}

type ModeOptions struct {
	RateLimit       int      `long:"rate-limit" default:"0" description:"Int, request rate limit (rate/s), e.g.: --rate-limit 100" config:"rate-limit"`
	Force           bool     `long:"force" description:"Bool, skip error break" config:"force"`
	NoScope         bool     `long:"no-scope" description:"Bool, no scope" config:"no-scope"`
	Scope           []string `long:"scope" description:"String, custom scope, e.g.: --scope *.example.com" config:"scope"`
	Recursive       string   `long:"recursive" default:"current.IsDir()" description:"String,custom recursive rule, e.g.: --recursive current.IsDir()" config:"recursive"`
	Depth           int      `long:"depth" default:"0" description:"Int, recursive depth" config:"depth"`
	Index           string   `long:"index" default:"/" description:"String, custom index path" config:"index"`
	Random          string   `long:"random" default:"" description:"String, custom random path" config:"random"`
	CheckPeriod     int      `long:"check-period" default:"200" description:"Int, check period when request" config:"check-period"`
	ErrPeriod       int      `long:"error-period" default:"10" description:"Int, check period when error" config:"error-period"`
	BreakThreshold  int      `long:"error-threshold" default:"20" description:"Int, break when the error exceeds the threshold" config:"error-threshold"`
	BlackStatus     string   `short:"B" long:"black-status" default:"400,410" description:"Strings (comma split),custom black status" config:"black-status"`
	WhiteStatus     string   `short:"W" long:"white-status" default:"200" description:"Strings (comma split), custom white status" config:"white-status"`
	FuzzyStatus     string   `long:"fuzzy-status" default:"500,501,502,503,301,302,404" description:"Strings (comma split), custom fuzzy status" config:"fuzzy-status"`
	UniqueStatus    string   `long:"unique-status" default:"403,200,404" description:"Strings (comma split), custom unique status" config:"unique-status"`
	Unique          bool     `long:"unique" description:"Bool, unique response" config:"unique"`
	RetryCount      int      `long:"retry" default:"0" description:"Int, retry count" config:"retry"`
	SimhashDistance int      `long:"sim-distance" default:"8" config:"sim-distance"`
}

type MiscOptions struct {
	Mod         string   `short:"m" long:"mod" default:"path" choice:"path" choice:"host" description:"String, path/host spray" config:"mod"`
	Client      string   `short:"C" long:"client" default:"auto" choice:"fast" choice:"standard" choice:"auto" description:"String, Client type" config:"client"`
	Deadline    int      `long:"deadline" default:"999999" description:"Int, deadline (seconds)" config:"deadline"` // todo 总的超时时间,适配云函数的deadline
	Timeout     int      `short:"T" long:"timeout" default:"5" description:"Int, timeout with request (seconds)" config:"timeout"`
	PoolSize    int      `short:"P" long:"pool" default:"5" description:"Int, Pool size" config:"pool"`
	Threads     int      `short:"t" long:"thread" default:"20" description:"Int, number of threads per pool" config:"thread"`
	Debug       bool     `long:"debug" description:"Bool, output debug info" config:"debug"`
	Version     bool     `long:"version" description:"Bool, show version"`
	Verbose     []bool   `short:"v" description:"Bool, log verbose level ,default 0, level1: -v level2 -vv " config:"verbose"`
	Proxies     []string `long:"proxy" description:"String, proxy address, e.g.: --proxy socks5://127.0.0.1:1080" config:"proxies"`
	InitConfig  bool     `long:"init" description:"Bool, init config file"`
	PrintPreset bool     `long:"print" description:"Bool, print preset all preset config "`
}

func (opt *Option) Validate() error {
	if opt.Uppercase && opt.Lowercase {
		return errors.New("cannot set -U and -L at the same time")
	}

	if (opt.Offset != 0 || opt.Limit != 0) && opt.Depth > 0 {
		// 偏移和上限与递归同时使用时也会造成混淆.
		return errors.New("--offset and --limit cannot be used with --depth at the same time")
	}

	if opt.Depth > 0 && opt.ResumeFrom != "" {
		// 递归与断点续传会造成混淆, 断点续传的word与rule不是通过命令行获取的
		return errors.New("--resume and --depth cannot be used at the same time")
	}

	if opt.ResumeFrom == "" && len(opt.URL) == 0 && opt.URLFile == "" && len(opt.CIDRs) == 0 && opt.RawFile == "" {
		return fmt.Errorf("without any target, please use -u/-l/-c/--resume to set targets")
	}

	return nil
}

func (opt *Option) Prepare() error {
	var err error
	logs.Log.SetColor(true)
	if err = opt.FingerOptions.Validate(); err != nil {
		return err
	}

	if opt.FingerUpdate {
		err = opt.UpdateFinger()
		if err != nil {
			return err
		}
	}
	err = opt.LoadLocalFingerConfig()
	if err != nil {
		return err
	}

	err = opt.Validate()
	if err != nil {
		return err
	}
	err = pkg.LoadFingers()
	if err != nil {
		return err
	}

	err = pkg.Load()
	if err != nil {
		return err
	}

	if opt.Extracts != nil {
		for _, e := range opt.Extracts {
			if reg, ok := pkg.ExtractRegexps[e]; ok {
				pkg.Extractors[e] = reg
			} else {
				pkg.Extractors[e] = []*parsers.Extractor{
					&parsers.Extractor{
						Name:            e,
						CompiledRegexps: []*regexp.Regexp{regexp.MustCompile(e)},
					},
				}
			}
		}
	}
	if opt.ExtractConfig != "" {
		extracts, err := pkg.LoadExtractorConfig(opt.ExtractConfig)
		if err != nil {
			return err
		}
		pkg.Extractors[opt.ExtractConfig] = extracts
	}

	// 初始化全局变量
	baseline.Distance = uint8(opt.SimhashDistance)
	if opt.MaxBodyLength == -1 {
		ihttp.DefaultMaxBodySize = -1
	} else {
		ihttp.DefaultMaxBodySize = opt.MaxBodyLength * 1024
	}

	pkg.BlackStatus = pkg.ParseStatus(pkg.DefaultBlackStatus, opt.BlackStatus)
	pkg.WhiteStatus = pkg.ParseStatus(pkg.DefaultWhiteStatus, opt.WhiteStatus)
	if opt.FuzzyStatus == "all" {
		pool.EnableAllFuzzy = true
	} else {
		pkg.FuzzyStatus = pkg.ParseStatus(pkg.DefaultFuzzyStatus, opt.FuzzyStatus)
	}

	if opt.Unique {
		pool.EnableAllUnique = true
	} else {
		pkg.UniqueStatus = pkg.ParseStatus(pkg.DefaultUniqueStatus, opt.UniqueStatus)
	}

	logs.Log.Logf(pkg.LogVerbose, "Black Status: %v, WhiteStatus: %v, WAFStatus: %v", pkg.BlackStatus, pkg.WhiteStatus, pkg.WAFStatus)
	logs.Log.Logf(pkg.LogVerbose, "Fuzzy Status: %v, Unique Status: %v", pkg.FuzzyStatus, pkg.UniqueStatus)

	return nil
}

func (opt *Option) NewRunner() (*Runner, error) {
	var err error
	r := &Runner{
		Option:   opt,
		taskCh:   make(chan *Task),
		OutputCh: make(chan *baseline.Baseline, 256),
		poolwg:   &sync.WaitGroup{},
		OutWg:    &sync.WaitGroup{},
		fuzzyCh:  make(chan *baseline.Baseline, 256),
		Headers:  make(map[string]string),
		Total:    opt.Limit,
		Color:    true,
	}

	// log and bar
	if opt.NoColor {
		logs.Log.SetColor(false)
		r.Color = false
	}
	if opt.Quiet {
		logs.Log.SetQuiet(true)
		logs.Log.SetColor(false)
		r.Color = false
	}

	if !(opt.Quiet || opt.NoBar) {
		r.Progress = mpb.New(mpb.WithRefreshRate(100 * time.Millisecond))
		logs.Log.SetOutput(r.Progress)
	}

	// configuration
	if opt.Force {
		// 如果开启了force模式, 将关闭check机制, err积累到一定数量自动退出机制
		r.BreakThreshold = MAX
		r.CheckPeriod = MAX
		r.ErrPeriod = MAX
	}

	// 选择client
	if opt.Client == "auto" {
		r.ClientType = ihttp.Auto
	} else if opt.Client == "fast" {
		r.ClientType = ihttp.FAST
	} else if opt.Client == "standard" || opt.Client == "base" || opt.Client == "http" {
		r.ClientType = ihttp.STANDARD
	}

	if len(opt.Proxies) > 0 {
		urls, err := proxyclient.ParseProxyURLs(opt.Proxies)
		if err != nil {
			return nil, err
		}
		r.ProxyClient, err = proxyclient.NewClientChain(urls)
		if err != nil {
			return nil, err
		}
	}
	err = opt.BuildPlugin(r)
	if err != nil {
		return nil, err
	}

	err = opt.BuildWords(r)
	if err != nil {
		return nil, err
	}

	if opt.Threads == DefaultThreads && r.bruteMod {
		r.Threads = 1000
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

	r.Tasks, err = opt.BuildTasks(r)
	if err != nil {
		return nil, err
	}

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

	// 初始化递归
	var express string
	if opt.Recursive != "current.IsDir()" && opt.Depth != 0 {
		// 默认不打开递归, 除非指定了非默认的递归表达式
		opt.Depth = 1
		express = opt.Recursive
	}

	if opt.Depth != 0 {
		// 手动设置的depth优先级高于默认
		express = opt.Recursive
	}

	if express != "" {
		exp, err := expr.Compile(express)
		if err != nil {
			return nil, err
		}
		r.RecursiveExpr = exp
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

	if !opt.Quiet {
		fmt.Println(opt.PrintConfig(r))
	}

	// init output file
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
	}
	if err != nil {
		return nil, err
	}

	if !opt.NoStat {
		r.StatFile, err = files.NewFile(pkg.SafeFilename(r.Tasks.Name)+".stat", false, true, true)
		r.StatFile.Mod = os.O_WRONLY | os.O_CREATE
		err = r.StatFile.Init()
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (opt *Option) PrintConfig(r *Runner) string {
	// 定义颜色样式
	keyStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Width(20) // Key 加粗并设定宽度
	stringValueStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA07A"))              // 字符串样式
	arrayValueStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#98FB98"))               // 数组样式
	numberValueStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#ADD8E6"))              // 数字样式
	panelWidth := 60                                                                           // 调整 panelWidth 使内容稍微靠左
	padding := 2                                                                               // 减少 padding 以调整布局靠左

	// 分割线样式和终端宽度计算
	divider := strings.Repeat("─", panelWidth) // 使用"─"符号生成更加连贯的分割线

	// 处理不同类型的值
	formatValue := func(value interface{}) string {
		switch v := value.(type) {
		case string:
			return stringValueStyle.Render(v)
		case []string:
			return arrayValueStyle.Render(fmt.Sprintf("%v", v))
		case int, int64, float64:
			return numberValueStyle.Render(fmt.Sprintf("%v", v))
		default:
			return stringValueStyle.Render(fmt.Sprintf("%v", v)) // 默认为字符串样式
		}
	}

	// 处理互斥参数，选择输出有值的那一个
	inputSource := ""
	if opt.ResumeFrom != "" {
		inputSource = lipgloss.JoinHorizontal(lipgloss.Left, "🌀 ", keyStyle.Render("ResumeFrom: "), formatValue(opt.ResumeFrom))
	} else if len(opt.URL) > 0 {
		inputSource = lipgloss.JoinHorizontal(lipgloss.Left, "🌐 ", keyStyle.Render("URL: "), formatValue(opt.URL))
	} else if opt.URLFile != "" {
		inputSource = lipgloss.JoinHorizontal(lipgloss.Left, "📂 ", keyStyle.Render("URLFile: "), formatValue(opt.URLFile))
	} else if len(opt.CIDRs) > 0 {
		inputSource = lipgloss.JoinHorizontal(lipgloss.Left, "📡 ", keyStyle.Render("CIDRs: "), formatValue(opt.CIDRs))
	} else if opt.RawFile != "" {
		inputSource = lipgloss.JoinHorizontal(lipgloss.Left, "📄 ", keyStyle.Render("RawFile: "), formatValue(opt.RawFile))
	}

	// Input Options
	inputOptions := lipgloss.JoinVertical(lipgloss.Left,
		inputSource, // 互斥量处理

		// PortRange 展示
		lipgloss.JoinHorizontal(lipgloss.Left, "🔢 ", keyStyle.Render("PortRange: "), formatValue(opt.PortRange)),

		// Dictionaries 展示
		lipgloss.JoinHorizontal(lipgloss.Left, "📚 ", keyStyle.Render("Dictionaries: "), formatValue(opt.Dictionaries)),

		// Word, Rules, FilterRule 展开为单独的行
		lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.JoinHorizontal(lipgloss.Left, "💡 ", keyStyle.Render("Word: "), formatValue(r.Word)),
			lipgloss.JoinHorizontal(lipgloss.Left, "📜 ", keyStyle.Render("Rules: "), formatValue(opt.Rules)),
			lipgloss.JoinHorizontal(lipgloss.Left, "🔍 ", keyStyle.Render("FilterRule: "), formatValue(opt.FilterRule)),
		),

		// AppendRule 和 AppendWords 展开为单独的行
		lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.JoinHorizontal(lipgloss.Left, "🔧 ", keyStyle.Render("AppendRule: "), formatValue(r.AppendRule)),
			lipgloss.JoinHorizontal(lipgloss.Left, "🧩 ", keyStyle.Render("AppendWords: "), formatValue(len(r.AppendWords))),
		),
	)

	// Output Options
	outputOptions := lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.JoinHorizontal(lipgloss.Left, "📊 ", keyStyle.Render("Match: "), formatValue(opt.Match)),
		lipgloss.JoinHorizontal(lipgloss.Left, "⚙️ ", keyStyle.Render("Filter: "), formatValue(opt.Filter)),
	)

	// Plugin Options
	pluginValues := []string{}
	if opt.ActivePlugin {
		pluginValues = append(pluginValues, "active")
	}
	if opt.ReconPlugin {
		pluginValues = append(pluginValues, "recon")
	}
	if opt.BakPlugin {
		pluginValues = append(pluginValues, "bak")
	}
	if opt.FuzzuliPlugin {
		pluginValues = append(pluginValues, "fuzzuli")
	}
	if opt.CommonPlugin {
		pluginValues = append(pluginValues, "common")
	}
	if opt.CrawlPlugin {
		pluginValues = append(pluginValues, "crawl")
	}

	pluginOptions := lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.JoinHorizontal(lipgloss.Left, "🔎 ", keyStyle.Render("Extracts: "), formatValue(opt.Extracts)),
		lipgloss.JoinHorizontal(lipgloss.Left, "🔌 ", keyStyle.Render("Plugins: "), formatValue(strings.Join(pluginValues, ", "))),
	)

	// Mode Options
	modeOptions := lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.JoinHorizontal(lipgloss.Left, "🛑 ", keyStyle.Render("BlackStatus: "), formatValue(pkg.BlackStatus)),
		lipgloss.JoinHorizontal(lipgloss.Left, "✅ ", keyStyle.Render("WhiteStatus: "), formatValue(pkg.WhiteStatus)),
		lipgloss.JoinHorizontal(lipgloss.Left, "🔄 ", keyStyle.Render("FuzzyStatus: "), formatValue(pkg.FuzzyStatus)),
		lipgloss.JoinHorizontal(lipgloss.Left, "🔒 ", keyStyle.Render("UniqueStatus: "), formatValue(pkg.UniqueStatus)),
		lipgloss.JoinHorizontal(lipgloss.Left, "🔑 ", keyStyle.Render("Unique: "), formatValue(opt.Unique)),
	)

	// Misc Options
	miscOptions := lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.JoinHorizontal(lipgloss.Left, "⏱ ", keyStyle.Render("Timeout: "), formatValue(opt.Timeout)),
		lipgloss.JoinHorizontal(lipgloss.Left, "📈 ", keyStyle.Render("PoolSize: "), formatValue(opt.PoolSize)),
		lipgloss.JoinHorizontal(lipgloss.Left, "🧵 ", keyStyle.Render("Threads: "), formatValue(opt.Threads)),
		lipgloss.JoinHorizontal(lipgloss.Left, "🌍 ", keyStyle.Render("Proxies: "), formatValue(opt.Proxies)),
	)

	// 将所有内容拼接在一起
	content := lipgloss.JoinVertical(lipgloss.Left,
		inputOptions,
		outputOptions,
		pluginOptions,
		modeOptions,
		miscOptions,
	)

	// 使用正确的方式添加 padding，并居中显示内容
	contentWithPadding := lipgloss.NewStyle().PaddingLeft(padding).Render(content)

	// 使用 Place 方法来将整个内容居中显示
	return lipgloss.Place(panelWidth+padding*2, 0, lipgloss.Center, lipgloss.Center,
		lipgloss.JoinVertical(lipgloss.Center,
			divider, // 顶部分割线
			contentWithPadding,
			divider, // 底部分割线
		),
	)
}

func (opt *Option) BuildPlugin(r *Runner) error {
	// brute only
	if opt.Advance {
		opt.CrawlPlugin = true
		opt.Finger = true
		opt.BakPlugin = true
		opt.FuzzuliPlugin = true
		opt.CommonPlugin = true
		opt.ActivePlugin = true
		opt.ReconPlugin = true
	}

	if opt.ReconPlugin {
		pkg.Extractors["recon"] = pkg.ExtractRegexps["pentest"]
	}

	if opt.Finger {
		pkg.EnableAllFingerEngine = true
	}

	if opt.BakPlugin {
		r.bruteMod = true
		opt.AppendRule = append(opt.AppendRule, "filebak")
		r.AppendWords = append(r.AppendWords, pkg.GetPresetWordList([]string{"bak_file"})...)
	}

	if opt.CommonPlugin {
		r.bruteMod = true
		r.AppendWords = append(r.AppendWords, pkg.Dicts["common"]...)
		r.AppendWords = append(r.AppendWords, pkg.Dicts["log"]...)
	}

	if opt.ActivePlugin {
		r.bruteMod = true
		r.AppendWords = append(r.AppendWords, pkg.ActivePath...)
	}

	if opt.CrawlPlugin {
		r.bruteMod = true
	}

	if r.bruteMod {
		logs.Log.Important("enabling brute mod, because of enabled brute plugin")
	}

	if opt.NoScope {
		r.Scope = []string{"*"}
	}
	return nil
}

func (opt *Option) BuildWords(r *Runner) error {
	var dicts [][]string
	var err error
	if opt.DefaultDict {
		dicts = append(dicts, pkg.Dicts["default"])
		logs.Log.Info("use default dictionary: https://github.com/maurosoria/dirsearch/blob/master/db/dicc.txt")
	}
	for i, f := range opt.Dictionaries {
		dict, err := pkg.LoadFileToSlice(f)
		if err != nil {
			return err
		}
		dicts = append(dicts, dict)
		if opt.ResumeFrom != "" {
			pkg.Dicts[f] = dicts[i]
		}

		logs.Log.Logf(pkg.LogVerbose, "Loaded %d word from %s", len(dict), f)
	}

	if len(dicts) == 0 && opt.Word == "" && len(opt.Rules) == 0 && len(opt.AppendRule) == 0 {
		r.IsCheck = true
	}

	if opt.Word == "" {
		opt.Word = "{?"
		for i, _ := range dicts {
			opt.Word += strconv.Itoa(i)
		}
		opt.Word += "}"
	}

	if len(opt.Suffixes) != 0 {
		mask.SpecialWords["suffix"] = opt.Suffixes
		opt.Word += "{?@suffix}"
	}
	if len(opt.Prefixes) != 0 {
		mask.SpecialWords["prefix"] = opt.Prefixes
		opt.Word = "{?@prefix}" + opt.Word
	}

	if opt.ForceExtension && opt.Extensions != "" {
		exts := strings.Split(opt.Extensions, ",")
		for i, e := range exts {
			if !strings.HasPrefix(e, ".") {
				exts[i] = "." + e
			}
		}
		mask.SpecialWords["ext"] = exts
		opt.Word += "{?@ext}"
	}

	r.Wordlist, err = mask.Run(opt.Word, dicts, nil)
	if err != nil {
		return fmt.Errorf("%s %w", opt.Word, err)
	}
	if len(r.Wordlist) > 0 {
		logs.Log.Logf(pkg.LogVerbose, "Parsed %d words by %s", len(r.Wordlist), opt.Word)
	}

	if len(opt.Rules) != 0 {
		rules, err := pkg.LoadRuleAndCombine(opt.Rules)
		if err != nil {
			return err
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

	if len(opt.AppendRule) != 0 {
		content, err := pkg.LoadRuleAndCombine(opt.AppendRule)
		if err != nil {
			return err
		}
		r.AppendRules = rule.Compile(string(content), "")
	}

	if len(opt.AppendFile) != 0 {
		var lines []string
		for _, f := range opt.AppendFile {
			dict, err := pkg.LoadFileToSlice(f)
			if err != nil {
				return err
			}
			lines = append(lines, dict...)
		}
		r.AppendWords = append(r.AppendWords, lines...)
	}

	//  类似dirsearch中的
	if opt.Extensions != "" {
		r.AppendFunction(pkg.ParseEXTPlaceholderFunc(strings.Split(opt.Extensions, ",")))
	} else {
		r.AppendFunction(func(s string) []string {
			if strings.Contains(s, pkg.EXTChar) {
				return nil
			}
			return []string{s}
		})
	}

	if opt.Uppercase {
		r.AppendFunction(pkg.WrapWordsFunc(strings.ToUpper))
	}
	if opt.Lowercase {
		r.AppendFunction(pkg.WrapWordsFunc(strings.ToLower))
	}

	if opt.RemoveExtensions != "" {
		rexts := strings.Split(opt.RemoveExtensions, ",")
		r.AppendFunction(func(s string) []string {
			if ext := pkg.ParseExtension(s); iutils.StringsContains(rexts, ext) {
				return []string{strings.TrimSuffix(s, "."+ext)}
			}
			return []string{s}
		})
	}

	if opt.ExcludeExtensions != "" {
		exexts := strings.Split(opt.ExcludeExtensions, ",")
		r.AppendFunction(func(s string) []string {
			if ext := pkg.ParseExtension(s); iutils.StringsContains(exexts, ext) {
				return nil
			}
			return []string{s}
		})
	}

	if len(opt.Replaces) > 0 {
		r.AppendFunction(func(s string) []string {
			for k, v := range opt.Replaces {
				s = strings.Replace(s, k, v, -1)
			}
			return []string{s}
		})
	}

	if len(opt.Skips) > 0 {
		r.AppendFunction(func(s string) []string {
			for _, skip := range opt.Skips {
				if strings.Contains(s, skip) {
					return nil
				}
			}
			return []string{s}
		})
	}

	return nil
}

func (opt *Option) BuildTasks(r *Runner) (*TaskGenerator, error) {
	// prepare task`
	var err error
	gen := NewTaskGenerator(opt.PortRange)
	if opt.ResumeFrom != "" {
		stats, err := pkg.ReadStatistors(opt.ResumeFrom)
		if err != nil {
			logs.Log.Error(err.Error())
		}
		r.Count = len(stats)
		gen.Name = "resume " + opt.ResumeFrom
		go func() {
			for _, stat := range stats {
				gen.In <- &Task{baseUrl: stat.BaseUrl, origin: NewOrigin(stat)}
			}
			close(gen.In)
		}()
	} else {
		var file *os.File

		// 根据不同的输入类型生成任务
		if len(opt.URL) == 1 {
			gen.Name = opt.URL[0]
			go func() {
				gen.Run(opt.URL[0])
				close(gen.In)
			}()
			r.Count = 1
		} else if len(opt.URL) > 1 {
			go func() {
				for _, u := range opt.URL {
					gen.Run(u)
				}
				close(gen.In)
			}()
			gen.Name = "cmd"
			r.Count = len(opt.URL)
		} else if opt.RawFile != "" {
			raw, err := os.Open(opt.RawFile)
			if err != nil {
				return nil, err
			}

			req, err := http.ReadRequest(bufio.NewReader(raw))
			if err != nil {
				return nil, err
			}
			go func() {
				gen.Run(fmt.Sprintf("http://%s%s", req.Host, req.URL.String()))
				close(gen.In)
			}()
			r.Method = req.Method
			for k, _ := range req.Header {
				r.Headers[k] = req.Header.Get(k)
			}
			r.Count = 1
		} else if len(opt.CIDRs) != 0 {
			cidrs := utils.ParseCIDRs(opt.CIDRs)
			if len(gen.ports) == 0 {
				gen.ports = []string{"80", "443"}
			}
			gen.Name = "cidr"
			r.Count = cidrs.Count()
			go func() {
				for _, cidr := range cidrs {
					if cidr == nil {
						logs.Log.Error("cidr format error: " + cidr.String())
					}
					for ip := range cidr.Range() {
						gen.Run(ip.String())
					}
				}
				close(gen.In)
			}()
		} else if opt.URLFile != "" {
			file, err = os.Open(opt.URLFile)
			if err != nil {
				return nil, err
			}
			gen.Name = filepath.Base(opt.URLFile)
		} else if files.HasStdin() {
			file = os.Stdin
			gen.Name = "stdin"
		}
		if file != nil {
			content, err := ioutil.ReadAll(file)
			if err != nil {
				return nil, err
			}
			urls := strings.Split(strings.TrimSpace(string(content)), "\n")
			for _, u := range urls {
				u = strings.TrimSpace(u)
				if _, err := url.Parse(u); err == nil {
					r.Count++
				} else if ip := utils.ParseIP(u); ip != nil {
					r.Count++
				} else if cidr := utils.ParseCIDR(u); cidr != nil {
					r.Count += cidr.Count()
				}
			}

			go func() {
				for _, u := range urls {
					u = strings.TrimSpace(u)
					if _, err := url.Parse(u); err == nil {
						gen.Run(u)
					} else if ip := utils.ParseIP(u); ip != nil {
						gen.Run(u)
					} else if cidr := utils.ParseCIDR(u); cidr != nil {
						for ip := range cidr.Range() {
							gen.Run(ip.String())
						}
					}
				}
				close(gen.In)
			}()
		}
	}

	if len(gen.ports) > 0 {
		r.Count = r.Count * len(gen.ports)
	}
	return gen, nil
}
