package sdk

import (
	"context"
	"fmt"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/spray/core"
	"github.com/chainreactors/spray/pkg"
)

// SprayEngine Spray 扫描器 SDK
type SprayEngine struct {
	Option *core.Option // 默认配置选项
}

// NewSprayEngine 创建新的 Spray SDK 实例
func NewSprayEngine(opt *core.Option) *SprayEngine {
	if opt == nil {
		opt = DefaultConfig()
	}
	return &SprayEngine{
		Option: opt,
	}
}

// Init 初始化 SDK，加载必要的配置（指纹库等持久化状态）
func (s *SprayEngine) Init() error {
	err := pkg.Load()
	if err != nil {
		return fmt.Errorf("load config failed, %v", err)
	}

	err = pkg.LoadFingers()
	if err != nil {
		return fmt.Errorf("load fingers failed, %v", err)
	}

	return nil
}

// SetThreads 设置线程数
func (s *SprayEngine) SetThreads(threads int) {
	s.Option.Threads = threads
}

// SetTimeout 设置超时时间（秒）
func (s *SprayEngine) SetTimeout(timeout int) {
	s.Option.Timeout = timeout
}

// DefaultConfig 返回默认配置
// 基于 core.Option 的默认值，并针对 SDK 使用场景进行优化
func DefaultConfig() *core.Option {
	opt := &core.Option{}

	// Request Options - 参考 core/option.go:101-110
	opt.Method = "GET"      // default: "GET"
	opt.MaxBodyLength = 100 // default: 100 (KB)
	opt.RandomUserAgent = false

	// Mode Options - 参考 core/option.go:128-147
	opt.BlackStatus = "400,410"                     // default: "400,410"
	opt.WhiteStatus = "200"                         // default: "200"
	opt.FuzzyStatus = "500,501,502,503,301,302,404" // default
	opt.UniqueStatus = "403,200,404"                // default
	opt.CheckPeriod = 200                           // default: 200
	opt.ErrPeriod = 10                              // default: 10
	opt.BreakThreshold = 20                         // default: 20
	opt.Recursive = "current.IsDir()"               // default
	opt.Depth = 0                                   // default: 0
	opt.Index = "/"                                 // default: "/"
	opt.Random = ""                                 // default: ""
	opt.RetryCount = 0                              // default: 0
	opt.SimhashDistance = 8                         // default: 8

	// Misc Options - 参考 core/option.go:149-163
	opt.Mod = "path"      // default: "path"
	opt.Client = "auto"   // default: "auto"
	opt.Timeout = 5       // default: 5 (seconds)
	opt.Threads = 20      // default: 20
	opt.PoolSize = 1      // SDK 优化: 默认 1 个 pool（原始默认 5）
	opt.Deadline = 999999 // default: 999999

	// Output Options - SDK 优化
	opt.Quiet = true        // SDK 优化: 静默模式
	opt.NoBar = true        // SDK 优化: 不显示进度条
	opt.NoStat = true       // SDK 优化: 不输出统计文件
	opt.NoColor = false     // default: false
	opt.Json = false        // default: false
	opt.FileOutput = "json" // default: "json"

	// Plugin Options - 默认关闭所有插件
	opt.Advance = false
	opt.Finger = false
	opt.CrawlPlugin = false
	opt.BakPlugin = false
	opt.FuzzuliPlugin = false
	opt.CommonPlugin = false
	opt.ActivePlugin = false
	opt.ReconPlugin = false
	opt.CrawlDepth = 3        // default: 3
	opt.AppendDepth = 2       // default: 2
	opt.FingerEngines = "all" // default: "all"

	return opt
}

// CheckStream 批量 URL 检测流式模式，返回实时结果 channel
func (s *SprayEngine) CheckStream(ctx context.Context, urls []string) (<-chan *parsers.SprayResult, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("urls cannot be empty")
	}

	// 克隆配置避免修改原始配置
	opt := *s.Option
	opt.URL = urls

	// 准备配置
	err := opt.Prepare()
	if err != nil {
		return nil, fmt.Errorf("prepare config failed: %v", err)
	}

	// 创建 Runner
	runner, err := opt.NewRunner()
	if err != nil {
		return nil, fmt.Errorf("create runner failed: %v", err)
	}

	// 强制设置为 check 模式
	runner.IsCheck = true

	// 创建结果 channel
	resultCh := make(chan *parsers.SprayResult, 100)

	// 启动检测 goroutine
	go func() {
		defer close(resultCh)
		defer closeRunner(runner)

		// 启动结果处理 goroutine
		go func() {
			for bl := range runner.OutputCh {
				select {
				case resultCh <- bl.SprayResult:
				case <-ctx.Done():
					return
				}
				runner.OutWg.Done()
			}
		}()

		// 运行检测
		err = runner.Prepare(ctx)
		if err != nil {
			logs.Log.Errorf("runner prepare failed: %v", err)
			return
		}
	}()

	return resultCh, nil
}

// BruteStream 暴力破解流式模式，返回实时结果 channel
func (s *SprayEngine) BruteStream(ctx context.Context, baseURL string, wordlist []string) (<-chan *parsers.SprayResult, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("baseURL cannot be empty")
	}

	if len(wordlist) == 0 {
		return nil, fmt.Errorf("wordlist cannot be empty")
	}

	// 克隆配置避免修改原始配置
	opt := *s.Option
	opt.URL = []string{baseURL}

	// 准备配置
	err := opt.Prepare()
	if err != nil {
		return nil, fmt.Errorf("prepare config failed: %v", err)
	}

	// 创建 Runner
	runner, err := opt.NewRunner()
	if err != nil {
		return nil, fmt.Errorf("create runner failed: %v", err)
	}

	// 设置字典和模式
	runner.Wordlist = wordlist
	runner.Total = len(wordlist)
	runner.IsCheck = false

	// 创建结果 channel
	resultCh := make(chan *parsers.SprayResult, 100)

	// 启动暴力破解 goroutine
	go func() {
		defer close(resultCh)
		defer closeRunner(runner)

		// 启动结果处理 goroutine
		go func() {
			for bl := range runner.OutputCh {
				select {
				case resultCh <- bl.SprayResult:
				case <-ctx.Done():
					return
				}
				runner.OutWg.Done()
			}
		}()

		// 运行暴力破解
		err = runner.Prepare(ctx)
		if err != nil {
			logs.Log.Errorf("runner prepare failed: %v", err)
			return
		}
	}()

	return resultCh, nil
}

// Check 批量 URL 检测，返回所有结果切片
func (s *SprayEngine) Check(ctx context.Context, urls []string) ([]*parsers.SprayResult, error) {
	resultCh, err := s.CheckStream(ctx, urls)
	if err != nil {
		return nil, err
	}

	var results []*parsers.SprayResult
	for result := range resultCh {
		results = append(results, result)
	}

	return results, nil
}

// Brute 暴力破解，返回所有结果切片
func (s *SprayEngine) Brute(ctx context.Context, baseURL string, wordlist []string) ([]*parsers.SprayResult, error) {
	resultCh, err := s.BruteStream(ctx, baseURL, wordlist)
	if err != nil {
		return nil, err
	}

	var results []*parsers.SprayResult
	for result := range resultCh {
		results = append(results, result)
	}

	return results, nil
}

// closeRunner 关闭 Runner 的资源
func closeRunner(runner *core.Runner) {
	if runner.OutputFile != nil {
		runner.OutputFile.Close()
	}
	if runner.DumpFile != nil {
		runner.DumpFile.Close()
	}
	if runner.StatFile != nil {
		runner.StatFile.Close()
	}
	if runner.Progress != nil {
		runner.Progress.Wait()
	}
}
