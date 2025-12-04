package sdk

import (
	"context"
	"testing"
	"time"
)

func TestInit(t *testing.T) {
	engine := NewSprayEngine(nil)
	err := engine.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestCheckStream(t *testing.T) {
	// 创建 SprayEngine
	engine := NewSprayEngine(nil)
	err := engine.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// 自定义配置
	engine.SetThreads(10)

	// 测试 URL 列表
	urls := []string{
		"http://example.com",
		"http://httpbin.org/get",
		"http://www.baidu.com",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 调用 CheckStream
	resultCh, err := engine.CheckStream(ctx, urls)
	if err != nil {
		t.Fatalf("CheckStream failed: %v", err)
	}

	// 接收结果
	count := 0
	for result := range resultCh {
		t.Logf("Result: URL=%s, Status=%d, Valid=%v",
			result.UrlString, result.Status, result.IsValid)
		count++
	}

	t.Logf("Total results: %d", count)
}

func TestCheck(t *testing.T) {
	// 创建 SprayEngine
	engine := NewSprayEngine(nil)
	err := engine.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// 自定义配置
	engine.SetThreads(10)

	// 测试 URL 列表
	urls := []string{
		"http://httpbin.org/get",
		"http://httpbin.org/status/200",
		"http://httpbin.org/status/404",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 调用 Check
	results, err := engine.Check(ctx, urls)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	t.Logf("Total results: %d", len(results))
	for _, result := range results {
		t.Logf("Result: URL=%s, Status=%d, Valid=%v",
			result.UrlString, result.Status, result.IsValid)
	}
}

func TestBruteStream(t *testing.T) {
	// 创建 SprayEngine
	engine := NewSprayEngine(nil)
	err := engine.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// 测试字典
	wordlist := []string{
		"admin",
		"test",
		"api",
		"index.html",
		"robots.txt",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 调用 BruteStream
	resultCh, err := engine.BruteStream(ctx, "http://httpbin.org", wordlist)
	if err != nil {
		t.Fatalf("BruteStream failed: %v", err)
	}

	// 接收结果
	count := 0
	for result := range resultCh {
		t.Logf("Result: URL=%s, Status=%d, Valid=%v",
			result.UrlString, result.Status, result.IsValid)
		count++
	}

	t.Logf("Total valid results: %d", count)
}

func TestBrute(t *testing.T) {
	// 创建 SprayEngine
	engine := NewSprayEngine(nil)
	err := engine.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// 测试字典
	wordlist := []string{
		"get",
		"post",
		"status/200",
		"headers",
		"ip",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 调用 Brute
	results, err := engine.Brute(ctx, "http://httpbin.org", wordlist)
	if err != nil {
		t.Fatalf("Brute failed: %v", err)
	}

	t.Logf("Total valid results: %d", len(results))
	for _, result := range results {
		t.Logf("Result: URL=%s, Status=%d, Length=%d",
			result.UrlString, result.Status, result.BodyLength)
	}
}

func TestCheckWithCustomHeaders(t *testing.T) {
	// 创建 SprayEngine 并自定义配置
	opt := DefaultConfig()
	opt.Headers = []string{
		"X-Custom-Header: test-value",
		"Authorization: Bearer token123",
	}

	engine := NewSprayEngine(opt)
	err := engine.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	engine.SetThreads(10)

	urls := []string{
		"http://httpbin.org/headers",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := engine.Check(ctx, urls)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	for _, result := range results {
		t.Logf("Result: URL=%s, Status=%d", result.UrlString, result.Status)
	}
}

func TestBruteWithFilter(t *testing.T) {
	// 创建 SprayEngine 并自定义配置
	opt := DefaultConfig()
	opt.Filter = "current.Status == 404" // 过滤掉 404

	engine := NewSprayEngine(opt)
	err := engine.Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	wordlist := []string{
		"get",
		"post",
		"notfound",
		"status/200",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results, err := engine.Brute(ctx, "http://httpbin.org", wordlist)
	if err != nil {
		t.Fatalf("Brute failed: %v", err)
	}

	t.Logf("Total valid results (after filter): %d", len(results))
	for _, result := range results {
		t.Logf("Result: URL=%s, Status=%d", result.UrlString, result.Status)
	}
}

func TestMultipleEngines(t *testing.T) {
	// 测试多个 SprayEngine 实例共享持久化状态
	engine1 := NewSprayEngine(nil)
	err := engine1.Init()
	if err != nil {
		t.Fatalf("Engine1 Init failed: %v", err)
	}

	engine2 := NewSprayEngine(nil)
	engine2.SetThreads(50)
	engine2.SetTimeout(10)

	urls := []string{
		"http://httpbin.org/get",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 使用两个不同的 engine
	results1, err := engine1.Check(ctx, urls)
	if err != nil {
		t.Fatalf("Engine1 Check failed: %v", err)
	}

	results2, err := engine2.Check(ctx, urls)
	if err != nil {
		t.Fatalf("Engine2 Check failed: %v", err)
	}

	t.Logf("Engine1 results: %d, Engine2 results: %d", len(results1), len(results2))
}
