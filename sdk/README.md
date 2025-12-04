# Spray SDK

Spray SDK 提供了简洁的 Go API，用于 HTTP URL 检测和路径暴力破解。

## 核心概念

SDK 由两部分组成：

1. **SprayEngine**: 管理持久化状态（指纹库等）
2. **两个核心 API**:
   - `CheckStream`: URL 批量检测，返回 channel
   - `BruteStream`: 路径暴力破解，返回 channel

其他 API（`Check`、`Brute`）都是对 Stream API 的简单封装，你也可以根据需要自行封装。

## 快速开始

```go
import "github.com/chainreactors/spray/sdk"

// 1. 创建 SprayEngine
engine := sdk.NewSprayEngine(nil)

// 2. 初始化（加载指纹库等）
engine.Init()

// 3. 使用
ctx := context.Background()

// URL 检测
urls := []string{"http://example.com", "http://httpbin.org"}
resultCh, _ := engine.CheckStream(ctx, urls)
for result := range resultCh {
    fmt.Printf("%s [%d]\n", result.UrlString, result.Status)
}

// 路径暴力破解
wordlist := []string{"admin", "api", "test"}
resultCh, _ := engine.BruteStream(ctx, "http://example.com", wordlist)
for result := range resultCh {
    fmt.Printf("%s [%d]\n", result.UrlString, result.Status)
}
```

## 配置

### 使用默认配置

```go
engine := sdk.NewSprayEngine(nil)
```

默认配置针对 SDK 场景优化：静默模式、无进度条、单 pool、20 线程。

### 自定义配置

```go
opt := sdk.DefaultConfig()
opt.Threads = 100
opt.Timeout = 10
opt.Filter = "current.Status == 404"  // 过滤 404
opt.Headers = []string{"Authorization: Bearer token"}

engine := sdk.NewSprayEngine(opt)
```

### 运行时修改

```go
engine.SetThreads(50)
engine.SetTimeout(10)
```

## API 参考

### SprayEngine

```go
// 创建实例
engine := sdk.NewSprayEngine(opt)  // opt 为 nil 时使用默认配置

// 初始化（必须调用）
engine.Init()

// 设置参数
engine.SetThreads(threads)
engine.SetTimeout(timeout)
```

### 核心 API

```go
// URL 检测（流式）
CheckStream(ctx, urls) -> channel

// 暴力破解（流式）
BruteStream(ctx, baseURL, wordlist) -> channel
```

### 便捷 API

```go
// URL 检测（批量）
Check(ctx, urls) -> []result

// 暴力破解（批量）
Brute(ctx, baseURL, wordlist) -> []result
```

## 配置选项

`core.Option` 包含所有 spray 的配置项，常用的有：

**请求配置**
- `Method`: HTTP 方法
- `Timeout`: 超时时间（秒）
- `Threads`: 线程数
- `Headers`: 自定义请求头
- `MaxBodyLength`: 最大响应体长度（KB）

**模式配置**
- `Mod`: 扫描模式（`path` 或 `host`）
- `Filter`: 过滤规则（expr 表达式）
- `Match`: 匹配规则（expr 表达式）
- `BlackStatus`: 黑名单状态码
- `WhiteStatus`: 白名单状态码
- `RateLimit`: 速率限制（请求/秒）

**插件配置**
- `Finger`: 启用指纹识别
- `CrawlPlugin`: 启用爬虫
- `BakPlugin`: 启用备份文件检测

完整配置项参考 `core.Option` 结构体。

## 结果结构

```go
type SprayResult struct {
    UrlString   string              // URL
    Status      int                 // HTTP 状态码
    BodyLength  int                 // 响应体长度
    Title       string              // 页面标题
    IsValid     bool                // 是否有效
    Frameworks  common.Frameworks   // 识别的框架
    Extracts    map[string][]string // 提取的信息
}
```

## 完整示例

### 示例 1: URL 批量检测

```go
package main

import (
    "context"
    "fmt"
    "github.com/chainreactors/spray/sdk"
)

func main() {
    engine := sdk.NewSprayEngine(nil)
    engine.Init()
    engine.SetThreads(50)

    urls := []string{
        "http://example.com",
        "http://httpbin.org/get",
    }

    ctx := context.Background()
    results, _ := engine.Check(ctx, urls)

    for _, r := range results {
        if r.IsValid {
            fmt.Printf("[+] %s [%d] %s\n", r.UrlString, r.Status, r.Title)
        }
    }
}
```

### 示例 2: 路径暴力破解（流式）

```go
package main

import (
    "context"
    "fmt"
    "github.com/chainreactors/spray/sdk"
)

func main() {
    opt := sdk.DefaultConfig()
    opt.Threads = 100
    opt.Filter = "current.Status == 404"

    engine := sdk.NewSprayEngine(opt)
    engine.Init()

    wordlist := []string{"admin", "api", "test", ".git"}
    ctx := context.Background()

    resultCh, _ := engine.BruteStream(ctx, "http://example.com", wordlist)
    for result := range resultCh {
        fmt.Printf("[+] %s [%d] %d bytes\n",
            result.UrlString, result.Status, result.BodyLength)
    }
}
```

### 示例 3: 多实例共享指纹库

```go
package main

import (
    "context"
    "github.com/chainreactors/spray/sdk"
)

func main() {
    // 第一个实例初始化指纹库
    engine1 := sdk.NewSprayEngine(nil)
    engine1.Init()

    // 第二个实例共享已加载的指纹库
    opt2 := sdk.DefaultConfig()
    opt2.Threads = 100
    engine2 := sdk.NewSprayEngine(opt2)
    // 不需要再次 Init

    ctx := context.Background()

    // 并发使用
    go engine1.Check(ctx, urls1)
    go engine2.Check(ctx, urls2)
}
```

## 注意事项

1. **必须初始化**: 创建 `SprayEngine` 后必须调用 `Init()` 加载指纹库
2. **配置克隆**: SDK 内部会克隆配置，避免并发修改
3. **共享状态**: 多个 `SprayEngine` 实例共享已加载的指纹库
4. **自动清理**: Stream 模式会自动清理资源

## 许可证

MIT License
