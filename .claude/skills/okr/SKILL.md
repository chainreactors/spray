---
name: okr
description: "本项目的 OKR 目标和关键结果。每次开始新任务前参考此 OKR 确保工作方向一致。生成时间：2026-03-22。基于项目诊断 + 用户意图共同生成。"
license: MIT
---

# spray — OKR

> 本文件由 okr-creator skill 自动生成，基于对项目的全面分析和与项目负责人的对齐。
> 生成时间：2026-03-22
> 建议每季度重新运行 /okr:create 更新。

## 项目概况

**spray** — 最好用最智能最可控的目录 Fuzz 工具，Go 编写，995 stars / 67 forks / 410 commits。
技术栈：Go 1.20 + fasthttp + ants goroutine pool + chainreactors 生态（fingers/parsers/words/utils）。
当前阶段：**快速成长期 → 稳定成熟期过渡**。用户量上来了，但稳定性和质量还没跟上。

## 六维诊断摘要

| 维度 | 现状评分 (1-5) | 关键发现 |
|------|--------------|---------|
| 项目愿景 | 4 | 定位清晰，功能丰富（指纹+爬虫+提取+断点续传），缺公开 roadmap |
| 交付质量 | 2 | 50 个 open issues，近期密集修 panic/deadlock/channel close，并发安全是系统性风险 |
| 历史债务 | 3 | 代码无 TODO/FIXME，但 GitHub Issues 积压严重：crawler 无限递归、JSON panic、低并发报错、Windows 路径 |
| 结构架构 | 4 | cmd/core/pkg 三层清晰，但 option.go 38KB 巨型文件，templates.go 125KB 生成代码 |
| 文档完善 | 2 | 只有 4.4KB README，无 CHANGELOG、无贡献者指南，依赖外部 wiki |
| 自动化 | 3 | CI 矩阵测试 + goreleaser 自动发版，但仅 5 个测试文件，无覆盖率报告 |

## 用户意图

- **方向：** 全面推进（稳定性、功能、文档并行）
- **底线：** 零 panic 发版 + open issues 降到 30 以下 + 发布 v1.3.0
- **资源：** 业余维护（每周几小时）
- **核心矛盾：** 野心和资源不匹配——需要极度聚焦，用最少动作撬动最大价值

## OKR

### O1: 彻底消灭并发安全隐患，让 spray 不再崩溃

> 用户信任是根基。一个会 panic 的安全工具 = 没人敢用的安全工具。

| KR | Baseline | Target | Harness（验收方法） | 优先级 |
|----|----------|--------|-------------------|-------|
| KR1.1: 修复所有已知 panic/deadlock/channel close issue | 6 个相关 issue（#129 #127 #126 #85 #93 #117） | 0 个 panic 类 open issue | `gh issue list --repo chainreactors/spray --state open --json title \| grep -iE "panic\|deadlock\|channel\|crash\|range"` 返回空 | P0 |
| KR1.2: pool 包测试覆盖率提升 | 1 个测试文件，覆盖率未知 | pool 包测试覆盖率 ≥ 60% | `cd core/pool && go test -coverprofile=cover.out && go tool cover -func=cover.out \| grep total` 显示 ≥ 60% | P0 |
| KR1.3: CI 增加 race detector 全量检测 | 仅测试 4 个子包 | 所有包启用 `-race` 测试 | CI workflow 中 `go test -race ./...` 通过 | P1 |
| KR1.4: 修复 crawler 无限递归 #137 | 存在无限递归 bug | crawler 有深度限制，不再无限嵌套 | 对已知递归 URL 运行 `spray --crawl`，观察爬取深度不超过设定值 | P0 |

### O2: 清理 Issue 积压，将社区信任度拉回正轨

> 50 个 open issues 对一个 995 star 项目来说是危险信号。社区看到 issue 没人管，就不会再报了。

| KR | Baseline | Target | Harness（验收方法） | 优先级 |
|----|----------|--------|-------------------|-------|
| KR2.1: Open issues 数量下降 | 50 个 open issues | ≤ 30 个 open issues | `gh issue list --repo chainreactors/spray --state open --json number \| jq length` ≤ 30 | P0 |
| KR2.2: Bug 标签 issue 全部处理 | 存在多个 bug 标签 issue（#127 #126 等） | 0 个 bug 标签 open issue | `gh issue list --repo chainreactors/spray --state open --label bug --json number \| jq length` = 0 | P0 |
| KR2.3: 对所有 open issue 进行 triage 分类 | 大部分 issue 无 label | 100% issue 有 label（bug/enhancement/question/wontfix） | `gh issue list --repo chainreactors/spray --state open --json labels \| jq '[.[] \| select(.labels \| length == 0)] \| length'` = 0 | P1 |
| KR2.4: Issue 平均首次响应时间 | 部分 issue 数周无回应 | 新 issue 72h 内首次响应 | 抽查最近 10 个 issue 的首次回复时间 | P2 |

### O3: 发布 v1.3.0，交付用户最期待的能力升级

> 差 5 个 star 就破千了。v1.3.0 是冲过这个里程碑的最好武器。

| KR | Baseline | Target | Harness（验收方法） | 优先级 |
|----|----------|--------|-------------------|-------|
| KR3.1: 实现 SimHash 去噪过滤 | 不支持 | 支持 SimHash 相似页面自动去重，解决 Spring Boot 随机值干扰 | `spray -u <target-with-random-pages> --simhash` 能正确过滤相似页面 | P1 |
| KR3.2: 蜜罐/全 200 检测机制 | 不支持 | 能识别全量返回 200 的站点并标记/过滤 | 对已知全 200 站点扫描，输出中标记 honeypot 警告 | P1 |
| KR3.3: Windows 兼容性修复 | #125 路径语法错误 | Windows 下 URL 含特殊字符不再报错 | Windows 上 `spray -u "http://example.com/path?param="` 正常运行 | P1 |
| KR3.4: 发布 v1.3.0 release | 当前最新版本 v1.2.x | v1.3.0 tag + GitHub Release + 多平台二进制 | `gh release view v1.3.0 --repo chainreactors/spray` 成功 | P0 |

### O4: 补齐文档短板，让社区能自助、能贡献

> README 4.4KB + 无 CHANGELOG + 无贡献指南 = 用户问什么都得开 issue 问。文档不是锦上添花，是降低你自己的维护成本。

| KR | Baseline | Target | Harness（验收方法） | 优先级 |
|----|----------|--------|-------------------|-------|
| KR4.1: README 扩充 | 4.4KB，只有基础用法 | ≥ 15KB，包含完整参数说明、常见场景、FAQ | `wc -c README.md` ≥ 15000 且包含 "FAQ" 章节 | P1 |
| KR4.2: 新增 CHANGELOG.md | 不存在 | 覆盖 v1.0.0 至 v1.3.0 的变更记录 | `test -f CHANGELOG.md && grep "v1.3.0" CHANGELOG.md` 成功 | P2 |
| KR4.3: 新增 CONTRIBUTING.md | 不存在 | 包含开发环境搭建、代码规范、PR 流程 | `test -f CONTRIBUTING.md && wc -l CONTRIBUTING.md` ≥ 50 行 | P2 |
| KR4.4: option.go 拆分重构 | 38KB 单文件 | 拆为 ≤ 5 个文件，每个 ≤ 10KB | `wc -c core/option*.go \| tail -1` 显示无单文件超过 10KB | P2 |

## 优先级排序与执行节奏

**业余维护现实约束下的推荐节奏：**

| 阶段 | 时间 | 聚焦 | 交付物 |
|------|------|------|--------|
| Phase 1 (Week 1-4) | 4 周 | O1 全部 + O2.1/O2.2 | 零 panic 补丁版，Bug issues 清零 |
| Phase 2 (Week 5-8) | 4 周 | O3.1/O3.2/O3.3 + O2.3 | SimHash + 蜜罐检测 + Windows 修复 |
| Phase 3 (Week 9-12) | 4 周 | O3.4 + O4 全部 | v1.3.0 发版 + 文档补齐 |

## 工作指引

当你在本项目工作时，请参考以上 OKR：
- 新的工作应与某个 Objective 对齐
- 每次交付建议标注关联的 KR
- 遇到优先级冲突时，按 O 的排序决策：O1 > O2 > O3 > O4
- 发现与 OKR 不一致的方向时，主动提出讨论
- **P0 是底线**——做不到就算这个季度失败
- **业余时间有限**——每周只挑 1-2 个 KR 推进，不要铺太开
