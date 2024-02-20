# SPRAY

![](https://socialify.git.ci/chainreactors/spray/image?description=1&font=Inter&forks=1&issues=1&language=1&name=1&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Light)

<p align="center">
    <a href="#features">Features</a> •
    <a href="#quickstart">QuickStart</a> •
    <a href="#make">Make</a> •
    <a href="https://chainreactors.github.io/wiki/spray/">Wiki</a>
</p>

## Features

* 超强的性能, 在本地测试极限性能的场景下, 能超过ffuf与feroxbruster的性能50%以上. 实际情况受到网络的影响, 感受没有这么明确. 但在多目标下可以感受到明显的区别.
* 基于掩码的字典生成
* 基于规则的字典生成
* 动态智能过滤
* 全量[gogo](https://github.com/chainreactors/gogo)的指纹识别, 全量的[fingerprinthub](https://github.com/0x727/FingerprintHub)指纹
* 自定义信息提取, 如ip,js, title, hash以及自定义的正则表达式
* 自定义过滤策略
* 自定义输出格式与内容
* *nix的命令行设计, 轻松与其他工具联动
* 多角度的自动被ban,被waf判断
* 断点续传

## QuickStart

[**Document**](https://chainreactors.github.io/wiki/spray/start)

基本使用, 从字典中读取目录进行爆破

`spray -u http://example.com -d wordlist1.txt -d wordlist2.txt`

通过掩码生成字典进行爆破

`spray -u http://example.com -w "/aaa/bbb{?l#4}/ccc"`

通过规则生成字典爆破. 规则文件格式参考hashcat的字典生成规则

`spray -u http://example.com -r rule.txt -d 1.txt`

批量爆破

`spray -l url.txt -r rule.txt -d 1.txt`

断点续传

`spray --resume stat.json`

被动url收集

参见: https://github.com/chainreactors/urlfounder

## Wiki

详细用法请见[wiki](https://chainreactors.github.io/wiki/spray/)

https://chainreactors.github.io/wiki/spray/

## Make

```
git clone --recurse-submodules https://github.com/chainreactors/spray

cd spray

go mod tidy

go generate

go build .  
```

## Similar or related works

* [ffuf](https://github.com/ffuf/ffuf) 一款优秀的http fuzz工具, 与spray的功能有一定重合但并不完全相同
* [feroxbuster](https://github.com/epi052/feroxbuster) 在编写spray之前我最常使用的目录爆破工具, 但因为批量扫描与过滤配置不便的原因选择自行编写
* [dirsearch](https://github.com/maurosoria/dirsearch) 较早的目录爆破工具, 参考了部分字典生成与配色
* [httpx](https://github.com/projectdiscovery/httpx) http信息收集功能, 参考了通过脚本语言编写任意过滤条件的功能
* [gobuster](https://github.com/OJ/gobuster) 一款统一是go编写的爆破工具, 但不仅限于目录爆破

## TODO

1. [x] 模糊对比
2. [x] 断点续传
3. [x] 简易爬虫
4. [ ] 支持http2
5. [ ] auto-tune, 自动调整并发数量
6. [x] 可自定义的递归配置
7. [x] 参考[feroxbuster](https://github.com/epi052/feroxbuster)的`--collect-backups`, 自动爆破有效目录的备份
8. [ ] 支持socks/http代理, 不建议使用, 优先级较低. 代理的keep-alive会带来严重的性能下降
9. [ ] 云函数化, chainreactors工具链的通用分布式解决方案.

## Thanks

* [fuzzuli](https://github.com/musana/fuzzuli) 提供了一个备份文件字典生成思路
* [fingerprinthub](https://github.com/0x727/FingerprintHub) 作为指纹库的补充