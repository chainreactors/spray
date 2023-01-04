# SPRAY
名为"上一代"目录爆破工具的下一代目录爆破工具

针对path的反向代理, host的反向代理, cdn等中间件编写的高性能目录爆破工具. 

复活了一些hashcat中的字典生成算法, 因此戏称为"上一代"目录爆破工具.
## Features
* 超强的性能, 在本地测试极限性能的场景下, 能超过ffuf与feroxbruster的性能50%以上. 实际情况受到网络的影响, 感受没有这么明确. 但在多目标下可以感受到明显的区别.
* 基于掩码的字典生成
* 基于规则的字典生成
* 动态智能过滤
* 全量gogo的指纹识别
* 自定义信息提取, 如ip,js, title, hash以及自定义的正则表达式
* 自定义过滤策略
* 自定义输出格式与内容
* *nix的命令行设计, 轻松与其他工具联动
* 多角度的自动被ban,被waf判断
* 断点续传

## Usage

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

## Wiki

https://chainreactors.github.io/wiki/spray/

## Make

```
git clone https://github.com/chainreactors/spray
cd spray
git clone https://github.com/chainreactors/gogo-templates templates
# 这里没用使用类似gogo的子模块的方式, 因为spray仅依赖其中的http指纹

go generate

go build .  
```

## TODO

1. [x] 模糊对比
2. [x] 断点续传
3. [x] 简易爬虫
4. [ ] 支持http2
5. [ ] auto-tune, 自动调整并发数量
6. [x] 可自定义的递归配置