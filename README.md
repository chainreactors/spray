# SPRAY
名为"上一代"目录爆破工具的下一代目录爆破工具

针对path的反向代理, host的反向代理, cdn等中间件编写的高性能目录爆破工具. 

复活了了一些hashcat中的字典生成算法, 因此戏称为"上一代"目录爆破工具.
## Features
* 超强的性能, 在本地测试极限性能的场景下, 能超过ffuf与feroxbruster的性能50%以上. 实际情况受到网络的影响, 感受没有这么明确. 但在多目标下可以感受到明显的区别.
* 基于掩码的字典生成
* 基于规则的字典生成
* 动态智能过滤
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

### 基于掩码的字典生成
为了实现这个功能, 编写了一门名为mask的模板语言. 代码位于: [mask](https://github.com/chainreactors/words/tree/master/mask).

一些使用案例

`spray -u http://example.com -w "/{?l#3}/{?ud#3}"`

含义为, "/全部三位小写字母/全部三位大写字母+数字" 组成的字典.

所有的mask生成器都需要通过`{}`包裹, 并且括号内的第一个字符必须为`?`, `$`, `@`其中之一. `#`后的数组表示重复次数, 可留空, 例如`{?lu}` , 表示"全部小写字母+全部大写字母"组成的字典.

* `?` 表示普通的笛卡尔积. 例如`{?l#3}`表示生成三位小写字母的所有可能组合
* `$` 表示贪婪模式, 例如`{$l#3}`表示3位小写字母的所有可能组合+2位小写字母的所有可能组合+1位小写字母的所有可能组合
* `@` 表示关键字模式, 例如`{@year}`, 表示年份, 1970-2030年. 

掩码的定义参考了hashcat, 但是并不完全相同. 目前可用的关键字如下表:
```
"l": Lowercase,  // 26个小写字母
"u": Uppercase,  // 26个大写字母
"w": Letter,     // 52大写+小写字母
"d": Digit, // 数字0-9
"h": LowercaseHex, // 小写hex字符, 0-9 + a-f
"H": UppercaseHex, // 大写hex字符, 0-9 + A-F
"x": Hex,          // 大写+小写hex字符, 0-9 + a-f + A-F
"p": Punctuation,  // 特殊字符 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~
"P": Printable,    // 可见的ascii字符
"s": Whitespace,   // 空字符 \t\n\r\x0b\x0c
```

还支持通过数字表示命令行输入的字典序号, 例如

`spray -u http://example.com -w "/{?0u#2}/{?01}" -d word0.txt -d word1.txt`

其中`{?0u#2}`表示word0.txt的所有内容+所有大写字母笛卡尔积两次, `{?01}` 表示word0.txt + word1.txt的所有内容.

关键字目前还在不断完善中, 欢迎提供需求.

### 基于规则的字典生成
实现rule-base的字典生成器同样编写了一门模板语言, 代码在 [ruke](https://github.com/chainreactors/words/tree/master/rule)

规则语法请参考 [hashcat_rule_base](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

目前除了带M(Memorize)的规则已经全部实现. 并且去掉了hashcat的一些限制, 比如最多支持5个规则, 字符串长度不能大于10等.

如果spray的rule-base生成器与hashcat的结果不一致, 请提交issue.

这里有一些hashcat自带的规则示例, 但是因为hashcat用户生成密码字典, 因此对于目录爆破的规则还需要重新积累. 

接下来将会整理一些特别常用的规则库, 例如403bypass, java权限绕过等.


### 智能过滤

智能过滤较为复杂, 我只能简单描述一下逻辑, 具体的请看代码.

智能过滤依赖一些经验公式, 内置的经验公式为最小状态, 可以自行通过命令行进行修改.

```
WhiteStatus = []int{200}
BlackStatus = []int{400, 404, 410}
FuzzyStatus = []int{403, 500, 501, 502, 503}
WAFStatus   = []int{493, 418}
```
修改对应列表的命令行参数为`--white-status`, `--black-status`, `--fuzzy-status`, `--waf-status`.

智能过滤分为三个阶段. 

在开始之前, 会进行基础信息的收集, 会发送一个随机目录(random_baseline)与根目录(index_baseline)的请求, 不论这两个请求的返回结果是什么, 保存这两个请求的详细信息.

收集到这些信息之后, 才会开始目录爆破. 

**第一个阶段为预过滤**. 预过滤分为几个步骤:

1. 如果请求的状态码为200, 则跳过预过滤.
2. 如果请求的状态码包含BlackStatus与WAFStatus中的几个状态码, 则被过滤.
3. 过滤30x请求中, redirect的目的地与random_baseline的redirect相同, 则被过滤
4. 如果请求的状态码与random_baseline的状态码相同, 则被过滤

通过预过滤的请求会执行一次详细的信息收集, 包括被动指纹识别, hash计算等工作.

**第二阶段为普通过滤**, 分为以下几个步骤:

1. 如果是FuzzyStatus中的几个状态码, 第一次出现该状态码将会被添加到baseline列表中, 用来给之后的相同状态码当作baseline.
2. 选择对应状态码的baseline, 如果不存在则使用index_baseline
3. 根据的页面的body长度绝对值小于path与MD5值进行对比, 如果均不同则进入到4中
4. 判断页面中是否存在path, 很多情况下, 输入的path会被重新拼接到body中. 如果存在path则认为是无效数据.

如果通过了上面这几个步骤, 则进入下一步.

**第三阶段为模糊过滤**, 这一阶段还在探索中, 可能存在误判漏判, 因此提供了--fuzzy-file参数将这一阶段被过滤的结果单独输出到一个文件中做人工分析.

1. 将会对比对应baseline的simhash, 如果simhash的阈值小于5, 则认为是相似页面, 被过滤. 可通过`--simhash-threshold`参数进行修改.

目前只有这一个步骤, 还有其他模糊过滤的思路可以一起交流.

当然, 使用spray并不需要了解每一个细节, 如果输出的结果不符合预期, 可以打开`--debug`查看被过滤的原因, 如果认为存在不合理的过滤, 请提交issue.

### 自定义过滤

智能过滤可能不能满足所有的场景, 某些情况可能非常离谱, 比如404页面返回200, 并且每次body相似度都不高. 这种情况下, 就可以使用自定义过滤功能.

spray中内置了一门脚本语言 [expr](https://github.com/antonmedv/expr), 应该是市面上公开的性能最强的脚本语言了.

我们可以使用--match 定义我们需要的过滤规则, --match自定义的过滤函数将会替换掉默认的智能过滤. 也就是说, 开启了--match, 智能过滤就自动关闭了, 如果不想关闭智能过滤, 也提供了其他解决办法.

下面是一个简单的例子, 过滤掉所有的带"公益"字样的状态码为200的页面:

`spray -u http://example.com -d word1.txt --match 'current.Status == 200 && current.Body not contains "公益"'`

这里的current表示当前的请求.

spray获取的baseline也会被注册到将本语言中. index表示index_baseline, random表示random_baseline, 403bl表示如果第一个获取的状态码为403的请求. 如果之前没有403, 则所有字段为空.

按照expr的规则, 可以直接通过`.`访问各种属性, 如果是嵌套的属性, 再加一个`.` 即可. 下面是Baseline的定义.
```
type Baseline struct {
	Url          *url.URL   
	UrlString    string     
	Path         string     
	Host         string     
	Body         []byte     
	BodyLength   int        
	Header       []byte     
	Raw          []byte     
	HeaderLength int        
	RedirectURL  string     
	FrontURL     string     
	Status       int        
	Spended      int64      
	Title        string     
	Frameworks   Frameworks 
	Extracteds   Extracteds 
	ErrString    string     
	Reason       string     
	IsValid      bool       
	IsFuzzy      bool       
	*parsers.Hashes
}
```

如果匹配的结果依旧不满意, 可以加上`--filter` 对match的结果进行二次过滤, `--filter`的规则与 `--match` 一致. 

如果没有自定义`--match` , `--filter`将会对智能过滤的结果进行二次过滤.

### 输出

spray默认输出到终端的格式是human-like文本, 输出到文件的格式是json格式, 可以通过`-o`参数指定输出格式, 类似gogo的-o参数, 可以指定如`-o url,status`这样的自定义格式.

## TODO

1. [ ] fuzzyequal
2. [ ] http2
3. [ ] auto-tune, 自定调整并发数量
4. [ ] 递归