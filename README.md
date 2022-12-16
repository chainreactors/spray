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

`spray --resume-from stat.json`
### 基于掩码的字典生成
为了实现这个功能, 编写了一门名为mask的模板语言. 代码位于: [mask](https://github.com/chainreactors/words/tree/master/mask).

一些使用案例

`spray -u http://example.com -w "/{?l#3}/{?ud#3}"`

含义为, "/全部三位小写字母/全部三位大写字母+数字" 组成的字典.

所有的mask生成器都需要通过`{}`包裹, 并且括号内的第一个字符必须为`?`, `$`, `@`其中之一. `#`后的数字表示重复次数, 可留空, 例如`{?lu}` , 表示"全部小写字母+全部大写字母"组成的字典.

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
实现rule-base的字典生成器同样编写了一门模板语言, 代码在 [rule](https://github.com/chainreactors/words/tree/master/rule)

规则语法请参考 [hashcat_rule_base](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

目前除了带M(Memorize)的规则已经全部实现. 并且去掉了hashcat的一些限制, 比如最多支持5个规则, 字符串长度不能大于10等.

如果spray的rule-base生成器与hashcat的结果不一致, 请提交issue.

这里有一些hashcat自带的规则示例, 但是因为hashcat用户生成密码字典, 因此对于目录爆破的规则还需要重新积累. 

接下来将会整理一些特别常用的规则库, 例如403bypass, java权限绕过等.

简单使用

`spray -u http://example.com -d word.txt -r rule.txt -r rule2.txt`

通用过滤规则, 过滤规则目前与hashcat一致

`spray -u http://example.com -d word.txt --rule-filter ">15"`

这行命令的意思是, 指定字典, 并过滤掉长度大于15的字典.

因为hashcat是设计用来针对密码的, 后续将会针对http fuzz的场景添加一些spray特有的过滤规则.
### 使用函数装饰字典
内置了一些函数可以对字典进行装饰. 目前支持的如下:

mask生成阶段的函数
1. `--suffix` 在字典后面添加后缀, 可添加多个, 与原有的字典组成笛卡尔积
2. `--prefix` 在字典前面添加前缀, 可添加多个, 与原有的字典组成笛卡尔积
3. `-e`/`--extension` 添加拓展名, 逗号分割

rule阶段的函数
1. `-L`/`--lowercase` 将字典中的所有字母转换为小写
2. `-U`/`--uppercase` 将字典中的所有字母转换为大写
3. `--replace` 替换字典中的字符, 例如`--replace aaa=bbb` 将字典中的a替换为b, 可以添加多个`--replace`
4. `--remove-extension` 删除字典中的文件扩展名, 逗号分割
5. `--exclude-extension` 排除字典中的文件扩展名, 逗号分割

### 字典生成器的优先级

将`-w`与`-d`解析成mask表达式

--> 给mask表达式添加上`suffix`与`prefix` 关键字

--> mask字典生成器 

--> rule字典生成器 

--> rule过滤器 

--> 函数装饰器 

### Baseline

baseline既是spray的输出的结构体, 也是实现各种过滤策略与高级功能的基石.

baseline的定义如下:
```
type Baseline struct {
	Url          *url.URL   `json:"-"`
	UrlString    string     `json:"url"`
	Path         string     `json:"path"`
	Host         string     `json:"host"`
	Body         []byte     `json:"-"`
	BodyLength   int        `json:"body_length"`
	Header       []byte     `json:"-"`
	Raw          []byte     `json:"-"`
	HeaderLength int        `json:"header_length"`
	RedirectURL  string     `json:"redirect_url,omitempty"`
	FrontURL     string     `json:"front_url,omitempty"`
	Status       int        `json:"status"`
	Spended      int64      `json:"spend"` // 耗时, 毫秒
	Title        string     `json:"title"`
	Frameworks   Frameworks `json:"frameworks"`
	Extracteds   Extracteds `json:"extracts"`
	ErrString    string     `json:"error"`
	Reason       string     `json:"reason"`
	IsValid      bool       `json:"valid"`
	IsFuzzy      bool       `json:"fuzzy"`
	RecuDepth    int        `json:"-"`
	Recu         bool       `json:"-"`
	*parsers.Hashes
}
```

(结构体中的hashes,frameworks,extracteds的结构与gogo中的一致, 作为高级用法使用, 可以直接翻代码, 或者后续将会在高级使用的文档中介绍)

每接收到一个目标, 创建任务并初始化, 在初始化阶段, 实际上会做两件事. 首先访问index页面, 查看连通性以及获取index的baseline.

然后再生成一个随机目录, 获取随机目录的baseline.

初始化完成之后, 将会保存这两个baseline, 这两个baseline就是后续一切智能过滤与高级过滤的基石.

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

spray中使用了 [expr](https://github.com/antonmedv/expr) 作为表达式语言, 应该是市面上公开的性能最强的脚本语言了.

expr的语法介绍: https://github.com/antonmedv/expr/blob/master/docs/Language-Definition.md

expr语法和xray/github action中差不多, spray中绝大多数情况也用不到高级功能. 只需要了解最简单的等于/包含之类判断即可.

我们可以使用--match 定义我们需要的过滤规则, --match自定义的过滤函数将会替换掉默认的智能过滤. 也就是说, 开启了--match, 智能过滤就自动关闭了, 如果不想关闭智能过滤, 也提供了其他解决办法.

下面是一个简单的例子, 假设某个网站所有的404页面都指向公益页面, 我们想去掉所有的带"公益"字样的页面:

`spray -u http://example.com -d word1.txt --match 'current.Body not contains "公益"'`

这里的current关键字表示当前的请求的baseline. `current.Body`即为baseline结构体中的Body字段, baseline结构体可以见上文.

spray获取的baseline也会被注册到将本语言中. index表示index_baseline, random表示random_baseline, 403bl表示如果第一个获取的状态码为403的请求. 如果之前没有403, 则所有字段为空.

按照expr的规则, 可以直接通过`.`访问各种属性, 如果是嵌套的属性, 再加一个`.` 即可. 下面是Baseline的定义.

如果匹配的结果依旧不满意, 可以加上`--filter` 对match的结果进行二次过滤, `--filter`的规则与 `--match` 一致. 

如果没有自定义`--match` , `--filter`将会对智能过滤的结果进行二次过滤.

### 输出

spray默认输出到终端的格式是human-like文本, 输出到文件的格式是json格式, 可以通过`-o`参数指定输出格式, 类似gogo的-o参数, 可以指定如`-o url,status`这样的自定义格式.

## 高级用法

### 手动配置过滤器

假设一个功能为api的站点， 他通过全局的错误处理将返回值统一改成200/405.

在spray中, 200是白名单状态码, 会跳过precompare, 直接到智能过滤的第二步, 开始内容的匹配. 如果内存中存在例如时间戳之类的随机数, 还会到第三步模糊过滤.

而405状态码则输出没有任何配置的状态码, 返回结果大概率会能到模糊过滤中, 如果405与200差异较小. 这种情况下就需要手动修改过滤规则了. 

spray中修改过滤规则有很多中方式, 以这个例子进行简单介绍不同方式之间的差异.

**方法1: 添加参数`--black-status 405`**

这种方式较为暴力, 会在precompare阶段直接过滤掉, 跳过后续的阶段.

建议明确知道405状态码为无效页面的情况下使用. 果405页面的依旧有可能存在有价值的信息, 则不推荐使用这种方式.

**方法2: 添加参数`--fuzzy-status 405`**

405配置到fuzzy-status状态码列表中, 每次遇到405请求, 都会与405baseline进行对比. 

这种方法是比较推荐的, 它只会微调智能过滤的逻辑, 随机目录的405状态码将会加入到基线中, 如果其他请求也遇到了几乎相同的405页面, 则可以认为是无效数据过滤掉.

可以保留智能过滤的全部功能, 并且不会有额外的性能损耗. 

**方法3: 使用表达式匹配`--match current.Status != 405`**

这个表达式表示, 所有状态码不等于405的页面都会输出. 有些类似方法1中的black-status, 但是方法1并不会对其他智能过滤的规则做出修改.

--match将会重载默认的智能过滤的全部逻辑. 也就是说, 智能过滤的123阶段都会跳过, 取而代之的是这个表达式.

表达式的性能并不好, 并且配置起来也较为麻烦, 不推荐使用.

**方法4: 使用表达式过滤`--filter current.Status == 405`**

filter一般来说是比match的更高优先级的选择. 

--filter与--match的区别在于, --filter作用于compare(包括智能过滤与match表达式过滤)的下一阶段. 通过compare结果将会由--filter进行二次过滤.

意味着, 如果仅设置了--filter, 那么智能过滤依旧生效, 并且可以过滤掉状态码为405的请求.

### 断点续传

spray支持断点续传, 可以通过`--resume-from`参数指定断点文件. 通过断点文件中记录的数据恢复进度.

为了更好的支持断点续传, spray监听了ctrl+c信号, 如果通过ctrl+c取消任务, 所有任务(包括已完成与没完成)的数据都会保存到stat结尾的文件中.

所以建议非必要情况不要使用kill -9 结束spray进程.

另外, 如果使用`--resume-from`依旧没有完成任务, 只要是正常的退出信号, 都会重写当前的stat文件, 以更新进度到当前扫描, 随时可以再次读取stat文件继续扫描任务.

断点续传支持比命令行更自由的字典配置. 每个任务都可以拥有独立的-w/-r/-d配置. 因此某些特殊情况下要进行批量操作, 可以通过脚本去构造对应的stat文件, 实现更加自由的任务配置.

### 递归
spray并不鼓励使用递归, 因为spray的定位是批量从反代/cdn中发现隐形资产. 不管是因为批量, 还是因为反代/cdn, 绝大多数的情况都用不到递归.

但为了兼容某些极为罕见的情况, spray依旧保留了递归的功能. 

默认递归为关闭状态, 可以使用`--depth 2`选择递归深度开启递归模式. 

默认的递归规则为`current.IsDir()`, 即所有的目录(结尾为/的结果)都会被递归.

也可以通过--recursive手动选择递归规则. 例如`--recursive current.IsDir() && current.Status == 403`表示, 递归所有状态码为403的有效目录.
## TODO

1. [x] fuzzyequal
2. [x] 断点续传
3. [ ] 简易爬虫
4. [ ] 支持http2
5. [ ] auto-tune, 自动调整并发数量
6. [x] 可自定义的递归配置