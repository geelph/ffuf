package ffuf

import (
	"context"
)

type Config struct {
	AuditLog                  string                `json:"auditlog"`                   // 审计日志文件路径，用于记录请求和响应的详细信息
	AutoCalibration           bool                  `json:"autocalibration"`            // 是否启用自动校准功能
	AutoCalibrationKeyword    string                `json:"autocalibration_keyword"`    // 自动校准过程中使用的关键词
	AutoCalibrationPerHost    bool                  `json:"autocalibration_perhost"`    // 是否为每个主机单独执行自动校准
	AutoCalibrationStrategies []string              `json:"autocalibration_strategies"` // 自动校准策略列表
	AutoCalibrationStrings    []string              `json:"autocalibration_strings"`    // 自动校准中使用的一组字符串
	Cancel                    context.CancelFunc    `json:"-"`                          // 上下文取消函数，用于终止正在进行的操作
	Colors                    bool                  `json:"colors"`                     // 是否在输出中启用颜色显示
	CommandKeywords           []string              `json:"-"`                          // 命令关键字列表（不参与 JSON 序列化）
	CommandLine               string                `json:"cmdline"`                    // 记录完整的命令行参数
	ConfigFile                string                `json:"configfile"`                 // 配置文件路径
	Context                   context.Context       `json:"-"`                          // 上下文对象，用于控制 goroutine 的生命周期
	Data                      string                `json:"postdata"`                   // POST 请求的数据内容
	Debuglog                  string                `json:"debuglog"`                   // 调试日志文件路径
	Delay                     optRange              `json:"delay"`                      // 请求之间的延迟时间范围
	DirSearchCompat           bool                  `json:"dirsearch_compatibility"`    // 启用与 dirsearch 工具兼容的模式
	Encoders                  []string              `json:"encoders"`                   // 编码器名称列表
	Extensions                []string              `json:"extensions"`                 // 文件扩展名列表
	FilterMode                string                `json:"fmode"`                      // 过滤器工作模式
	FollowRedirects           bool                  `json:"follow_redirects"`           // 是否跟随 HTTP 重定向
	Headers                   map[string]string     `json:"headers"`                    // HTTP 请求头映射表
	IgnoreBody                bool                  `json:"ignorebody"`                 // 忽略响应体内容
	IgnoreWordlistComments    bool                  `json:"ignore_wordlist_comments"`   // 在词表处理中忽略注释行
	InputMode                 string                `json:"inputmode"`                  // 输入源模式
	InputNum                  int                   `json:"cmd_inputnum"`               // 控制命令输入的数量
	InputProviders            []InputProviderConfig `json:"inputproviders"`             // 输入提供者配置列表
	InputShell                string                `json:"inputshell"`                 // 输入 shell 命令
	Json                      bool                  `json:"json"`                       // 输出格式是否为 JSON 格式
	MatcherManager            MatcherManager        `json:"matchers"`                   // 匹配管理器实例
	MatcherMode               string                `json:"mmode"`                      // 匹配器的工作模式
	MaxTime                   int                   `json:"maxtime"`                    // 最大运行总时间（秒）
	MaxTimeJob                int                   `json:"maxtime_job"`                // 单个任务的最大运行时间（秒）
	Method                    string                `json:"method"`                     // HTTP 请求方法类型，默认为 GET
	Noninteractive            bool                  `json:"noninteractive"`             // 禁用交互式操作
	OutputDirectory           string                `json:"outputdirectory"`            // 输出目录路径
	OutputFile                string                `json:"outputfile"`                 // 输出文件路径
	OutputFormat              string                `json:"outputformat"`               // 输出格式类型
	OutputSkipEmptyFile       bool                  `json:"OutputSkipEmptyFile"`        // 当输出为空时不创建空文件
	ProgressFrequency         int                   `json:"-"`                          // 控制进度更新频率（不参与 JSON 序列化）
	ProxyURL                  string                `json:"proxyurl"`                   // HTTP 代理服务器地址
	Quiet                     bool                  `json:"quiet"`                      // 安静模式，减少输出信息
	Rate                      int64                 `json:"rate"`                       // 请求速率限制（每秒请求数）
	Raw                       bool                  `json:"raw"`                        // 使用原始请求模式
	Recursion                 bool                  `json:"recursion"`                  // 是否启用递归扫描
	RecursionDepth            int                   `json:"recursion_depth"`            // 递归扫描深度
	RecursionStrategy         string                `json:"recursion_strategy"`         // 递归扫描策略
	ReplayProxyURL            string                `json:"replayproxyurl"`             // 回放代理服务器地址
	RequestFile               string                `json:"requestfile"`                // 请求模板文件路径
	RequestProto              string                `json:"requestproto"`               // 使用的 HTTP 协议版本
	ScraperFile               string                `json:"scraperfile"`                // 数据抓取规则文件路径
	Scrapers                  string                `json:"scrapers"`                   // 抓取规则字符串
	SNI                       string                `json:"sni"`                        // TLS 握手中使用的服务器名称指示
	StopOn403                 bool                  `json:"stop_403"`                   // 收到 403 响应时停止扫描
	StopOnAll                 bool                  `json:"stop_all"`                   // 收到任意错误响应时停止扫描
	StopOnErrors              bool                  `json:"stop_errors"`                // 收到错误响应时停止扫描
	Threads                   int                   `json:"threads"`                    // 并发线程数量
	Timeout                   int                   `json:"timeout"`                    // 请求超时时间（秒）
	Url                       string                `json:"url"`                        // 目标 URL 地址
	Verbose                   bool                  `json:"verbose"`                    // 显示详细调试信息
	Wordlists                 []string              `json:"wordlists"`                  // 字典文件路径列表
	Http2                     bool                  `json:"http2"`                      // 是否启用 HTTP/2 协议支持
	ClientCert                string                `json:"client-cert"`                // 客户端证书文件路径
	ClientKey                 string                `json:"client-key"`                 // 客户端私钥文件路径
}

// InputProviderConfig 定义了输入提供者的配置结构。
// 它包含了配置输入数据如何被处理和编码所需的字段。
type InputProviderConfig struct {
	Name     string `json:"name"`     // 输入提供者的名称
	Keyword  string `json:"keyword"`  // 用于标识此提供者的关键词
	Value    string `json:"value"`    // 实际的值或数据源
	Encoders string `json:"encoders"` // 要应用的编码器列表，以逗号分隔
	Template string `json:"template"` // 用于sniper模式的模板字符串（通常是"§"）
}

// NewConfig 创建并初始化一个新的 Config 实例，设置默认值。
// 接受上下文和取消函数参数，用于请求取消和超时控制。
//
// 参数:
//
//	ctx:    用于管理请求生命周期和超时的上下文
//	cancel: 用于停止正在进行操作的取消函数
//
// 返回值:
//
//	Config: 具有默认设置的新配置实例
func NewConfig(ctx context.Context, cancel context.CancelFunc) Config {
	var conf Config

	// 初始化默认配置值
	conf.AutoCalibrationKeyword = "FUZZ"               // 自动校准关键词默认为"FUZZ"
	conf.AutoCalibrationStrategies = []string{"basic"} // 自动校准策略默认为"basic"
	conf.AutoCalibrationStrings = make([]string, 0)    // 自动校准字符串列表初始化为空
	conf.CommandKeywords = make([]string, 0)           // 命令关键词列表初始化为空
	conf.Context = ctx                                 // 设置上下文
	conf.Cancel = cancel                               // 设置取消函数
	conf.Data = ""                                     // POST数据默认为空
	conf.Debuglog = ""                                 // 调试日志路径默认为空

	// 设置默认延迟范围（无延迟）
	conf.Delay = optRange{0, 0, false, false}

	// 兼容性和编码设置
	conf.DirSearchCompat = false        // dirsearch兼容模式默认关闭
	conf.Encoders = make([]string, 0)   // 编码器列表初始化为空
	conf.Extensions = make([]string, 0) // 扩展名列表初始化为空

	// 过滤器和匹配器配置
	conf.FilterMode = "or"       // 过滤器模式默认为"or"
	conf.FollowRedirects = false // 跟随重定向默认关闭

	// HTTP头和输入处理
	conf.Headers = make(map[string]string)               // HTTP头映射初始化为空
	conf.IgnoreWordlistComments = false                  // 忽略词表注释默认关闭
	conf.InputMode = "clusterbomb"                       // 输入模式默认为"clusterbomb"
	conf.InputNum = 0                                    // 输入数量默认为0
	conf.InputShell = ""                                 // 输入shell命令默认为空
	conf.InputProviders = make([]InputProviderConfig, 0) // 输入提供者配置列表初始化为空

	// 输出和格式化选项
	conf.Json = false       // JSON输出格式默认关闭
	conf.MatcherMode = "or" // 匹配器模式默认为"or"

	// 时间和速率限制
	conf.MaxTime = 0    // 最大运行时间默认为0（无限制）
	conf.MaxTimeJob = 0 // 单任务最大时间默认为0（无限制）
	conf.Method = "GET" // HTTP方法默认为"GET"

	// 用户界面和交互设置
	conf.Noninteractive = false  // 非交互模式默认关闭
	conf.ProgressFrequency = 125 // 进度更新频率默认为125ms
	conf.ProxyURL = ""           // 代理URL默认为空
	conf.Quiet = false           // 安静模式默认关闭
	conf.Rate = 0                // 请求速率默认为0（无限制）

	// 请求和协议设置
	conf.Raw = false                   // 原始请求模式默认关闭
	conf.Recursion = false             // 递归扫描默认关闭
	conf.RecursionDepth = 0            // 递归深度默认为0
	conf.RecursionStrategy = "default" // 递归策略默认为"default"
	conf.RequestFile = ""              // 请求文件路径默认为空
	conf.RequestProto = "https"        // 请求协议默认为"https"
	conf.SNI = ""                      // SNI默认为空

	// 抓取器配置
	conf.ScraperFile = "" // 抓取器文件路径默认为空
	conf.Scrapers = "all" // 抓取器默认为"all"

	// 错误处理和停止条件
	conf.StopOn403 = false    // 收到403时停止默认关闭
	conf.StopOnAll = false    // 收到所有错误时停止默认关闭
	conf.StopOnErrors = false // 收到错误时停止默认关闭
	conf.Timeout = 10         // 超时时间默认为10秒

	// 目标和详细程度设置
	conf.Url = ""               // URL默认为空
	conf.Verbose = false        // 详细模式默认关闭
	conf.Wordlists = []string{} // 词表列表初始化为空

	// HTTP/2支持
	conf.Http2 = false // HTTP/2支持默认关闭

	return conf
}

// SetContext 为 Config 设置上下文和取消函数。
// 它将提供的上下文和取消函数存储在 Config 结构体中，
// 可以用于管理操作的生命周期和取消操作。
//
// 参数:
//
//	ctx: 要存储在 Config 中的上下文
//	cancel: 与上下文关联的取消函数
func (c *Config) SetContext(ctx context.Context, cancel context.CancelFunc) {
	c.Context = ctx
	c.Cancel = cancel
}
