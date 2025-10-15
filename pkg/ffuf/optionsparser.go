package ffuf

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	//"github.com/pelletier/go-toml"
	"github.com/pelletier/go-toml/v2"
)

// ConfigOptions 定义了配置选项的结构体，包含多个子选项用于控制程序行为。
type ConfigOptions struct {
	Filter  FilterOptions  `json:"filters"`  // 过滤器相关配置
	General GeneralOptions `json:"general"`  // 通用配置
	HTTP    HTTPOptions    `json:"http"`     // HTTP 请求相关配置
	Input   InputOptions   `json:"input"`    // 输入相关配置
	Matcher MatcherOptions `json:"matchers"` // 匹配器相关配置
	Output  OutputOptions  `json:"output"`   // 输出相关配置
}

// HTTPOptions 定义了与 HTTP 请求相关的配置选项。
type HTTPOptions struct {
	Cookies           []string `json:"-"`                  // Cookies 会被附加到 Headers 中
	Data              string   `json:"data"`               // 请求体数据
	FollowRedirects   bool     `json:"follow_redirects"`   // 是否跟随重定向
	Headers           []string `json:"headers"`            // 自定义请求头
	IgnoreBody        bool     `json:"ignore_body"`        // 是否忽略响应体
	Method            string   `json:"method"`             // HTTP 请求方法
	ProxyURL          string   `json:"proxy_url"`          // 代理地址
	Raw               bool     `json:"raw"`                // 是否使用原始请求
	Recursion         bool     `json:"recursion"`          // 是否启用递归扫描
	RecursionDepth    int      `json:"recursion_depth"`    // 递归深度限制
	RecursionStrategy string   `json:"recursion_strategy"` // 递归策略
	ReplayProxyURL    string   `json:"replay_proxy_url"`   // 重放请求使用的代理
	SNI               string   `json:"sni"`                // TLS SNI 设置
	Timeout           int      `json:"timeout"`            // 请求超时时间（秒）
	URL               string   `json:"url"`                // 目标 URL
	Http2             bool     `json:"http2"`              // 是否启用 HTTP/2
	ClientCert        string   `json:"client-cert"`        // 客户端证书路径
	ClientKey         string   `json:"client-key"`         // 客户端私钥路径
}

// GeneralOptions 定义了通用配置选项。
type GeneralOptions struct {
	AutoCalibration           bool     `json:"autocalibration"`            // 是否启用自动校准
	AutoCalibrationKeyword    string   `json:"autocalibration_keyword"`    // 自动校准关键字
	AutoCalibrationPerHost    bool     `json:"autocalibration_per_host"`   // 是否为每个主机单独校准
	AutoCalibrationStrategies []string `json:"autocalibration_strategies"` // 自动校准策略列表
	AutoCalibrationStrings    []string `json:"autocalibration_strings"`    // 自动校准字符串列表
	Colors                    bool     `json:"colors"`                     // 是否启用颜色输出
	ConfigFile                string   `toml:"-" json:"config_file"`       // 配置文件路径（不参与 toml 序列化）
	Delay                     string   `json:"delay"`                      // 请求延迟设置
	Json                      bool     `json:"json"`                       // 是否以 JSON 格式输出
	MaxTime                   int      `json:"maxtime"`                    // 最大运行时间（秒）
	MaxTimeJob                int      `json:"maxtime_job"`                // 单个任务最大运行时间（秒）
	Noninteractive            bool     `json:"noninteractive"`             // 是否启用非交互模式
	Quiet                     bool     `json:"quiet"`                      // 是否静默模式
	Rate                      int      `json:"rate"`                       // 每秒请求数限制
	ScraperFile               string   `json:"scraperfile"`                // 爬虫文件路径
	Scrapers                  string   `json:"scrapers"`                   // 爬虫规则
	Searchhash                string   `json:"-"`                          // 搜索哈希值（不参与 JSON 序列化）
	ShowVersion               bool     `toml:"-" json:"-"`                 // 是否显示版本信息（不参与序列化）
	StopOn403                 bool     `json:"stop_on_403"`                // 遇到 403 响应时是否停止
	StopOnAll                 bool     `json:"stop_on_all"`                // 遇到任意错误时是否停止
	StopOnErrors              bool     `json:"stop_on_errors"`             // 遇到错误时是否停止
	Threads                   int      `json:"threads"`                    // 并发线程数
	Verbose                   bool     `json:"verbose"`                    // 是否启用详细输出
}

// InputOptions 定义了输入相关的配置选项。
type InputOptions struct {
	DirSearchCompat        bool     `json:"dirsearch_compat"`         // 是否兼容 dirsearch 格式
	Encoders               []string `json:"encoders"`                 // 编码器列表
	Extensions             string   `json:"extensions"`               // 文件扩展名列表
	IgnoreWordlistComments bool     `json:"ignore_wordlist_comments"` // 是否忽略词表中的注释
	InputMode              string   `json:"input_mode"`               // 输入模式
	InputNum               int      `json:"input_num"`                // 输入数量
	InputShell             string   `json:"input_shell"`              // 输入 shell 命令
	Inputcommands          []string `json:"input_commands"`           // 输入命令列表
	Request                string   `json:"request_file"`             // 请求模板文件路径
	RequestProto           string   `json:"request_proto"`            // 请求协议
	Wordlists              []string `json:"wordlists"`                // 词表文件路径列表
}

// OutputOptions 定义了输出相关的配置选项。
type OutputOptions struct {
	AuditLog            string `json:"audit_log"`         // 审计日志文件路径
	DebugLog            string `json:"debug_log"`         // 调试日志文件路径
	OutputDirectory     string `json:"output_directory"`  // 输出目录路径
	OutputFile          string `json:"output_file"`       // 输出文件路径
	OutputFormat        string `json:"output_format"`     // 输出格式
	OutputSkipEmptyFile bool   `json:"output_skip_empty"` // 是否跳过空文件输出
}

// FilterOptions 定义了过滤器相关的配置选项。
type FilterOptions struct {
	Mode   string `json:"mode"`   // 过滤模式
	Lines  string `json:"lines"`  // 行数过滤条件
	Regexp string `json:"regexp"` // 正则表达式过滤条件
	Size   string `json:"size"`   // 响应大小过滤条件
	Status string `json:"status"` // 状态码过滤条件
	Time   string `json:"time"`   // 响应时间过滤条件
	Words  string `json:"words"`  // 单词数过滤条件
}

// MatcherOptions 定义了匹配器相关的配置选项。
type MatcherOptions struct {
	Mode   string `json:"mode"`   // 匹配模式
	Lines  string `json:"lines"`  // 行数匹配条件
	Regexp string `json:"regexp"` // 正则表达式匹配条件
	Size   string `json:"size"`   // 响应大小匹配条件
	Status string `json:"status"` // 状态码匹配条件
	Time   string `json:"time"`   // 响应时间匹配条件
	Words  string `json:"words"`  // 单词数匹配条件
}

// NewConfigOptions 返回一个新创建的 ConfigOptions 结构体，其中包含默认值
//
// 返回值:
//   - *ConfigOptions: 指向一个已使用默认配置值初始化的 ConfigOptions 实例的指针
func NewConfigOptions() *ConfigOptions {
	c := &ConfigOptions{}

	// 使用默认值初始化过滤器部分
	c.Filter.Mode = "or" // 过滤器模式默认为 "or"
	c.Filter.Lines = ""  // 行数过滤条件默认为空
	c.Filter.Regexp = "" // 正则表达式过滤条件默认为空
	c.Filter.Size = ""   // 响应大小过滤条件默认为空
	c.Filter.Status = "" // 状态码过滤条件默认为空
	c.Filter.Time = ""   // 响应时间过滤条件默认为空
	c.Filter.Words = ""  // 单词数过滤条件默认为空

	// 使用默认值初始化通用设置部分
	c.General.AutoCalibration = false                       // 自动校准默认关闭
	c.General.AutoCalibrationKeyword = "FUZZ"               // 自动校准关键字默认为 "FUZZ"
	c.General.AutoCalibrationStrategies = []string{"basic"} // 自动校准策略默认为 ["basic"]
	c.General.Colors = false                                // 颜色输出默认关闭
	c.General.Delay = ""                                    // 请求延迟默认为空
	c.General.Json = false                                  // JSON 输出默认关闭
	c.General.MaxTime = 0                                   // 最大运行时间默认为 0（无限制）
	c.General.MaxTimeJob = 0                                // 单个任务最大运行时间默认为 0（无限制）
	c.General.Noninteractive = false                        // 非交互模式默认关闭
	c.General.Quiet = false                                 // 静默模式默认关闭
	c.General.Rate = 0                                      // 请求速率限制默认为 0（无限制）
	c.General.Searchhash = ""                               // 搜索哈希值默认为空
	c.General.ScraperFile = ""                              // 爬虫文件路径默认为空
	c.General.Scrapers = "all"                              // 爬虫规则默认为 "all"
	c.General.ShowVersion = false                           // 显示版本信息默认关闭
	c.General.StopOn403 = false                             // 遇到 403 响应时停止默认关闭
	c.General.StopOnAll = false                             // 遇到所有错误时停止默认关闭
	c.General.StopOnErrors = false                          // 遇到错误时停止默认关闭
	c.General.Threads = 40                                  // 并发线程数默认为 40
	c.General.Verbose = false                               // 详细输出默认关闭

	// 使用默认值初始化 HTTP 设置部分
	c.HTTP.Data = ""                     // 请求体数据默认为空
	c.HTTP.FollowRedirects = false       // 跟随重定向默认关闭
	c.HTTP.IgnoreBody = false            // 忽略响应体默认关闭
	c.HTTP.Method = ""                   // HTTP 方法默认为空
	c.HTTP.ProxyURL = ""                 // 代理地址默认为空
	c.HTTP.Raw = false                   // 原始请求模式默认关闭
	c.HTTP.Recursion = false             // 递归扫描默认关闭
	c.HTTP.RecursionDepth = 0            // 递归深度默认为 0（无限制）
	c.HTTP.RecursionStrategy = "default" // 递归策略默认为 "default"
	c.HTTP.ReplayProxyURL = ""           // 重放请求代理默认为空
	c.HTTP.Timeout = 10                  // 请求超时时间默认为 10 秒
	c.HTTP.SNI = ""                      // TLS SNI 默认为空
	c.HTTP.URL = ""                      // 目标 URL 默认为空
	c.HTTP.Http2 = false                 // HTTP/2 默认关闭

	// 使用默认值初始化输入设置部分
	c.Input.DirSearchCompat = false        // DirSearch 兼容模式默认关闭
	c.Input.Encoders = []string{}          // 编码器列表默认为空
	c.Input.Extensions = ""                // 文件扩展名列表默认为空
	c.Input.IgnoreWordlistComments = false // 忽略词表注释默认关闭
	c.Input.InputMode = "clusterbomb"      // 输入模式默认为 "clusterbomb"
	c.Input.InputNum = 100                 // 输入数量默认为 100
	c.Input.Request = ""                   // 请求模板文件路径默认为空
	c.Input.RequestProto = "https"         // 请求协议默认为 "https"

	// 使用默认值初始化匹配器部分
	c.Matcher.Mode = "or"                                    // 匹配器模式默认为 "or"
	c.Matcher.Lines = ""                                     // 行数匹配条件默认为空
	c.Matcher.Regexp = ""                                    // 正则表达式匹配条件默认为空
	c.Matcher.Size = ""                                      // 响应大小匹配条件默认为空
	c.Matcher.Status = "200-299,301,302,307,401,403,405,500" // 状态码匹配条件默认为常见成功和重定向状态码
	c.Matcher.Time = ""                                      // 响应时间匹配条件默认为空
	c.Matcher.Words = ""                                     // 单词数匹配条件默认为空

	// 使用默认值初始化输出设置部分
	c.Output.AuditLog = ""               // 审计日志文件路径默认为空
	c.Output.DebugLog = ""               // 调试日志文件路径默认为空
	c.Output.OutputDirectory = ""        // 输出目录路径默认为空
	c.Output.OutputFile = ""             // 输出文件路径默认为空
	c.Output.OutputFormat = "json"       // 输出格式默认为 "json"
	c.Output.OutputSkipEmptyFile = false // 跳过空文件输出默认关闭

	return c
}

// ConfigFromOptions parses the values in ConfigOptions struct, ensures that the values are sane,
// and creates a Config struct out of them.
// ConfigFromOptions 根据解析后的命令行选项、上下文和取消函数创建一个配置对象。
// 它会验证输入参数的有效性，并根据需要初始化各种配置项（如请求方式、URL、Headers、代理等），
// 同时处理输入源（如字典文件或命令）、编码器设置以及输出格式等内容。
//
// 参数:
//   - parseOpts: 包含从命令行解析出的所有配置选项的结构体指针。
//   - ctx: 上下文对象，用于控制 goroutine 生命周期。
//   - cancel: 取消函数，可用于主动终止上下文。
//
// 返回值:
//   - *Config: 构建完成的配置对象。
//   - error: 如果在构建过程中出现错误，则返回相应的错误信息；否则返回 nil。
func ConfigFromOptions(parseOpts *ConfigOptions, ctx context.Context, cancel context.CancelFunc) (*Config, error) {
	//TODO: refactor in a proper flag library that can handle things like required flags
	errs := NewMultierror()
	conf := NewConfig(ctx, cancel)

	var err error
	var err2 error
	if len(parseOpts.HTTP.URL) == 0 && parseOpts.Input.Request == "" {
		errs.Add(fmt.Errorf("-u flag or -request flag is required"))
	}

	// 准备扩展名列表
	if parseOpts.Input.Extensions != "" {
		extensions := strings.Split(parseOpts.Input.Extensions, ",")
		conf.Extensions = extensions
	}

	// 将 Cookie 转换为 Header 形式追加到 Headers 中
	if len(parseOpts.HTTP.Cookies) > 0 {
		parseOpts.HTTP.Headers = append(parseOpts.HTTP.Headers, "Cookie: "+strings.Join(parseOpts.HTTP.Cookies, "; "))
	}

	// 设置输入模式并校验其合法性
	conf.InputMode = parseOpts.Input.InputMode

	validmode := false
	for _, mode := range []string{"clusterbomb", "pitchfork", "sniper"} {
		if conf.InputMode == mode {
			validmode = true
		}
	}
	if !validmode {
		errs.Add(fmt.Errorf("Input mode (-mode) %s not recognized", conf.InputMode))
	}

	template := ""
	// 对 sniper 模式进行额外检查：只允许使用一个词表和一个命令
	if conf.InputMode == "sniper" {
		template = "§"

		if len(parseOpts.Input.Wordlists) > 1 {
			errs.Add(fmt.Errorf("sniper mode only supports one wordlist"))
		}

		if len(parseOpts.Input.Inputcommands) > 1 {
			errs.Add(fmt.Errorf("sniper mode only supports one input command"))
		}
	}

	// 解析编码器配置
	tmpEncoders := make(map[string]string)
	for _, e := range parseOpts.Input.Encoders {
		if strings.Contains(e, ":") {
			key := strings.Split(e, ":")[0]
			val := strings.Split(e, ":")[1]
			tmpEncoders[key] = val
		}
	}

	// 处理词表路径及关键字映射关系
	tmpWordlists := make([]string, 0)
	for _, v := range parseOpts.Input.Wordlists {
		var wl []string
		if runtime.GOOS == "windows" {
			// 在 Windows 平台尝试正确识别带关键字的路径（例如 C:\path\to\wordlist.txt:KEYWORD）
			if FileExists(v) {
				// 不带关键字参数的情况
				wl = []string{v}
			} else {
				filepart := v
				if strings.Contains(filepart, ":") {
					filepart = v[:strings.LastIndex(filepart, ":")]
				}

				if FileExists(filepart) {
					wl = []string{filepart, v[strings.LastIndex(v, ":")+1:]}
				} else {
					// 文件未找到，保留原始值以便后续报错更清晰
					wl = []string{v}
				}
			}
		} else {
			wl = strings.SplitN(v, ":", 2)
		}
		// 使用绝对路径表示词表位置
		fullpath := ""
		if wl[0] != "-" {
			fullpath, err = filepath.Abs(wl[0])
		} else {
			fullpath = wl[0]
		}

		if err == nil {
			wl[0] = fullpath
		}
		if len(wl) == 2 {
			if conf.InputMode == "sniper" {
				errs.Add(fmt.Errorf("sniper mode does not support wordlist keywords"))
			} else {
				newp := InputProviderConfig{
					Name:    "wordlist",
					Value:   wl[0],
					Keyword: wl[1],
				}
				// 添加对应的编码器
				enc, ok := tmpEncoders[wl[1]]
				if ok {
					newp.Encoders = enc
				}
				conf.InputProviders = append(conf.InputProviders, newp)
			}
		} else {
			newp := InputProviderConfig{
				Name:     "wordlist",
				Value:    wl[0],
				Keyword:  "FUZZ",
				Template: template,
			}
			// 添加对应的编码器
			enc, ok := tmpEncoders["FUZZ"]
			if ok {
				newp.Encoders = enc
			}
			conf.InputProviders = append(conf.InputProviders, newp)
		}
		tmpWordlists = append(tmpWordlists, strings.Join(wl, ":"))
	}
	conf.Wordlists = tmpWordlists

	// 处理通过命令提供输入的方式及其关键字映射
	for _, v := range parseOpts.Input.Inputcommands {
		ic := strings.SplitN(v, ":", 2)
		if len(ic) == 2 {
			if conf.InputMode == "sniper" {
				errs.Add(fmt.Errorf("sniper mode does not support command keywords"))
			} else {
				newp := InputProviderConfig{
					Name:    "command",
					Value:   ic[0],
					Keyword: ic[1],
				}
				enc, ok := tmpEncoders[ic[1]]
				if ok {
					newp.Encoders = enc
				}
				conf.InputProviders = append(conf.InputProviders, newp)
				conf.CommandKeywords = append(conf.CommandKeywords, ic[0])
			}
		} else {
			newp := InputProviderConfig{
				Name:     "command",
				Value:    ic[0],
				Keyword:  "FUZZ",
				Template: template,
			}
			enc, ok := tmpEncoders["FUZZ"]
			if ok {
				newp.Encoders = enc
			}
			conf.InputProviders = append(conf.InputProviders, newp)
			conf.CommandKeywords = append(conf.CommandKeywords, "FUZZ")
		}
	}

	if len(conf.InputProviders) == 0 {
		errs.Add(fmt.Errorf("Either -w or --input-cmd flag is required"))
	}

	// 解析原始请求内容
	if parseOpts.Input.Request != "" {
		err := parseRawRequest(parseOpts, &conf)
		if err != nil {
			errmsg := fmt.Sprintf("Could not parse raw request: %s", err)
			errs.Add(fmt.Errorf(errmsg))
		}
	}

	// 设置目标 URL
	if parseOpts.HTTP.URL != "" {
		conf.Url = parseOpts.HTTP.URL
	}

	// 设置 SNI 名称
	if parseOpts.HTTP.SNI != "" {
		conf.SNI = parseOpts.HTTP.SNI
	}

	// 设置客户端证书与私钥
	if parseOpts.HTTP.ClientCert != "" {
		conf.ClientCert = parseOpts.HTTP.ClientCert
	}
	if parseOpts.HTTP.ClientKey != "" {
		conf.ClientKey = parseOpts.HTTP.ClientKey
	}

	// 处理 HTTP 请求头并标准化字段名称
	for _, v := range parseOpts.HTTP.Headers {
		hs := strings.SplitN(v, ":", 2)
		if len(hs) == 2 {
			// 判断是否需要标准化头部字段名
			var CanonicalNeeded = true
			for _, a := range conf.CommandKeywords {
				if strings.Contains(hs[0], a) {
					CanonicalNeeded = false
				}
			}
			// 再次判断是否属于 InputProviders 的关键词
			if CanonicalNeeded {
				for _, b := range conf.InputProviders {
					if strings.Contains(hs[0], b.Keyword) {
						CanonicalNeeded = false
					}
				}
			}
			if CanonicalNeeded {
				var CanonicalHeader = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(hs[0]))
				conf.Headers[CanonicalHeader] = strings.TrimSpace(hs[1])
			} else {
				conf.Headers[strings.TrimSpace(hs[0])] = strings.TrimSpace(hs[1])
			}
		} else {
			errs.Add(fmt.Errorf("Header defined by -H needs to have a value. \":\" should be used as a separator"))
		}
	}

	// 设置延迟时间范围
	d := strings.Split(parseOpts.General.Delay, "-")
	if len(d) > 2 {
		errs.Add(fmt.Errorf("Delay needs to be either a single float: \"0.1\" or a range of floats, delimited by dash: \"0.1-0.8\""))
	} else if len(d) == 2 {
		conf.Delay.IsRange = true
		conf.Delay.HasDelay = true
		conf.Delay.Min, err = strconv.ParseFloat(d[0], 64)
		conf.Delay.Max, err2 = strconv.ParseFloat(d[1], 64)
		if err != nil || err2 != nil {
			errs.Add(fmt.Errorf("Delay range min and max values need to be valid floats. For example: 0.1-0.5"))
		}
	} else if len(parseOpts.General.Delay) > 0 {
		conf.Delay.IsRange = false
		conf.Delay.HasDelay = true
		conf.Delay.Min, err = strconv.ParseFloat(parseOpts.General.Delay, 64)
		if err != nil {
			errs.Add(fmt.Errorf("Delay needs to be either a single float: \"0.1\" or a range of floats, delimited by dash: \"0.1-0.8\""))
		}
	}

	// 验证代理地址格式
	if len(parseOpts.HTTP.ProxyURL) > 0 {
		u, err := url.Parse(parseOpts.HTTP.ProxyURL)
		if err != nil || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
			errs.Add(fmt.Errorf("Bad proxy url (-x) format. Expected http, https or socks5 url"))
		} else {
			conf.ProxyURL = parseOpts.HTTP.ProxyURL
		}
	}

	// 验证重放代理地址格式
	if len(parseOpts.HTTP.ReplayProxyURL) > 0 {
		u, err := url.Parse(parseOpts.HTTP.ReplayProxyURL)
		if err != nil || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h") {
			errs.Add(fmt.Errorf("Bad replay-proxy url (-replay-proxy) format. Expected http, https or socks5 url"))
		} else {
			conf.ReplayProxyURL = parseOpts.HTTP.ReplayProxyURL
		}
	}

	// 校验输出文件格式类型
	if parseOpts.Output.OutputFile != "" {
		// 仅当定义了输出文件时才做检查
		outputFormats := []string{"all", "json", "ejson", "html", "md", "csv", "ecsv"}
		found := false
		for _, f := range outputFormats {
			if f == parseOpts.Output.OutputFormat {
				conf.OutputFormat = f
				found = true
			}
		}
		if !found {
			errs.Add(fmt.Errorf("Unknown output file format (-of): %s", parseOpts.Output.OutputFormat))
		}
	}

	// 自动校准字符串设置
	if len(parseOpts.General.AutoCalibrationStrings) > 0 {
		conf.AutoCalibrationStrings = parseOpts.General.AutoCalibrationStrings
	}
	// 自动校准策略设置
	if len(parseOpts.General.AutoCalibrationStrategies) > 0 {
		conf.AutoCalibrationStrategies = parseOpts.General.AutoCalibrationStrategies
	}
	// 使用 -acc 或 -acs 表示启用自动校准功能
	if len(parseOpts.General.AutoCalibrationStrings) > 0 {
		conf.AutoCalibration = true
	}
	if len(parseOpts.General.AutoCalibrationStrategies) > 0 {
		conf.AutoCalibration = true
	}

	if parseOpts.General.Rate < 0 {
		conf.Rate = 0
	} else {
		conf.Rate = int64(parseOpts.General.Rate)
	}

	if conf.Method == "" {
		if parseOpts.HTTP.Method == "" {
			// 仅在命令行中指定的情况下设置默认方法，因为可能是在重新解析 CLI 后填充的
			conf.Method = "GET"
		} else {
			conf.Method = parseOpts.HTTP.Method
		}
	} else {
		if parseOpts.HTTP.Method != "" {
			// 方法被命令行覆盖
			conf.Method = parseOpts.HTTP.Method
		}
	}

	if parseOpts.HTTP.Data != "" {
		// 仅在命令行中指定的情况下设置数据，因为可能是在重新解析 CLI 后填充的
		conf.Data = parseOpts.HTTP.Data
	}

	// 常规通用配置赋值
	conf.IgnoreWordlistComments = parseOpts.Input.IgnoreWordlistComments
	conf.DirSearchCompat = parseOpts.Input.DirSearchCompat
	conf.Colors = parseOpts.General.Colors
	conf.InputNum = parseOpts.Input.InputNum

	conf.InputShell = parseOpts.Input.InputShell
	conf.AuditLog = parseOpts.Output.AuditLog
	conf.OutputFile = parseOpts.Output.OutputFile
	conf.OutputDirectory = parseOpts.Output.OutputDirectory
	conf.OutputSkipEmptyFile = parseOpts.Output.OutputSkipEmptyFile
	conf.IgnoreBody = parseOpts.HTTP.IgnoreBody
	conf.Quiet = parseOpts.General.Quiet
	conf.ScraperFile = parseOpts.General.ScraperFile
	conf.Scrapers = parseOpts.General.Scrapers
	conf.StopOn403 = parseOpts.General.StopOn403
	conf.StopOnAll = parseOpts.General.StopOnAll
	conf.StopOnErrors = parseOpts.General.StopOnErrors
	conf.FollowRedirects = parseOpts.HTTP.FollowRedirects
	conf.Raw = parseOpts.HTTP.Raw
	conf.Recursion = parseOpts.HTTP.Recursion
	conf.RecursionDepth = parseOpts.HTTP.RecursionDepth
	conf.RecursionStrategy = parseOpts.HTTP.RecursionStrategy
	conf.AutoCalibration = parseOpts.General.AutoCalibration
	conf.AutoCalibrationPerHost = parseOpts.General.AutoCalibrationPerHost
	conf.AutoCalibrationStrategies = parseOpts.General.AutoCalibrationStrategies
	conf.Threads = parseOpts.General.Threads
	conf.Timeout = parseOpts.HTTP.Timeout
	conf.MaxTime = parseOpts.General.MaxTime
	conf.MaxTimeJob = parseOpts.General.MaxTimeJob
	conf.Noninteractive = parseOpts.General.Noninteractive
	conf.Verbose = parseOpts.General.Verbose
	conf.Json = parseOpts.General.Json
	conf.Http2 = parseOpts.HTTP.Http2

	// 校验 filter 和 matcher 的操作模式是否合法
	valid_opmodes := []string{"and", "or"}
	fmode_found := false
	mmode_found := false
	for _, v := range valid_opmodes {
		if v == parseOpts.Filter.Mode {
			fmode_found = true
		}
		if v == parseOpts.Matcher.Mode {
			mmode_found = true
		}
	}
	if !fmode_found {
		errmsg := fmt.Sprintf("Unrecognized value for parameter fmode: %s, valid values are: and, or", parseOpts.Filter.Mode)
		errs.Add(fmt.Errorf(errmsg))
	}
	if !mmode_found {
		errmsg := fmt.Sprintf("Unrecognized value for parameter mmode: %s, valid values are: and, or", parseOpts.Matcher.Mode)
		errs.Add(fmt.Errorf(errmsg))
	}
	conf.FilterMode = parseOpts.Filter.Mode
	conf.MatcherMode = parseOpts.Matcher.Mode

	if conf.AutoCalibrationPerHost {
		// AutoCalibrationPerHost 暗示启用了 AutoCalibration 功能
		conf.AutoCalibration = true
	}

	// 处理 curl 类似场景下的隐式 POST 方法行为
	if len(conf.Data) > 0 &&
		conf.Method == "GET" &&
		// 不修改已使用请求文件作为输入的情况
		len(parseOpts.Input.Request) == 0 {

		conf.Method = "POST"
	}

	conf.CommandLine = strings.Join(os.Args, " ")

	// 过滤掉模板或关键词不存在于请求中的输入提供者
	newInputProviders := []InputProviderConfig{}
	for _, provider := range conf.InputProviders {
		if provider.Template != "" {
			if !templatePresent(provider.Template, &conf) {
				errmsg := fmt.Sprintf("Template %s defined, but not found in pairs in headers, method, URL or POST data.", provider.Template)
				errs.Add(fmt.Errorf(errmsg))
			} else {
				newInputProviders = append(newInputProviders, provider)
			}
		} else {
			if !keywordPresent(provider.Keyword, &conf) {
				errmsg := fmt.Sprintf("Keyword %s defined, but not found in headers, method, URL or POST data.", provider.Keyword)
				_, _ = fmt.Fprintf(os.Stderr, "%s\n", fmt.Errorf(errmsg))
			} else {
				newInputProviders = append(newInputProviders, provider)
			}
		}
	}
	conf.InputProviders = newInputProviders

	// sniper 模式不允许存在 FUZZ 关键词
	if conf.InputMode == "sniper" {
		if keywordPresent("FUZZ", &conf) {
			errs.Add(fmt.Errorf("FUZZ keyword defined, but we are using sniper mode."))
		}
	}

	// 递归模式相关检查
	if parseOpts.HTTP.Recursion {
		if !strings.HasSuffix(conf.Url, "FUZZ") {
			errmsg := "When using -recursion the URL (-u) must end with FUZZ keyword."
			errs.Add(fmt.Errorf(errmsg))
		}
	}

	// verbose 与 json 输出互斥
	if parseOpts.General.Verbose && parseOpts.General.Json {
		errs.Add(fmt.Errorf("Cannot have -json and -v"))
	}
	return &conf, errs.ErrorOrNil()
}

// parseRawRequest 从指定的请求文件中解析原始HTTP请求，并将解析结果填充到配置对象中。
// 参数:
//   - parseOpts: 包含输入选项的配置选项结构体指针，用于获取请求文件路径和协议等信息。
//   - conf: 配置结构体指针，用于存储解析后的请求信息，如方法、URL、头部和请求体等。
//
// 返回值:
//   - error: 如果在打开文件、读取内容或解析过程中发生错误，则返回相应的错误信息；否则返回nil。
func parseRawRequest(parseOpts *ConfigOptions, conf *Config) error {
	conf.RequestFile = parseOpts.Input.Request
	conf.RequestProto = parseOpts.Input.RequestProto
	file, err := os.Open(parseOpts.Input.Request)
	if err != nil {
		return fmt.Errorf("could not open request file: %s", err)
	}
	defer file.Close()

	r := bufio.NewReader(file)

	s, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("could not read request: %s", err)
	}
	parts := strings.Split(s, " ")
	if len(parts) < 3 {
		return fmt.Errorf("malformed request supplied")
	}
	// 设置请求方法
	conf.Method = parts[0]

	// 逐行读取并解析HTTP头部字段
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)

		if err != nil || line == "" {
			break
		}

		p := strings.SplitN(line, ":", 2)
		if len(p) != 2 {
			continue
		}

		// 忽略Content-Length头部，避免与实际请求体长度冲突
		if strings.EqualFold(p[0], "content-length") {
			continue
		}

		conf.Headers[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
	}

	// 处理路径为完整HTTP URL的情况，此时使用该URL作为请求地址，并更新Host头部
	if strings.HasPrefix(parts[1], "http") {
		parsed, err := url.Parse(parts[1])
		if err != nil {
			return fmt.Errorf("could not parse request URL: %s", err)
		}
		conf.Url = parts[1]
		conf.Headers["Host"] = parsed.Host
	} else {
		// 构建完整的请求URL：协议 + Host头 + 路径
		conf.Url = parseOpts.Input.RequestProto + "://" + conf.Headers["Host"] + parts[1]
	}

	// 读取并设置请求体内容
	b, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("could not read request body: %s", err)
	}
	conf.Data = string(b)

	// 移除文件末尾可能由编辑器自动添加的换行符（仅移除一个）
	//nolint:gosimple // we specifically want to remove just a single newline, not all of them
	if strings.HasSuffix(conf.Data, "\r\n") {
		conf.Data = conf.Data[:len(conf.Data)-2]
	} else if strings.HasSuffix(conf.Data, "\n") {
		conf.Data = conf.Data[:len(conf.Data)-1]
	}
	return nil
}

// keywordPresent 检查关键词是否出现在HTTP请求配置的任何部分
// 它会搜索HTTP方法、URL、POST数据以及请求头(包括键和值)
//
// 参数:
//   - keyword: 要搜索的关键词字符串
//   - conf: 指向包含HTTP请求配置的Config结构体的指针
//
// 返回值:
//   - bool: 如果在配置的任何部分找到关键词则返回true，否则返回false
func keywordPresent(keyword string, conf *Config) bool {
	// 从HTTP方法、URL和POST数据中搜索关键词
	if strings.Contains(conf.Method, keyword) {
		return true
	}
	if strings.Contains(conf.Url, keyword) {
		return true
	}
	if strings.Contains(conf.Data, keyword) {
		return true
	}

	// 检查关键词是否存在于请求头的键或值中
	for k, v := range conf.Headers {
		if strings.Contains(k, keyword) {
			return true
		}
		if strings.Contains(v, keyword) {
			return true
		}
	}
	return false
}

// templatePresent 检查模板标识符是否在所有配置字段中成对出现
// 它验证模板占位符出现的次数是否为偶数，以确保正确的开始/结束配对
//
// 参数:
//
//	template - 要搜索的模板标识符字符串
//	conf     - 指向Config结构体的指针，包含要搜索的方法、URL、数据和请求头
//
// 返回值:
//
//	bool - 如果在任何字段中找到成对的模板(偶数次)，则返回true；否则返回false或找到奇数次时也返回false
func templatePresent(template string, conf *Config) bool {
	// 搜索输入位置标识符，这些必须成对出现
	sane := false

	// 检查Method字段中的模板计数
	if c := strings.Count(conf.Method, template); c > 0 {
		if c%2 != 0 {
			return false
		}
		sane = true
	}

	// 检查Url字段中的模板计数
	if c := strings.Count(conf.Url, template); c > 0 {
		if c%2 != 0 {
			return false
		}
		sane = true
	}

	// 检查Data字段中的模板计数
	if c := strings.Count(conf.Data, template); c > 0 {
		if c%2 != 0 {
			return false
		}
		sane = true
	}

	// 检查Headers键值对中的模板计数
	for k, v := range conf.Headers {
		if c := strings.Count(k, template); c > 0 {
			if c%2 != 0 {
				return false
			}
			sane = true
		}
		if c := strings.Count(v, template); c > 0 {
			if c%2 != 0 {
				return false
			}
			sane = true
		}
	}

	return sane
}

// ReadConfig 从 TOML 配置文件中读取配置并将其解析到 ConfigOptions 结构体中。
// 接收一个 configFile 参数，表示配置文件的路径。
// 返回指向 ConfigOptions 的指针和在读取或解析过程中可能发生的错误。
func ReadConfig(configFile string) (*ConfigOptions, error) {
	// 创建一个新的 ConfigOptions 实例
	conf := NewConfigOptions()

	// 读取配置文件数据
	configData, err := os.ReadFile(configFile)
	if err == nil {
		// 将 TOML 格式的数据解析到 ConfigOptions 结构体中
		err = toml.Unmarshal(configData, conf)
	}

	return conf, err
}

// ReadDefaultConfig 读取默认配置文件并返回解析后的配置选项。
// 首先尝试从系统范围的配置目录读取，如果不存在则回退到用户主目录。
//
// 返回值:
//   - *ConfigOptions: 指向解析后的配置选项的指针
//   - error: 在读取或解析配置过程中遇到的任何错误
func ReadDefaultConfig() (*ConfigOptions, error) {
	// 尝试创建配置目录，忽略可能的错误
	_ = CheckOrCreateConfigDir()

	// 构造默认配置文件路径
	conffile := filepath.Join(CONFIGDIR, "ffufrc")

	// 如果在默认配置目录中找不到配置文件，则尝试使用用户主目录
	if !FileExists(conffile) {
		userhome, err := os.UserHomeDir()
		if err == nil {
			conffile = filepath.Join(userhome, ".ffufrc")
		}
	}

	// 读取并解析配置文件
	return ReadConfig(conffile)
}
