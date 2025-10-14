package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/filter"
	"github.com/ffuf/ffuf/v2/pkg/input"
	"github.com/ffuf/ffuf/v2/pkg/interactive"
	"github.com/ffuf/ffuf/v2/pkg/output"
	"github.com/ffuf/ffuf/v2/pkg/runner"
	"github.com/ffuf/ffuf/v2/pkg/scraper"
)

// multiStringFlag 定义了一个字符串切片类型，用于实现命令行参数的多重字符串标志
// 该类型可以接收多个字符串值作为命令行参数，例如可以用于处理多个HTTP头或Cookie
type multiStringFlag []string

// wordlistFlag 定义了一个字符串切片类型，用于实现命令行参数的词表标志
// 该类型专门用于处理词表相关的命令行参数输入，支持通过逗号分隔的多个词表路径
type wordlistFlag []string

// String 返回 multiStringFlag 的字符串表示形式，始终返回空字符串
// 该方法是实现 flag.Value 接口所必需的
func (m *multiStringFlag) String() string {
	return ""
}

// String 返回 wordlistFlag 的字符串表示形式，始终返回空字符串
// 该方法是实现 flag.Value 接口所必需的
func (m *wordlistFlag) String() string {
	return ""
}

// Set 将值添加到 multiStringFlag 切片中
// 该方法实现了 flag.Value 接口的 Set 方法
// 参数:
//   - value: 要追加到标志中的字符串值
//
// 返回值:
//   - error: 始终返回 nil，因为不执行任何验证
func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// Set 解析并将值添加到 wordlistFlag 切片中
// 如果输入包含逗号，则分割值并分别添加每个部分
// 否则将值作为单个元素添加
// 该方法实现了 flag.Value 接口的 Set 方法
// 参数:
//   - value: 要处理并追加到标志中的字符串值
//
// 返回值:
//   - error: 始终返回 nil，因为不执行任何验证
func (m *wordlistFlag) Set(value string) error {
	delimited := strings.Split(value, ",")

	// 如果找到逗号分隔的值，则分别添加每个值
	if len(delimited) > 1 {
		*m = append(*m, delimited...)
	} else {
		// 否则添加单个值
		*m = append(*m, value)
	}

	return nil
}

// ParseFlags parses the command line flags and (re)populates the ConfigOptions struct
// ParseFlags 解析命令行参数并填充到 ffuf.ConfigOptions 结构体中。
// 它定义了所有支持的命令行标志，并将解析后的值赋给传入的 opts 参数。
//
// 参数:
//   - opts: 指向 ffuf.ConfigOptions 的指针，用于接收解析后的配置选项。
//
// 返回值:
//   - *ffuf.ConfigOptions: 返回更新后的配置选项结构体指针。
func ParseFlags(opts *ffuf.ConfigOptions) *ffuf.ConfigOptions {
	var ignored bool

	// 定义多个自定义 flag 类型变量，用于处理多值参数
	var cookies, autocalibrationstrings, autocalibrationstrategies, headers, inputcommands multiStringFlag
	var wordlists, encoders wordlistFlag

	// 初始化这些变量为当前配置中的值
	cookies = opts.HTTP.Cookies
	autocalibrationstrings = opts.General.AutoCalibrationStrings
	headers = opts.HTTP.Headers
	inputcommands = opts.Input.Inputcommands
	wordlists = opts.Input.Wordlists
	encoders = opts.Input.Encoders

	// 注册 dummy 标志，用于兼容 curl 命令复制功能或向后兼容性
	flag.BoolVar(&ignored, "compressed", true, "Dummy flag for copy as curl functionality (ignored)")
	flag.BoolVar(&ignored, "i", true, "Dummy flag for copy as curl functionality (ignored)")
	flag.BoolVar(&ignored, "k", false, "Dummy flag for backwards compatibility")

	// 注册输出相关标志
	flag.BoolVar(&opts.Output.OutputSkipEmptyFile, "or", opts.Output.OutputSkipEmptyFile, "Don't create the output file if we don't have results")

	// 注册自动校准相关标志
	flag.BoolVar(&opts.General.AutoCalibration, "ac", opts.General.AutoCalibration, "Automatically calibrate filtering options")
	flag.BoolVar(&opts.General.AutoCalibrationPerHost, "ach", opts.General.AutoCalibration, "Per host autocalibration")

	// 注册通用行为控制标志
	flag.BoolVar(&opts.General.Colors, "c", opts.General.Colors, "Colorize output.")
	flag.BoolVar(&opts.General.Json, "json", opts.General.Json, "JSON output, printing newline-delimited JSON records")
	flag.BoolVar(&opts.General.Noninteractive, "noninteractive", opts.General.Noninteractive, "Disable the interactive console functionality")
	flag.BoolVar(&opts.General.Quiet, "s", opts.General.Quiet, "Do not print additional information (silent mode)")
	flag.BoolVar(&opts.General.ShowVersion, "V", opts.General.ShowVersion, "Show version information.")
	flag.BoolVar(&opts.General.StopOn403, "sf", opts.General.StopOn403, "Stop when > 95% of responses return 403 Forbidden")
	flag.BoolVar(&opts.General.StopOnAll, "sa", opts.General.StopOnAll, "Stop on all error cases. Implies -sf and -se.")
	flag.BoolVar(&opts.General.StopOnErrors, "se", opts.General.StopOnErrors, "Stop on spurious errors")
	flag.BoolVar(&opts.General.Verbose, "v", opts.General.Verbose, "Verbose output, printing full URL and redirect location (if any) with the results.")

	// 注册 HTTP 请求相关标志
	flag.BoolVar(&opts.HTTP.FollowRedirects, "r", opts.HTTP.FollowRedirects, "Follow redirects")
	flag.BoolVar(&opts.HTTP.IgnoreBody, "ignore-body", opts.HTTP.IgnoreBody, "Do not fetch the response content.")
	flag.BoolVar(&opts.HTTP.Raw, "raw", opts.HTTP.Raw, "Do not encode URI")
	flag.BoolVar(&opts.HTTP.Recursion, "recursion", opts.HTTP.Recursion, "Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it.")
	flag.BoolVar(&opts.HTTP.Http2, "http2", opts.HTTP.Http2, "Use HTTP2 protocol")

	// 注册输入处理相关标志
	flag.BoolVar(&opts.Input.DirSearchCompat, "D", opts.Input.DirSearchCompat, "DirSearch wordlist compatibility mode. Used in conjunction with -e flag.")
	flag.BoolVar(&opts.Input.IgnoreWordlistComments, "ic", opts.Input.IgnoreWordlistComments, "Ignore wordlist comments")

	// 注册整数类型参数标志
	flag.IntVar(&opts.General.MaxTime, "maxtime", opts.General.MaxTime, "Maximum running time in seconds for entire process.")
	flag.IntVar(&opts.General.MaxTimeJob, "maxtime-job", opts.General.MaxTimeJob, "Maximum running time in seconds per job.")
	flag.IntVar(&opts.General.Rate, "rate", opts.General.Rate, "Rate of requests per second")
	flag.IntVar(&opts.General.Threads, "t", opts.General.Threads, "Number of concurrent threads.")
	flag.IntVar(&opts.HTTP.RecursionDepth, "recursion-depth", opts.HTTP.RecursionDepth, "Maximum recursion depth.")
	flag.IntVar(&opts.HTTP.Timeout, "timeout", opts.HTTP.Timeout, "HTTP request timeout in seconds.")
	flag.IntVar(&opts.Input.InputNum, "input-num", opts.Input.InputNum, "Number of inputs to test. Used in conjunction with --input-cmd.")

	// 注册字符串类型参数标志
	flag.StringVar(&opts.General.AutoCalibrationKeyword, "ack", opts.General.AutoCalibrationKeyword, "Autocalibration keyword")
	flag.StringVar(&opts.HTTP.ClientCert, "cc", "", "Client cert for authentication. Client key needs to be defined as well for this to work")
	flag.StringVar(&opts.HTTP.ClientKey, "ck", "", "Client key for authentication. Client certificate needs to be defined as well for this to work")
	flag.StringVar(&opts.General.ConfigFile, "config", "", "Load configuration from a file")
	flag.StringVar(&opts.General.ScraperFile, "scraperfile", "", "Custom scraper file path")
	flag.StringVar(&opts.General.Scrapers, "scrapers", opts.General.Scrapers, "Active scraper groups")
	flag.StringVar(&opts.Filter.Mode, "fmode", opts.Filter.Mode, "Filter set operator. Either of: and, or")
	flag.StringVar(&opts.Filter.Lines, "fl", opts.Filter.Lines, "Filter by amount of lines in response. Comma separated list of line counts and ranges")
	flag.StringVar(&opts.Filter.Regexp, "fr", opts.Filter.Regexp, "Filter regexp")
	flag.StringVar(&opts.Filter.Size, "fs", opts.Filter.Size, "Filter HTTP response size. Comma separated list of sizes and ranges")
	flag.StringVar(&opts.Filter.Status, "fc", opts.Filter.Status, "Filter HTTP status codes from response. Comma separated list of codes and ranges")
	flag.StringVar(&opts.Filter.Time, "ft", opts.Filter.Time, "Filter by number of milliseconds to the first response byte, either greater or less than. EG: >100 or <100")
	flag.StringVar(&opts.Filter.Words, "fw", opts.Filter.Words, "Filter by amount of words in response. Comma separated list of word counts and ranges")
	flag.StringVar(&opts.General.Delay, "p", opts.General.Delay, "Seconds of `delay` between requests, or a range of random delay. For example \"0.1\" or \"0.1-2.0\"")
	flag.StringVar(&opts.General.Searchhash, "search", opts.General.Searchhash, "Search for a FFUFHASH payload from ffuf history")
	flag.StringVar(&opts.HTTP.Data, "d", opts.HTTP.Data, "POST data")
	flag.StringVar(&opts.HTTP.Data, "data", opts.HTTP.Data, "POST data (alias of -d)")
	flag.StringVar(&opts.HTTP.Data, "data-ascii", opts.HTTP.Data, "POST data (alias of -d)")
	flag.StringVar(&opts.HTTP.Data, "data-binary", opts.HTTP.Data, "POST data (alias of -d)")
	flag.StringVar(&opts.HTTP.Method, "X", opts.HTTP.Method, "HTTP method to use")
	flag.StringVar(&opts.HTTP.ProxyURL, "x", opts.HTTP.ProxyURL, "Proxy URL (SOCKS5 or HTTP). For example: http://127.0.0.1:8080 or socks5://127.0.0.1:8080")
	flag.StringVar(&opts.HTTP.ReplayProxyURL, "replay-proxy", opts.HTTP.ReplayProxyURL, "Replay matched requests using this proxy.")
	flag.StringVar(&opts.HTTP.RecursionStrategy, "recursion-strategy", opts.HTTP.RecursionStrategy, "Recursion strategy: \"default\" for a redirect based, and \"greedy\" to recurse on all matches")
	flag.StringVar(&opts.HTTP.URL, "u", opts.HTTP.URL, "Target URL")
	flag.StringVar(&opts.HTTP.SNI, "sni", opts.HTTP.SNI, "Target TLS SNI, does not support FUZZ keyword")
	flag.StringVar(&opts.Input.Extensions, "e", opts.Input.Extensions, "Comma separated list of extensions. Extends FUZZ keyword.")
	flag.StringVar(&opts.Input.InputMode, "mode", opts.Input.InputMode, "Multi-wordlist operation mode. Available modes: clusterbomb, pitchfork, sniper")
	flag.StringVar(&opts.Input.InputShell, "input-shell", opts.Input.InputShell, "Shell to be used for running command")
	flag.StringVar(&opts.Input.Request, "request", opts.Input.Request, "File containing the raw http request")
	flag.StringVar(&opts.Input.RequestProto, "request-proto", opts.Input.RequestProto, "Protocol to use along with raw request")
	flag.StringVar(&opts.Matcher.Mode, "mmode", opts.Matcher.Mode, "Matcher set operator. Either of: and, or")
	flag.StringVar(&opts.Matcher.Lines, "ml", opts.Matcher.Lines, "Match amount of lines in response")
	flag.StringVar(&opts.Matcher.Regexp, "mr", opts.Matcher.Regexp, "Match regexp")
	flag.StringVar(&opts.Matcher.Size, "ms", opts.Matcher.Size, "Match HTTP response size")
	flag.StringVar(&opts.Matcher.Status, "mc", opts.Matcher.Status, "Match HTTP status codes, or \"all\" for everything.")
	flag.StringVar(&opts.Matcher.Time, "mt", opts.Matcher.Time, "Match how many milliseconds to the first response byte, either greater or less than. EG: >100 or <100")
	flag.StringVar(&opts.Matcher.Words, "mw", opts.Matcher.Words, "Match amount of words in response")
	flag.StringVar(&opts.Output.AuditLog, "audit-log", opts.Output.AuditLog, "Write audit log containing all requests, responses and config")
	flag.StringVar(&opts.Output.DebugLog, "debug-log", opts.Output.DebugLog, "Write all of the internal logging to the specified file.")
	flag.StringVar(&opts.Output.OutputDirectory, "od", opts.Output.OutputDirectory, "Directory path to store matched results to.")
	flag.StringVar(&opts.Output.OutputFile, "o", opts.Output.OutputFile, "Write output to file")
	flag.StringVar(&opts.Output.OutputFormat, "of", opts.Output.OutputFormat, "Output file format. Available formats: json, ejson, html, md, csv, ecsv (or, 'all' for all formats)")

	// 注册多值参数标志
	flag.Var(&autocalibrationstrings, "acc", "Custom auto-calibration string. Can be used multiple times. Implies -ac")
	flag.Var(&autocalibrationstrategies, "acs", "Custom auto-calibration strategies. Can be used multiple times. Implies -ac")
	flag.Var(&cookies, "b", "Cookie data `\"NAME1=VALUE1; NAME2=VALUE2\"` for copy as curl functionality.")
	flag.Var(&cookies, "cookie", "Cookie data (alias of -b)")
	flag.Var(&headers, "H", "Header `\"Name: Value\"`, separated by colon. Multiple -H flags are accepted.")
	flag.Var(&inputcommands, "input-cmd", "Command producing the input. --input-num is required when using this input method. Overrides -w.")
	flag.Var(&wordlists, "w", "Wordlist file path and (optional) keyword separated by colon. eg. '/path/to/wordlist:KEYWORD'")
	flag.Var(&encoders, "enc", "Encoders for keywords, eg. 'FUZZ:urlencode b64encode'")

	// 设置自定义 usage 函数并解析所有标志
	flag.Usage = Usage
	flag.Parse()

	// 将解析后的多值参数写回配置结构体
	opts.General.AutoCalibrationStrings = autocalibrationstrings
	if len(autocalibrationstrategies) > 0 {
		opts.General.AutoCalibrationStrategies = []string{}
		for _, strategy := range autocalibrationstrategies {
			opts.General.AutoCalibrationStrategies = append(opts.General.AutoCalibrationStrategies, strings.Split(strategy, ",")...)
		}
	}
	opts.HTTP.Cookies = cookies
	opts.HTTP.Headers = headers
	opts.Input.Inputcommands = inputcommands
	opts.Input.Wordlists = wordlists
	opts.Input.Encoders = encoders

	return opts
}

// main 是程序的入口函数，负责初始化配置、解析命令行参数、设置日志、处理特殊功能（如搜索哈希）、
// 构建扫描任务并启动执行。
func main() {

	var err, optserr error
	// 创建一个可取消的上下文，用于控制整个程序的生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 从默认配置文件中读取配置选项
	var opts *ffuf.ConfigOptions
	opts, optserr = ffuf.ReadDefaultConfig()

	// 解析命令行参数，并更新配置选项
	opts = ParseFlags(opts)

	// 处理 --searchhash 功能：根据给定的哈希值查找历史请求记录并打印结果
	if opts.General.Searchhash != "" {
		coptions, pos, err := ffuf.SearchHash(opts.General.Searchhash)
		if err != nil {
			fmt.Printf("[ERR] %s\n", err)
			os.Exit(1)
		}
		if len(coptions) > 0 {
			fmt.Printf("Request candidate(s) for hash %s\n", opts.General.Searchhash)
		}
		for _, copt := range coptions {
			conf, err := ffuf.ConfigFromOptions(&copt.ConfigOptions, ctx, cancel)
			if err != nil {
				continue
			}
			ok, reason := ffuf.HistoryReplayable(conf)
			if ok {
				printSearchResults(conf, pos, copt.Time, opts.General.Searchhash)
			} else {
				fmt.Printf("[ERR] Hash cannot be mapped back because %s\n", reason)
			}

		}
		if err != nil {
			fmt.Printf("[ERR] %s\n", err)
		}
		os.Exit(0)
	}

	// 显示版本信息并退出
	if opts.General.ShowVersion {
		fmt.Printf("ffuf version: %s\n", ffuf.Version())
		os.Exit(0)
	}

	// 设置调试日志输出目标
	if len(opts.Output.DebugLog) != 0 {
		f, err := os.OpenFile(opts.Output.DebugLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Disabling logging, encountered error(s): %s\n", err)
			log.SetOutput(io.Discard)
		} else {
			log.SetOutput(f)
			defer f.Close()
		}
	} else {
		log.SetOutput(io.Discard)
	}

	// 记录读取默认配置时出现的错误（如果有）
	if optserr != nil {
		log.Printf("Error while opening default config file: %s", optserr)
	}

	// 如果指定了自定义配置文件，则加载该配置文件的内容
	if opts.General.ConfigFile != "" {
		opts, err = ffuf.ReadConfig(opts.General.ConfigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Encoutered error(s): %s\n", err)
			Usage()
			fmt.Fprintf(os.Stderr, "Encoutered error(s): %s\n", err)
			os.Exit(1)
		}
		// 重置 flag 包的状态以重新解析 CLI 参数
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		// 再次解析命令行参数以覆盖配置文件中的设置
		opts = ParseFlags(opts)
	}

	// 根据最终的配置选项构建 Config 结构体
	conf, err := ffuf.ConfigFromOptions(opts, ctx, cancel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Encountered error(s): %s\n", err)
		Usage()
		fmt.Fprintf(os.Stderr, "Encountered error(s): %s\n", err)
		os.Exit(1)
	}

	// 准备扫描任务对象
	job, err := prepareJob(conf)

	// 关闭审计日志文件句柄（如果已打开）
	if job.AuditLogger != nil {
		defer job.AuditLogger.Close()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Encountered error(s): %s\n", err)
		Usage()
		fmt.Fprintf(os.Stderr, "Encountered error(s): %s\n", err)
		os.Exit(1)
	}

	// 配置过滤器规则
	if err := SetupFilters(opts, conf); err != nil {
		fmt.Fprintf(os.Stderr, "Encountered error(s): %s\n", err)
		Usage()
		fmt.Fprintf(os.Stderr, "Encountered error(s): %s\n", err)
		os.Exit(1)
	}

	// 启动交互式界面（仅在非交互模式下跳过）
	if !conf.Noninteractive {
		go func() {
			err := interactive.Handle(job)
			if err != nil {
				log.Printf("Error while trying to initialize interactive session: %s", err)
			}
		}()
	}

	// 启动扫描任务（内部会等待所有协程完成）
	job.Start()
}

// prepareJob 根据提供的配置准备一个新的 ffuf 任务
// 它初始化输入提供者、运行器、输出提供者、审计日志记录器和抓取器
func prepareJob(conf *ffuf.Config) (*ffuf.Job, error) {
	var err error
	// 创建新的任务实例
	job := ffuf.NewJob(conf)
	var errs ffuf.Multierror
	// 初始化输入提供者
	job.Input, errs = input.NewInputProvider(conf)

	// TODO: 为 runnerprovider 和 outputprovider 实现错误处理
	// 目前我们只有 HTTP 运行器
	job.Runner = runner.NewRunnerByName("http", conf, false)
	// 如果配置了重放代理 URL，则初始化重放运行器
	if len(conf.ReplayProxyURL) > 0 {
		job.ReplayRunner = runner.NewRunnerByName("http", conf, true)
	}
	// 目前我们只有标准输出输出提供者
	job.Output = output.NewOutputProviderByName("stdout", conf)

	// 如果指定了审计日志，则初始化审计日志记录器
	if len(conf.AuditLog) > 0 {
		job.AuditLogger, err = output.NewAuditLogger(conf.AuditLog)
		if err != nil {
			errs.Add(err)
		} else {
			// 将配置写入审计日志
			err = job.AuditLogger.Write(conf)
			if err != nil {
				errs.Add(err)
			}
		}
	}

	// 初始化抓取器
	newscraper, scraper_err := scraper.FromDir(ffuf.SCRAPERDIR, conf.Scrapers)
	if scraper_err.ErrorOrNil() != nil {
		errs.Add(scraper_err.ErrorOrNil())
	}
	job.Scraper = newscraper
	// 如果指定了抓取器文件，则从文件中追加抓取器配置
	if conf.ScraperFile != "" {
		err = job.Scraper.AppendFromFile(conf.ScraperFile)
		if err != nil {
			errs.Add(err)
		}
	}
	// 返回任务和可能的错误集合
	return job, errs.ErrorOrNil()
}

// SetupFilters 根据解析选项设置匹配器和过滤器，并将它们添加到配置中。
// 参数:
//   - parseOpts: 包含用户指定的过滤器和匹配器选项的结构体指针。
//   - conf: 配置对象，用于存储实际生效的匹配器管理器和其他运行时配置。
//
// 返回值:
//   - error: 如果在添加匹配器或过滤器过程中发生错误，则返回包含所有错误的多错误对象；否则返回 nil。
func SetupFilters(parseOpts *ffuf.ConfigOptions, conf *ffuf.Config) error {
	errs := ffuf.NewMultierror()
	conf.MatcherManager = filter.NewMatcherManager()

	// 检查是否通过命令行设置了特定标志位以决定默认行为
	matcherSet := false
	statusSet := false
	warningIgnoreBody := false

	// 遍历已设置的命令行标志，判断哪些匹配/过滤条件被显式指定
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "mc" {
			statusSet = true
		}
		if f.Name == "ms" {
			matcherSet = true
			warningIgnoreBody = true
		}
		if f.Name == "ml" {
			matcherSet = true
			warningIgnoreBody = true
		}
		if f.Name == "mr" {
			matcherSet = true
		}
		if f.Name == "mt" {
			matcherSet = true
		}
		if f.Name == "mw" {
			matcherSet = true
			warningIgnoreBody = true
		}
	})

	// 只有当没有其他匹配器被设置 或者 mc 被显式设置时才使用默认状态码匹配器
	if statusSet || !matcherSet {
		if err := conf.MatcherManager.AddMatcher("status", parseOpts.Matcher.Status); err != nil {
			errs.Add(err)
		}
	}

	// 添加各种过滤器（如果用户提供了相应的参数）
	if parseOpts.Filter.Status != "" {
		if err := conf.MatcherManager.AddFilter("status", parseOpts.Filter.Status, false); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Filter.Size != "" {
		warningIgnoreBody = true
		if err := conf.MatcherManager.AddFilter("size", parseOpts.Filter.Size, false); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Filter.Regexp != "" {
		if err := conf.MatcherManager.AddFilter("regexp", parseOpts.Filter.Regexp, false); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Filter.Words != "" {
		warningIgnoreBody = true
		if err := conf.MatcherManager.AddFilter("word", parseOpts.Filter.Words, false); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Filter.Lines != "" {
		warningIgnoreBody = true
		if err := conf.MatcherManager.AddFilter("line", parseOpts.Filter.Lines, false); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Filter.Time != "" {
		if err := conf.MatcherManager.AddFilter("time", parseOpts.Filter.Time, false); err != nil {
			errs.Add(err)
		}
	}

	// 添加各种匹配器（如果用户提供了相应的参数）
	if parseOpts.Matcher.Size != "" {
		if err := conf.MatcherManager.AddMatcher("size", parseOpts.Matcher.Size); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Matcher.Regexp != "" {
		if err := conf.MatcherManager.AddMatcher("regexp", parseOpts.Matcher.Regexp); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Matcher.Words != "" {
		if err := conf.MatcherManager.AddMatcher("word", parseOpts.Matcher.Words); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Matcher.Lines != "" {
		if err := conf.MatcherManager.AddMatcher("line", parseOpts.Matcher.Lines); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Matcher.Time != "" {
		if err := conf.MatcherManager.AddMatcher("time", parseOpts.Matcher.Time); err != nil {
			errs.Add(err)
		}
	}

	// 如果同时启用了忽略响应体和可能受其影响的过滤器/匹配器，给出警告提示
	if conf.IgnoreBody && warningIgnoreBody {
		fmt.Printf("*** Warning: possible undesired combination of -ignore-body and the response options: fl,fs,fw,ml,ms and mw.\n")
	}

	return errs.ErrorOrNil()
}

// printSearchResults 打印搜索结果，包括配置、位置、执行时间和哈希值
// 参数:
//   - conf: ffuf.Config 配置指针，包含任务配置信息
//   - pos: 整数，表示在输入提供者中的位置
//   - exectime: time.Time，表示执行开始的时间
//   - hash: 字符串，表示 FFUFHASH 值
func printSearchResults(conf *ffuf.Config, pos int, exectime time.Time, hash string) {
	// 根据配置创建新的输入提供者
	inp, err := input.NewInputProvider(conf)
	if err.ErrorOrNil() != nil {
		fmt.Printf("-------------------------------------------\n")
		fmt.Println("Encountered error that prevents reproduction of the request:")
		fmt.Println(err.ErrorOrNil())
		return
	}

	// 设置输入提供者的位置并获取输入数据
	inp.SetPosition(pos)
	inputdata := inp.Value()
	// 将哈希值添加到输入数据中
	inputdata["FFUFHASH"] = []byte(hash)

	// 获取基础请求并创建一个简单的运行器来转储请求
	basereq := ffuf.BaseRequest(conf)
	dummyrunner := runner.NewRunnerByName("simple", conf, false)
	ffufreq, _ := dummyrunner.Prepare(inputdata, &basereq)
	rawreq, _ := dummyrunner.Dump(&ffufreq)

	// 打印格式化的输出，包括执行时间和原始请求
	fmt.Printf("-------------------------------------------\n")
	fmt.Printf("ffuf job started at: %s\n\n", exectime.Format(time.RFC3339))
	fmt.Printf("%s\n", string(rawreq))
}
