package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

// UsageSection 代表命令或工具使用信息的一个部分。
type UsageSection struct {
	Name          string      // Name 是此使用信息部分的标识符
	Description   string      // Description 提供对此部分功能的人类可读解释
	Flags         []UsageFlag // Flags 是属于此部分的使用标志列表
	Hidden        bool        // Hidden 指示此部分是否应从帮助输出中隐藏
	ExpectedFlags []string    // ExpectedFlags 包含此部分中预期存在的标志名称
}

// PrintSection prints out the section name, description and each of the flags
func (u *UsageSection) PrintSection(max_length int, extended bool) {
	// Do not print if extended usage not requested and section marked as hidden
	if !extended && u.Hidden {
		return
	}
	fmt.Printf("%s:\n", u.Name)
	for _, f := range u.Flags {
		f.PrintFlag(max_length)
	}
	fmt.Printf("\n")
}

type UsageFlag struct {
	Name        string
	Description string
	Default     string
}

// PrintFlag prints out the flag name, usage string and default value
func (f *UsageFlag) PrintFlag(max_length int) {
	// Create format string, used for padding
	format := fmt.Sprintf("  -%%-%ds %%s", max_length)
	if f.Default != "" {
		format = format + " (default: %s)\n"
		fmt.Printf(format, f.Name, f.Description, f.Default)
	} else {
		format = format + "\n"
		fmt.Printf(format, f.Name, f.Description)
	}
}

// Usage 输出 ffuf 工具的使用帮助信息，包括各个功能模块的参数说明和使用示例。
// 该函数不接受任何参数，也不返回任何值。
func Usage() {
	// 定义 HTTP 相关选项的帮助信息段
	u_http := UsageSection{
		Name:          "HTTP OPTIONS",
		Description:   "Options controlling the HTTP request and its parts.",
		Flags:         make([]UsageFlag, 0),
		Hidden:        false,
		ExpectedFlags: []string{"cc", "ck", "H", "X", "b", "d", "r", "u", "raw", "recursion", "recursion-depth", "recursion-strategy", "replay-proxy", "timeout", "ignore-body", "x", "sni", "http2"},
	}

	// 定义通用选项的帮助信息段
	u_general := UsageSection{
		Name:          "GENERAL OPTIONS",
		Description:   "",
		Flags:         make([]UsageFlag, 0),
		Hidden:        false,
		ExpectedFlags: []string{"ac", "acc", "ack", "ach", "acs", "c", "config", "json", "maxtime", "maxtime-job", "noninteractive", "p", "rate", "scraperfile", "scrapers", "search", "s", "sa", "se", "sf", "t", "v", "V"},
	}

	// 定义兼容性选项的帮助信息段（默认隐藏）
	u_compat := UsageSection{
		Name:          "COMPATIBILITY OPTIONS",
		Description:   "Options to ensure compatibility with other pieces of software.",
		Flags:         make([]UsageFlag, 0),
		Hidden:        true,
		ExpectedFlags: []string{"compressed", "cookie", "data", "data-ascii", "data-binary", "i", "k"},
	}

	// 定义匹配器选项的帮助信息段
	u_matcher := UsageSection{
		Name:          "MATCHER OPTIONS",
		Description:   "Matchers for the response filtering.",
		Flags:         make([]UsageFlag, 0),
		Hidden:        false,
		ExpectedFlags: []string{"mmode", "mc", "ml", "mr", "ms", "mt", "mw"},
	}

	// 定义过滤器选项的帮助信息段
	u_filter := UsageSection{
		Name:          "FILTER OPTIONS",
		Description:   "Filters for the response filtering.",
		Flags:         make([]UsageFlag, 0),
		Hidden:        false,
		ExpectedFlags: []string{"fmode", "fc", "fl", "fr", "fs", "ft", "fw"},
	}

	// 定义输入选项的帮助信息段
	u_input := UsageSection{
		Name:          "INPUT OPTIONS",
		Description:   "Options for input data for fuzzing. Wordlists and input generators.",
		Flags:         make([]UsageFlag, 0),
		Hidden:        false,
		ExpectedFlags: []string{"D", "enc", "ic", "input-cmd", "input-num", "input-shell", "mode", "request", "request-proto", "e", "w"},
	}

	// 定义输出选项的帮助信息段
	u_output := UsageSection{
		Name:          "OUTPUT OPTIONS",
		Description:   "Options for output. Output file formats, file names and debug file locations.",
		Flags:         make([]UsageFlag, 0),
		Hidden:        false,
		ExpectedFlags: []string{"audit-log", "debug-log", "o", "of", "od", "or"},
	}

	// 将所有帮助信息段组合成一个切片
	sections := []UsageSection{u_http, u_general, u_compat, u_matcher, u_filter, u_input, u_output}

	// 遍历所有已注册的命令行标志，并将其归类到对应的帮助信息段中
	max_length := 0
	flag.VisitAll(func(f *flag.Flag) {
		found := false
		for i, section := range sections {
			if ffuf.StrInSlice(f.Name, section.ExpectedFlags) {
				sections[i].Flags = append(sections[i].Flags, UsageFlag{
					Name:        f.Name,
					Description: f.Usage,
					Default:     f.DefValue,
				})
				found = true
			}
		}
		if !found {
			fmt.Printf("DEBUG: Flag %s was found but not defined in help.go.\n", f.Name)
			os.Exit(1)
		}
		if len(f.Name) > max_length {
			max_length = len(f.Name)
		}
	})

	// 打印工具版本信息
	fmt.Printf("Fuzz Faster U Fool - v%s\n\n", ffuf.Version())

	// 打印各个帮助信息段的内容
	for _, section := range sections {
		section.PrintSection(max_length, false)
	}

	// 打印使用示例
	fmt.Printf("EXAMPLE USAGE:\n")

	fmt.Printf("  Fuzz file paths from wordlist.txt, match all responses but filter out those with content-size 42.\n")
	fmt.Printf("  Colored, verbose output.\n")
	fmt.Printf("    ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v\n\n")

	fmt.Printf("  Fuzz Host-header, match HTTP 200 responses.\n")
	fmt.Printf("    ffuf -w hosts.txt -u https://example.org/ -H \"Host: FUZZ\" -mc 200\n\n")

	fmt.Printf("  Fuzz POST JSON data. Match all responses not containing text \"error\".\n")
	fmt.Printf("    ffuf -w entries.txt -u https://example.org/ -X POST -H \"Content-Type: application/json\" \\\n")
	fmt.Printf("      -d '{\"name\": \"FUZZ\", \"anotherkey\": \"anothervalue\"}' -fr \"error\"\n\n")

	fmt.Printf("  Fuzz multiple locations. Match only responses reflecting the value of \"VAL\" keyword. Colored.\n")
	fmt.Printf("    ffuf -w params.txt:PARAM -w values.txt:VAL -u https://example.org/?PARAM=VAL -mr \"VAL\" -c\n\n")

	fmt.Printf("  More information and examples: https://github.com/ffuf/ffuf\n\n")
}
