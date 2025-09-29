package input

import (
	"fmt"
	"strings"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"

	"github.com/ffuf/pencode/pkg/pencode"
)

// MainInputProvider 结构体用于管理多个输入提供者及其编码器
// 它维护了输入源的集合、编码器映射以及配置信息
type MainInputProvider struct {
	Providers   []ffuf.InternalInputProvider `json:"-"` // 内部输入提供者切片，用于处理不同的输入源
	Encoders    map[string]*pencode.Chain    `json:"-"` // 编码器映射，键为字符串标识，值为编码链
	Config      *ffuf.Config                 `json:"-"` // 配置对象指针，包含运行时配置信息
	position    int                          `json:"-"` // 当前位置索引，用于跟踪处理进度
	msbIterator int                          `json:"-"` // 主迭代器索引，用于主循环迭代控制
}

// NewInputProvider 根据配置创建新的输入提供者
// 参数:
//   - conf: 指向 ffuf.Config 的指针，包含输入提供者的配置信息
//
// 返回值:
//   - ffuf.InputProvider: 创建的输入提供者实例
//   - ffuf.Multierror: 初始化过程中遇到的错误集合
func NewInputProvider(conf *ffuf.Config) (ffuf.InputProvider, ffuf.Multierror) {
	// 验证输入模式配置
	validmode := false
	errs := ffuf.NewMultierror()
	for _, mode := range []string{"clusterbomb", "pitchfork", "sniper"} {
		if conf.InputMode == mode {
			validmode = true
		}
	}
	if !validmode {
		errs.Add(fmt.Errorf("Input mode (-mode) %s not recognized", conf.InputMode))
		return &MainInputProvider{}, errs
	}

	// 创建主输入提供者实例
	mainip := MainInputProvider{Config: conf, msbIterator: 0, Encoders: make(map[string]*pencode.Chain)}

	// 初始化正确的输入提供者
	for _, v := range conf.InputProviders {
		err := mainip.AddProvider(v)
		if err != nil {
			errs.Add(err)
		}
	}
	return &mainip, errs
}

// AddProvider 向 MainInputProvider 添加新的输入提供者
// provider: 要添加的输入提供者配置
// 返回值: 如果提供者初始化失败则返回错误，否则返回 nil
func (i *MainInputProvider) AddProvider(provider ffuf.InputProviderConfig) error {
	// 处理命令输入提供者
	if provider.Name == "command" {
		newcomm, _ := NewCommandInput(provider.Keyword, provider.Value, i.Config)
		i.Providers = append(i.Providers, newcomm)
	} else {
		// 默认使用词表输入提供者
		newwl, err := NewWordlistInput(provider.Keyword, provider.Value, i.Config)
		if err != nil {
			return err
		}
		i.Providers = append(i.Providers, newwl)
	}

	// 如果提供者配置中指定了编码器，则初始化编码器
	if len(provider.Encoders) > 0 {
		chain := pencode.NewChain()
		err := chain.Initialize(strings.Split(strings.TrimSpace(provider.Encoders), " "))
		if err != nil {
			return err
		}
		i.Encoders[provider.Keyword] = chain
	}
	return nil
}

// ActivateKeywords 根据活动关键字列表启用/禁用词表
// 参数:
//   - kws: 包含要激活的关键字的字符串切片
//
// 该函数遍历所有提供者，激活其关键字存在于提供的关键字列表中的提供者，
// 而禁用其余的提供者。
func (i *MainInputProvider) ActivateKeywords(kws []string) {
	for _, p := range i.Providers {
		if ffuf.StrInSlice(p.Keyword(), kws) {
			p.Active()
		} else {
			p.Disable()
		}
	}
}

// Position will return the current position of progress
func (i *MainInputProvider) Position() int {
	return i.position
}

// SetPosition will reset the MainInputProvider to a specific position
func (i *MainInputProvider) SetPosition(pos int) {
	if i.Config.InputMode == "clusterbomb" || i.Config.InputMode == "sniper" {
		i.setclusterbombPosition(pos)
	} else {
		i.setpitchforkPosition(pos)
	}
}

// Keywords returns a slice of all keywords in the inputprovider
func (i *MainInputProvider) Keywords() []string {
	kws := make([]string, 0)
	for _, p := range i.Providers {
		kws = append(kws, p.Keyword())
	}
	return kws
}

// Next will increment the cursor position, and return a boolean telling if there's inputs left
func (i *MainInputProvider) Next() bool {
	if i.position >= i.Total() {
		return false
	}
	i.position++
	return true
}

// Value returns a map of inputs for keywords
func (i *MainInputProvider) Value() map[string][]byte {
	retval := make(map[string][]byte)
	if i.Config.InputMode == "clusterbomb" || i.Config.InputMode == "sniper" {
		retval = i.clusterbombValue()
	}
	if i.Config.InputMode == "pitchfork" {
		retval = i.pitchforkValue()
	}
	if len(i.Encoders) > 0 {
		for key, val := range retval {
			chain, ok := i.Encoders[key]
			if ok {
				tmpVal, err := chain.Encode([]byte(val))
				if err != nil {
					fmt.Printf("ERROR: %s\n", err)
				}
				retval[key] = tmpVal
			}
		}
	}
	return retval
}

// Reset resets all the inputproviders and counters
func (i *MainInputProvider) Reset() {
	for _, p := range i.Providers {
		p.ResetPosition()
	}
	i.position = 0
	i.msbIterator = 0
}

// pitchforkValue returns a map of keyword:value pairs including all inputs.
// This mode will iterate through wordlists in lockstep.
func (i *MainInputProvider) pitchforkValue() map[string][]byte {
	values := make(map[string][]byte)
	for _, p := range i.Providers {
		if !p.Active() {
			// The inputprovider is disabled
			continue
		}
		if !p.Next() {
			// Loop to beginning if the inputprovider has been exhausted
			p.ResetPosition()
		}
		values[p.Keyword()] = p.Value()
		p.IncrementPosition()
	}
	return values
}

func (i *MainInputProvider) setpitchforkPosition(pos int) {
	for _, p := range i.Providers {
		p.SetPosition(pos)
	}
}

// clusterbombValue returns map of keyword:value pairs including all inputs.
// this mode will iterate through all possible combinations.
func (i *MainInputProvider) clusterbombValue() map[string][]byte {
	values := make(map[string][]byte)
	// Should we signal the next InputProvider in the slice to increment
	signalNext := false
	first := true
	index := 0
	for _, p := range i.Providers {
		if !p.Active() {
			continue
		}
		if signalNext {
			p.IncrementPosition()
			signalNext = false
		}
		if !p.Next() {
			// No more inputs in this inputprovider
			if index == i.msbIterator {
				// Reset all previous wordlists and increment the msb counter
				i.msbIterator += 1
				i.clusterbombIteratorReset()
				// Start again
				return i.clusterbombValue()
			}
			p.ResetPosition()
			signalNext = true
		}
		values[p.Keyword()] = p.Value()
		if first {
			p.IncrementPosition()
			first = false
		}
		index += 1
	}
	return values
}

func (i *MainInputProvider) setclusterbombPosition(pos int) {
	i.Reset()
	if pos > i.Total() {
		// noop
		return
	}
	for i.position < pos-1 {
		i.Next()
		i.Value()
	}
}

func (i *MainInputProvider) clusterbombIteratorReset() {
	index := 0
	for _, p := range i.Providers {
		if !p.Active() {
			continue
		}
		if index < i.msbIterator {
			p.ResetPosition()
		}
		if index == i.msbIterator {
			p.IncrementPosition()
		}
		index += 1
	}
}

// Total returns the amount of input combinations available
func (i *MainInputProvider) Total() int {
	count := 0
	if i.Config.InputMode == "pitchfork" {
		for _, p := range i.Providers {
			if !p.Active() {
				continue
			}
			if p.Total() > count {
				count = p.Total()
			}
		}
	}
	if i.Config.InputMode == "clusterbomb" || i.Config.InputMode == "sniper" {
		count = 1
		for _, p := range i.Providers {
			if !p.Active() {
				continue
			}
			count = count * p.Total()
		}
	}
	return count
}
