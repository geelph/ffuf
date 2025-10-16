package ffuf

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type optRange struct {
	Min      float64 // 范围的最小值
	Max      float64 // 范围的最大值
	IsRange  bool    // 标识是否为范围值（true表示是范围，false表示单个值）
	HasDelay bool    // 标识是否包含延迟设置
}

type optRangeJSON struct {
	Value string `json:"value"` // 存储范围值的字符串表示
}

// MarshalJSON 实现了 json.Marshaler 接口，用于将 optRange 结构体序列化为 JSON 格式
// 根据 optRange 的值范围情况，生成相应的字符串表示：
// - 当 Min 和 Max 相等时，生成单个浮点数的字符串格式
// - 当 Min 和 Max 不相等时，生成 "最小值-最大值" 的范围格式
//
// 返回值：
//   - []byte: 序列化后的 JSON 字节切片
//   - error: 序列化过程中可能出现的错误
func (o *optRange) MarshalJSON() ([]byte, error) {
	value := ""
	if o.Min == o.Max {
		value = fmt.Sprintf("%.2f", o.Min)
	} else {
		value = fmt.Sprintf("%.2f-%.2f", o.Min, o.Max)
	}
	return json.Marshal(&optRangeJSON{
		Value: value,
	})
}

// UnmarshalJSON 实现了 json.Unmarshaler 接口，用于从 JSON 格式反序列化为 optRange 结构体
// 首先将输入的 JSON 字节切片解析为中间结构体 optRangeJSON
// 然后调用 Initialize 方法根据解析出的字符串值初始化 optRange
//
// 参数：
//   - b: 需要反序列化的 JSON 字节切片
//
// 返回值：
//   - error: 反序列化或初始化过程中可能出现的错误
func (o *optRange) UnmarshalJSON(b []byte) error {
	var inc optRangeJSON
	err := json.Unmarshal(b, &inc)
	if err != nil {
		return err
	}
	return o.Initialize(inc.Value)
}

// Initialize 根据给定的字符串值初始化 optRange 结构体
// 值可以是单个浮点数（例如："0.1"）或由短横线分隔的浮点数范围（例如："0.1-0.8"）
//
// 参数：
//   - value: 表示单个延迟值或延迟值范围的字符串
//
// 返回值：
//   - error: 如果值格式无效或浮点数解析失败则返回错误，否则返回 nil
func (o *optRange) Initialize(value string) error {
	var err, err2 error
	d := strings.Split(value, "-")

	// 验证格式并解析延迟值
	if len(d) > 2 {
		return fmt.Errorf("Delay needs to be either a single float: \"0.1\" or a range of floats, delimited by dash: \"0.1-0.8\"")
	} else if len(d) == 2 {
		// 处理范围格式（最小值-最大值）
		o.IsRange = true
		o.HasDelay = true
		o.Min, err = strconv.ParseFloat(d[0], 64)
		o.Max, err2 = strconv.ParseFloat(d[1], 64)
		if err != nil || err2 != nil {
			return fmt.Errorf("Delay range min and max values need to be valid floats. For example: 0.1-0.5")
		}
	} else if len(value) > 0 {
		// 处理单个值格式
		o.IsRange = false
		o.HasDelay = true
		o.Min, err = strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("Delay needs to be either a single float: \"0.1\" or a range of floats, delimited by dash: \"0.1-0.8\"")
		}
	}
	return nil
}
