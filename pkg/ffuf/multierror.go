package ffuf

import (
	"fmt"
)

// Multierror 是一个用于收集多个错误的结构体
type Multierror struct {
	errors []error // 存储错误切片
}

// NewMultierror 返回一个新的 Multierror 实例
func NewMultierror() Multierror {
	return Multierror{}
}

// Add 将一个错误添加到错误集合中
// 参数:
//   - err: 需要添加到集合中的错误
func (m *Multierror) Add(err error) {
	m.errors = append(m.errors, err)
}

// ErrorOrNil 如果集合中有错误则返回包含所有错误的错误信息，否则返回 nil
// 返回值:
//   - error: 包含所有错误的格式化错误信息，如果没有错误则返回 nil
func (m *Multierror) ErrorOrNil() error {
	var errString string
	if len(m.errors) > 0 {
		// 构建包含所有错误数量和详细信息的格式化错误字符串
		errString += fmt.Sprintf("%d errors occured.\n", len(m.errors))
		for _, e := range m.errors {
			errString += fmt.Sprintf("\t* %s\n", e)
		}
		return fmt.Errorf("%s", errString)
	}
	return nil
}
