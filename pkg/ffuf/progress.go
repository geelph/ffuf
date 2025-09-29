package ffuf

import (
	"time"
)

// Progress 结构体用于跟踪和记录任务执行进度信息
// 包含时间、请求数量、队列位置、错误统计等关键进度指标
type Progress struct {
	StartedAt  time.Time // StartedAt 表示任务开始执行的时间戳
	ReqCount   int       // ReqCount 表示已完成的请求数量
	ReqTotal   int       // ReqTotal 表示总请求数量
	ReqSec     int64     // ReqSec 表示每秒处理的请求数
	QueuePos   int       // QueuePos 表示当前在队列中的位置
	QueueTotal int       // QueueTotal 表示队列中总的项目数量
	ErrorCount int       // ErrorCount 表示执行过程中发生的错误数量
}
