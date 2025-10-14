package ffuf

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Job ties together Config, Runner, Input and Output
type Job struct {
	AuditLogger          AuditLogger    // 审计日志记录器，用于记录请求和响应的审计信息
	Config               *Config        // 任务配置信息
	ErrorMutex           sync.Mutex     // 错误相关字段的互斥锁，保护错误计数器的并发访问
	Input                InputProvider  // 输入提供者，负责处理输入数据
	Runner               RunnerProvider // 运行器，负责执行主要任务逻辑
	ReplayRunner         RunnerProvider // 重放运行器，用于重放请求
	Scraper              Scraper        // 数据抓取器
	Output               OutputProvider // 输出提供者，处理任务输出结果
	Jobhash              string         // 任务哈希值，用于唯一标识任务
	Counter              int            // 已处理的项目计数器
	ErrorCounter         int            // 错误计数器
	SpuriousErrorCounter int            // 伪错误计数器
	Total                int            // 总项目数
	Running              bool           // 标识任务是否正在运行
	RunningJob           bool           // 标识当前任务作业是否正在运行
	Paused               bool           // 标识任务是否已暂停
	Count403             int            // HTTP 403状态码计数器
	Count429             int            // HTTP 429状态码计数器
	Error                string         // 存储错误信息
	Rate                 *RateThrottle  // 速率限制控制器
	startTime            time.Time      // 任务开始时间
	startTimeJob         time.Time      // 当前任务作业开始时间
	queuejobs            []QueueJob     // 任务队列，存储待处理的任务
	queuepos             int            // 队列位置指针
	skipQueue            bool           // 是否跳过队列标志
	currentDepth         int            // 当前递归深度
	calibMutex           sync.Mutex     // 校准互斥锁
	pauseWg              sync.WaitGroup // 暂停等待组，用于控制任务暂停和恢复
}

// QueueJob 表示队列中的一个任务，包含URL、深度信息和请求详情
type QueueJob struct {
	Url   string  // 目标URL地址
	depth int     // 递归深度层级
	req   Request // 请求对象，包含请求的详细信息
}

// NewJob 创建一个新的Job实例，使用提供的配置初始化
// 该函数会将所有作业字段初始化为默认值，并返回指向创建的作业的指针
//
// 参数:
//   - conf: 指向Config结构体的指针，包含作业配置设置
//
// 返回值:
//   - *Job: 指向新创建的Job实例的指针
func NewJob(conf *Config) *Job {
	var j Job
	j.Config = conf                   // 设置配置信息
	j.Counter = 0                     // 初始化计数器
	j.ErrorCounter = 0                // 初始化错误计数器
	j.SpuriousErrorCounter = 0        // 初始化虚假错误计数器
	j.Running = false                 // 初始化运行状态为false
	j.RunningJob = false              // 初始化作业运行状态为false
	j.Paused = false                  // 初始化暂停状态为false
	j.queuepos = 0                    // 初始化队列位置为0
	j.queuejobs = make([]QueueJob, 0) // 初始化队列任务为空切片
	j.currentDepth = 0                // 初始化当前深度为0
	j.Rate = NewRateThrottle(conf)    // 创建新的速率限制器
	j.skipQueue = false               // 初始化跳过队列标志为false
	return &j                         // 返回作业指针
}

// incError 增加错误计数器
//
// 此函数通过获取 ErrorMutex 锁来安全地增加通用错误计数器和虚假错误计数器，
// 确保在多线程环境下对计数器的访问是线程安全的。
//
// 参数:
//   - j: 指向包含错误计数器和互斥锁的 Job 结构体的指针
func (j *Job) incError() {
	j.ErrorMutex.Lock()         // 获取错误互斥锁
	defer j.ErrorMutex.Unlock() // 函数结束时释放错误互斥锁
	j.ErrorCounter++            // 增加错误计数器
	j.SpuriousErrorCounter++    // 增加虚假错误计数器
}

// inc403 增加403响应计数器
// 该函数通过获取ErrorMutex锁来安全地增加Count403计数器，
// 确保在多线程环境下的线程安全访问。
//
// 参数:
//   - j: 指向Job结构体的指针，包含403计数器和互斥锁
func (j *Job) inc403() {
	j.ErrorMutex.Lock()         // 获取错误互斥锁
	defer j.ErrorMutex.Unlock() // 函数结束时释放错误互斥锁
	j.Count403++                // 增加403响应计数器
}

// inc429 增加429响应计数器
// 该函数用于跟踪作业执行期间收到的429(请求过多)HTTP响应数量。
// 通过使用ErrorMutex确保线程安全。
//
// 参数:
//   - j: 指向包含计数器和互斥锁的Job结构体的指针
func (j *Job) inc429() {
	// 获取锁以确保429计数器的线程安全增加
	j.ErrorMutex.Lock()
	defer j.ErrorMutex.Unlock()
	j.Count429++
}

// resetSpuriousErrors 重置虚假错误计数器
//
// 该函数用于将任务中的虚假错误计数器重置为零。
// 通过获取 ErrorMutex 锁来保证对 SpuriousErrorCounter 字段的线程安全访问。
//
// 参数:
//   - j: 指向需要重置计数器的 Job 结构体实例
func (j *Job) resetSpuriousErrors() {
	j.ErrorMutex.Lock()
	defer j.ErrorMutex.Unlock()
	j.SpuriousErrorCounter = 0
}

// DeleteQueueItem 通过索引从队列中删除一个递归任务
//
// 该函数根据提供的索引位置删除队列中的任务项。索引值是相对于当前队列位置的相对位置。
//
// 参数:
//   - index: 要删除的任务在队列中的位置索引（相对于当前队列位置）
func (j *Job) DeleteQueueItem(index int) {
	// 调整索引以考虑当前队列位置
	index = j.queuepos + index - 1
	// 通过连接索引前后的切片来移除指定索引位置的任务
	j.queuejobs = append(j.queuejobs[:index], j.queuejobs[index+1:]...)
}

// QueuedJobs 返回队列中待处理的递归任务切片
//
// 该函数返回从当前队列位置开始到队列末尾的所有排队任务。
// 提供对所有等待处理的队列任务的访问。
//
// 返回值:
//   - []QueueJob: 从当前队列位置到队列末尾的排队任务切片
func (j *Job) QueuedJobs() []QueueJob {
	return j.queuejobs[j.queuepos-1:]
}

// Start 启动作业的执行
//
// 该函数负责初始化并启动整个作业的执行流程。它会根据配置设置初始状态，
// 处理不同的输入模式，建立作业队列，并管理作业的完整执行周期。
//
// 主要功能包括：
// 1. 如果尚未设置，则记录作业开始时间
// 2. 根据输入模式（sniper模式或其他模式）创建基础请求
// 3. 初始化作业队列，添加相应的请求任务
// 4. 设置中断信号监控，确保程序能优雅退出
// 5. 循环处理队列中的所有作业直到完成
// 6. 最后执行输出终结操作并处理可能发生的错误
func (j *Job) Start() {
	// 如果startTime还未设置，则将其设置为当前时间
	if j.startTime.IsZero() {
		j.startTime = time.Now()
	}

	// 根据配置创建基础请求
	basereq := BaseRequest(j.Config)

	// 根据不同的输入模式处理请求队列
	if j.Config.InputMode == "sniper" {
		// sniper模式：处理多个载荷位置，为每个位置创建一个队列作业
		reqs := SniperRequests(&basereq, j.Config.InputProviders[0].Template)
		for _, r := range reqs {
			j.queuejobs = append(j.queuejobs, QueueJob{Url: j.Config.Url, depth: 0, req: r})
		}
		// 总请求数等于输入总数乘以请求的数量
		j.Total = j.Input.Total() * len(reqs)
	} else {
		// 默认模式：将默认作业添加到作业队列中
		j.queuejobs = append(j.queuejobs, QueueJob{Url: j.Config.Url, depth: 0, req: BaseRequest(j.Config)})
		j.Total = j.Input.Total()
	}

	// 初始化随机数种子
	rand.Seed(time.Now().UnixNano())
	// 函数退出时确保停止作业
	defer j.Stop()

	// 设置作业运行状态
	j.Running = true
	j.RunningJob = true

	// 如果不是静默模式则显示横幅
	if !j.Config.Quiet {
		j.Output.Banner()
	}

	// 监控SIGTERM信号，确保能够正确清理（如写入输出文件等）
	j.interruptMonitor()

	// 循环处理队列中的所有作业直到完成
	for j.jobsInQueue() {
		j.prepareQueueJob()
		j.Reset(true)
		j.RunningJob = true
		j.startExecution()
	}

	// 最终化输出并处理可能发生的错误
	err := j.Output.Finalize()
	if err != nil {
		j.Output.Error(err.Error())
	}
}

// Reset 重置作业的计数器和词表位置
//
// 该函数用于重置作业的状态，包括：
// - 重置输入提供者的词表位置到初始状态
// - 将处理计数器清零
// - 重置跳过队列标志
// - 更新作业开始时间为当前时间
// - 根据cycle参数决定是循环输出还是完全重置输出
//
// 参数:
//   - cycle: 布尔值，如果为true则循环输出，否则重置输出
func (j *Job) Reset(cycle bool) {
	j.Input.Reset()             // 重置输入提供者的词表位置
	j.Counter = 0               // 清零处理计数器
	j.skipQueue = false         // 重置跳过队列标志
	j.startTimeJob = time.Now() // 更新作业开始时间为当前时间
	if cycle {
		j.Output.Cycle() // 循环输出
	} else {
		j.Output.Reset() // 重置输出
	}
}

// jobsInQueue 检查队列中是否还有待处理的任务
//
// 该函数通过比较当前队列位置指针和队列总长度来判断是否还有未处理的任务。
// 当队列位置小于队列长度时，表示还有任务等待处理。
//
// 返回值:
//   - bool: 如果还有任务在队列中则返回true，否则返回false
func (j *Job) jobsInQueue() bool {
	return j.queuepos < len(j.queuejobs)
}

// prepareQueueJob 准备队列中的下一个作业
// 该函数从队列中获取下一个作业，更新当前作业的URL和深度，
// 检查新作业中包含的关键字，并相应地激活或禁用输入提供者
func (j *Job) prepareQueueJob() {
	// 从队列中获取下一个作业的URL和深度信息
	j.Config.Url = j.queuejobs[j.queuepos].Url
	j.currentDepth = j.queuejobs[j.queuepos].depth

	// 查找新排队作业中存在的所有关键字
	kws := j.Input.Keywords()
	found_kws := make([]string, 0)
	for _, k := range kws {
		if RequestContainsKeyword(j.queuejobs[j.queuepos].req, k) {
			found_kws = append(found_kws, k)
		}
	}

	// 根据找到的关键字激活或禁用相应的输入提供者
	j.Input.ActivateKeywords(found_kws)

	// 更新队列位置并写入历史记录
	j.queuepos += 1
	j.Jobhash, _ = WriteHistoryEntry(j.Config)
}

// SkipQueue 允许跳过当前作业并前进到下一个排队的递归作业
//
// 此函数将 skipQueue 标志设置为 true，表示应该跳过当前作业，
// 而是处理队列中的下一个作业。
//
// 参数:
//   - j: 指向将被修改的 Job 实例的指针
func (j *Job) SkipQueue() {
	j.skipQueue = true
}

// sleepIfNeeded 根据配置决定是否需要睡眠一段时间
//
// 该函数检查 Job 的延迟配置，如果配置了延迟则执行相应的睡眠逻辑。
// 支持固定延迟和范围延迟两种模式，并且睡眠过程可以被上下文取消。
func (j *Job) sleepIfNeeded() {
	var sleepDuration time.Duration

	// 根据配置计算需要睡眠的时长
	if j.Config.Delay.HasDelay {
		if j.Config.Delay.IsRange {
			// 如果是范围延迟，生成范围内的随机睡眠时间
			// 在最小延迟和最大延迟之间生成一个随机值
			sTime := j.Config.Delay.Min + rand.Float64()*(j.Config.Delay.Max-j.Config.Delay.Min)
			sleepDuration = time.Duration(sTime * 1000)
		} else {
			// 如果是固定延迟，使用最小延迟时间
			sleepDuration = time.Duration(j.Config.Delay.Min * 1000)
		}
		// 将睡眠时间转换为毫秒单位
		sleepDuration = sleepDuration * time.Millisecond
	}

	// 使睡眠过程可以被上下文取消
	// 通过select语句监听上下文取消信号和计时器信号
	select {
	case <-j.Config.Context.Done(): // 被上下文取消
	case <-time.After(sleepDuration): // 睡眠结束
	}
}

// Pause 暂停作业进程
//
// 该函数用于暂停当前作业的执行。它会设置作业的暂停状态为true，
// 向暂停等待组添加一个计数，并输出暂停信息。
// 如果作业已经处于暂停状态，则不执行任何操作。
func (j *Job) Pause() {
	// 只有在作业未暂停时才执行暂停操作
	if !j.Paused {
		j.Paused = true                        // 设置暂停状态为true
		j.pauseWg.Add(1)                       // 向暂停等待组添加计数
		j.Output.Info("------ PAUSING ------") // 输出暂停信息
	}
}

// Resume 恢复作业进程
//
// 该函数用于恢复之前暂停的作业。它会将作业的暂停状态设置为false，
// 输出一条恢复信息，并调用pauseWg.Done()来通知等待组作业已恢复。
//
// 参数:
//   - j: 指向需要恢复的Job结构体实例的指针
func (j *Job) Resume() {
	if j.Paused {
		j.Paused = false                       // 将暂停状态设置为false
		j.Output.Info("------ RESUMING -----") // 输出恢复信息
		j.pauseWg.Done()                       // 通知等待组作业已恢复
	}
}

// startExecution 启动任务执行流程，包括并发控制、速率限制和任务分发。
// 该函数会根据配置启动后台任务，并处理输入队列中的每个条目。
func (j *Job) startExecution() {
	var wg sync.WaitGroup
	wg.Add(1)
	go j.runBackgroundTasks(&wg)

	// 当开始一个新的递归或sniper队列任务时，打印基础URL信息
	if j.queuepos > 1 {
		if j.Config.InputMode == "sniper" {
			j.Output.Info(fmt.Sprintf("Starting queued sniper job (%d of %d) on target: %s", j.queuepos, len(j.queuejobs), j.Config.Url))
		} else {
			j.Output.Info(fmt.Sprintf("Starting queued job on target: %s", j.Config.Url))
		}
	}

	// 创建线程限制通道，用于控制最大并发数
	threadlimiter := make(chan bool, j.Config.Threads)

	// 遍历所有输入项并启动协程执行任务
	for j.Input.Next() && !j.skipQueue {
		// 检查是否应该停止处理
		j.CheckStop()

		if !j.Running {
			defer j.Output.Warning(j.Error)
			break
		}
		j.pauseWg.Wait()
		// 控制并发数量
		threadlimiter <- true
		// 等待速率控制器允许继续
		<-j.Rate.RateLimiter.C
		nextInput := j.Input.Value()
		nextPosition := j.Input.Position()
		// 添加FFUFHASH字段到输入数据中
		nextInput["FFUFHASH"] = j.ffufHash(nextPosition)

		wg.Add(1)
		j.Counter++

		// 启动一个协程来执行具体任务
		go func() {
			defer func() { <-threadlimiter }()
			defer wg.Done()
			threadStart := time.Now()
			j.runTask(nextInput, nextPosition, false)
			j.sleepIfNeeded()
			threadEnd := time.Now()
			j.Rate.Tick(threadStart, threadEnd)
		}()
		if !j.RunningJob {
			defer j.Output.Warning(j.Error)
			return
		}
	}
	wg.Wait()
	j.updateProgress()
}

// interruptMonitor 监听系统中断信号（如Ctrl-C），并在接收到时暂停或停止任务。
// 该函数会在接收到中断信号后恢复暂停状态并调用Stop方法。
func (j *Job) interruptMonitor() {
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range sigChan {
			j.Error = "Caught keyboard interrupt (Ctrl-C)\n"
			// 如果当前是暂停状态，则恢复
			if j.Paused {
				j.pauseWg.Done()
			}
			// 停止任务执行
			j.Stop()
		}
	}()
}

// runBackgroundTasks 在后台定期更新进度信息。
// 该函数会在任务运行期间持续更新进度直到任务完成或被取消。
// 参数:
//   - wg: 用于同步等待的WaitGroup指针
func (j *Job) runBackgroundTasks(wg *sync.WaitGroup) {
	defer wg.Done()
	totalProgress := j.Input.Total()
	for j.Counter <= totalProgress && !j.skipQueue {
		j.pauseWg.Wait()
		if !j.Running {
			break
		}
		j.updateProgress()
		if j.Counter == totalProgress {
			return
		}
		if !j.RunningJob {
			return
		}
		time.Sleep(time.Millisecond * time.Duration(j.Config.ProgressFrequency))
	}
}

// updateProgress 更新并输出当前任务进度信息。
// 该函数构造一个Progress结构体并将其传递给输出模块进行显示。
func (j *Job) updateProgress() {
	prog := Progress{
		StartedAt:  j.startTimeJob,
		ReqCount:   j.Counter,
		ReqTotal:   j.Input.Total(),
		ReqSec:     j.Rate.CurrentRate(),
		QueuePos:   j.queuepos,
		QueueTotal: len(j.queuejobs),
		ErrorCount: j.ErrorCounter,
	}
	j.Output.Progress(prog)
}

// isMatch 判断响应是否匹配预设的匹配器和过滤器规则。
// 该函数首先检查匹配器是否满足条件，然后应用过滤器进行进一步筛选。
// 参数:
//   - resp: 待检查的响应对象
//
// 返回值:
//   - bool: 如果响应匹配则返回true，否则返回false
func (j *Job) isMatch(resp Response) bool {
	matched := false
	var matchers map[string]FilterProvider
	var filters map[string]FilterProvider
	if j.Config.AutoCalibrationPerHost {
		filters = j.Config.MatcherManager.FiltersForDomain(HostURLFromRequest(*resp.Request))
	} else {
		filters = j.Config.MatcherManager.GetFilters()
	}
	matchers = j.Config.MatcherManager.GetMatchers()

	// 检查所有匹配器
	for _, m := range matchers {
		match, err := m.Filter(&resp)
		if err != nil {
			continue
		}
		if match {
			matched = true
		} else if j.Config.MatcherMode == "and" {
			// 在"and"模式下，任何一个不匹配就直接返回false
			return false
		}
	}
	// 如果没有匹配任何匹配器，则直接返回false
	if !matched {
		return false
	}

	// 应用过滤器
	for _, f := range filters {
		fv, err := f.Filter(&resp)
		if err != nil {
			continue
		}
		if fv {
			if j.Config.FilterMode == "or" {
				// 在"or"模式下，一旦有匹配就返回false（排除）
				return false
			}
		} else {
			if j.Config.FilterMode == "and" {
				// 在"and"模式下，一旦有不匹配就返回true（保留）
				return true
			}
		}
	}

	// 如果是"and"模式且所有过滤器都匹配了，则排除该响应
	if len(filters) > 0 && j.Config.FilterMode == "and" {
		return false
	}
	return true
}

// ffufHash 生成基于位置的哈希值，用于标识特定请求。
// 该函数结合任务哈希前五位字符与当前位置的十六进制表示生成唯一标识。
// 参数:
//   - pos: 当前输入的位置索引
//
// 返回值:
//   - []byte: 生成的哈希字节切片
func (j *Job) ffufHash(pos int) []byte {
	hashstring := ""
	r := []rune(j.Jobhash)
	if len(r) > 5 {
		hashstring = string(r[:5])
	}
	hashstring += fmt.Sprintf("%x", pos)
	return []byte(hashstring)
}

// runTask 执行单个任务，处理请求准备、执行、错误处理、审计和结果处理等完整流程
//
// 该函数负责执行ffuf的核心 fuzzing 任务。它接收输入数据，构建HTTP请求，
// 发送请求并处理响应，同时处理各种特殊情况如错误重试、超时、递归等。
//
// 参数:
//   - input: 包含fuzzing输入数据的映射，键为位置名称，值为实际数据
//   - position: 当前任务在输入队列中的位置索引
//   - retried: 标识是否为重试执行，避免无限重试
func (j *Job) runTask(input map[string][]byte, position int, retried bool) {
	// 获取当前队列任务的基础请求模板
	basereq := j.queuejobs[j.queuepos-1].req

	// 使用输入数据和基础请求准备实际要发送的请求
	req, err := j.Runner.Prepare(input, &basereq)

	// 设置请求的时间戳和位置信息
	req.Timestamp = time.Now()
	req.Position = position

	// 如果请求准备过程中出现错误，记录错误并返回
	if err != nil {
		j.Output.Error(fmt.Sprintf("Encountered an error while preparing request: %s\n", err))
		j.incError()
		log.Printf("%s", err)
		return
	}

	// 执行准备好的请求
	resp, err := j.Runner.Execute(&req)
	if err != nil {
		// 如果执行出错，将错误信息保存到请求对象中
		req.Error = err.Error()
	}

	// 在请求发送后进行审计记录，以便捕获请求在传输过程中的任何变化
	if j.AuditLogger != nil {
		e := j.AuditLogger.Write(&req)
		if e != nil {
			j.Output.Error(fmt.Sprintf("Encountered error while writing request audit log: %s\n", e))
		}
	}

	// 处理执行过程中出现的错误
	if err != nil {
		if retried {
			// 如果已经是重试执行仍然失败，则增加错误计数器
			j.incError()
			log.Printf("%s", err)
		} else {
			// 第一次失败则尝试重试执行
			j.runTask(input, position, true)
		}

		// 特殊处理超时错误，当使用"time"匹配器或过滤器时提供详细信息
		if os.IsTimeout(err) {
			// 检查是否有"time"匹配器激活
			for name := range j.Config.MatcherManager.GetMatchers() {
				if name == "time" {
					// 构建输入信息字符串用于输出
					inputmsg := ""
					for k, v := range input {
						inputmsg = inputmsg + fmt.Sprintf("%s : %s  // ", k, v)
					}
					j.Output.Info("Timeout while 'time' matcher is active: " + inputmsg)
					return
				}
			}

			// 检查是否有"time"过滤器激活
			for name := range j.Config.MatcherManager.GetFilters() {
				if name == "time" {
					// 构建输入信息字符串用于输出
					inputmsg := ""
					for k, v := range input {
						inputmsg = inputmsg + fmt.Sprintf("%s : %s  // ", k, v)
					}
					j.Output.Info("Timeout while 'time' filter is active: " + inputmsg)
					return
				}
			}
		}
		return
	}

	// 在错误处理完成后对响应进行审计记录
	if j.AuditLogger != nil {
		err = j.AuditLogger.Write(&resp)
		if err != nil {
			j.Output.Error(fmt.Sprintf("Encountered error while writing response audit log: %s\n", err))
		}
	}

	// 如果之前有虚假错误，现在重置计数器
	if j.SpuriousErrorCounter > 0 {
		j.resetSpuriousErrors()
	}

	// 根据配置检查是否需要因403状态码而停止
	if j.Config.StopOn403 || j.Config.StopOnAll {
		// 如果响应状态码为403，增加403计数器
		if resp.StatusCode == 403 {
			j.inc403()
		}
	}

	// 根据配置检查是否需要因429状态码而停止
	if j.Config.StopOnAll {
		// 如果响应状态码为429，增加429计数器
		if resp.StatusCode == 429 {
			j.inc429()
		}
	}

	// 等待可能的暂停操作完成
	j.pauseWg.Wait()

	// 处理自动校准，必须在实际请求之后进行以确保req.Host值正确
	_ = j.CalibrateIfNeeded(HostURLFromRequest(req), input)

	// 处理抓取器动作（如果配置了抓取器）
	if j.Scraper != nil {
		// 执行抓取器并处理结果
		for _, sres := range j.Scraper.Execute(&resp, j.isMatch(resp)) {
			resp.ScraperData[sres.Name] = sres.Results
			j.handleScraperResult(&resp, sres)
		}
	}

	// 检查响应是否匹配预设条件
	if j.isMatch(resp) {
		// 如果配置了重放运行器，则重新发送请求用于记录
		if j.ReplayRunner != nil {
			replayreq, err := j.ReplayRunner.Prepare(input, &basereq)
			replayreq.Position = position
			if err != nil {
				j.Output.Error(fmt.Sprintf("Encountered an error while preparing replayproxy request: %s\n", err))
				j.incError()
				log.Printf("%s", err)
			} else {
				// 执行重放请求
				_, _ = j.ReplayRunner.Execute(&replayreq)
			}
		}

		// 输出匹配的结果
		j.Output.Result(resp)

		// 因为输出了结果，刷新进度指示器
		j.updateProgress()

		// 如果启用了递归且策略为"greedy"，处理贪婪递归任务
		if j.Config.Recursion && j.Config.RecursionStrategy == "greedy" {
			j.handleGreedyRecursionJob(resp)
		}
	} else {
		// 如果响应不匹配但抓取器找到了数据，仍然输出结果
		if len(resp.ScraperData) > 0 {
			j.Output.Result(resp)
		}
	}

	// 如果启用了递归且策略为"default"，并且存在重定向，则处理默认递归任务
	if j.Config.Recursion && j.Config.RecursionStrategy == "default" && len(resp.GetRedirectLocation(false)) > 0 {
		j.handleDefaultRecursionJob(resp)
	}
}

// handleScraperResult 处理抓取器执行结果
//
// 该函数根据抓取器返回的操作类型执行相应处理，目前支持"output"操作。
//
// 参数:
//   - resp: 响应对象指针，用于存储抓取结果
//   - sres: 抓取器执行结果
func (j *Job) handleScraperResult(resp *Response, sres ScraperResult) {
	// 遍历抓取器结果中的所有操作
	for _, a := range sres.Action {
		switch a {
		case "output":
			// 对于"output"操作，将抓取结果存储到响应的ScraperData中
			resp.ScraperData[sres.Name] = sres.Results
		}
	}
}

// handleGreedyRecursionJob 处理贪婪递归任务，当未达到最大递归深度时将新的递归任务添加到队列中
//
// 该函数实现贪婪递归策略。在贪婪模式下，每个匹配的响应都会触发一个新的递归任务，
// 而不考虑是否是目录。函数会在递归深度限制内创建新的队列任务。
//
// 参数:
//   - resp: 包含请求信息的响应对象，用于构建递归URL
func (j *Job) handleGreedyRecursionJob(resp Response) {
	// 处理贪婪递归策略。在调用handleRecursionJob之前已经确定了匹配结果
	if j.Config.RecursionDepth == 0 || j.currentDepth < j.Config.RecursionDepth {
		// 当未达到递归深度限制时，构造递归URL并创建新的队列任务
		recUrl := resp.Request.Url + "/" + "FUZZ"
		newJob := QueueJob{Url: recUrl, depth: j.currentDepth + 1, req: RecursionRequest(j.Config, recUrl)}
		j.queuejobs = append(j.queuejobs, newJob)
		j.Output.Info(fmt.Sprintf("Adding a new job to the queue: %s", recUrl))
	} else {
		// 当达到最大递归深度时，输出警告信息并忽略该递归任务
		j.Output.Warning(fmt.Sprintf("Maximum recursion depth reached. Ignoring: %s", resp.Request.Url))
	}
}

// handleDefaultRecursionJob 处理默认递归任务，在发现新目录且未达到最大递归深度时将新的递归任务添加到任务队列中
//
// 该函数实现默认递归策略。只有当响应表明是一个目录（通过重定向位置判断）时，
// 才会创建新的递归任务。这与贪婪递归不同，贪婪递归会为每个匹配项创建递归任务。
//
// 参数:
//   - resp: 包含HTTP响应信息的Response对象，用于判断是否为目录以及构建递归URL
func (j *Job) handleDefaultRecursionJob(resp Response) {
	// 构造递归URL，在当前请求URL后添加"/FUZZ"
	recUrl := resp.Request.Url + "/" + "FUZZ"

	// 检查响应是否表示一个目录
	// 通过比较请求URL加上"/"后是否与重定向位置相等来判断
	if (resp.Request.Url + "/") != resp.GetRedirectLocation(true) {
		// 不是目录，提前返回
		return
	}

	// 检查是否未达到最大递归深度
	if j.Config.RecursionDepth == 0 || j.currentDepth < j.Config.RecursionDepth {
		// 尚未达到最大递归深度
		// 创建新的队列任务并添加到任务队列中
		newJob := QueueJob{Url: recUrl, depth: j.currentDepth + 1, req: RecursionRequest(j.Config, recUrl)}
		j.queuejobs = append(j.queuejobs, newJob)
		j.Output.Info(fmt.Sprintf("Adding a new job to the queue: %s", recUrl))
	} else {
		// 已达到最大递归深度，记录警告信息并忽略该目录
		j.Output.Warning(fmt.Sprintf("Directory found, but recursion depth exceeded. Ignoring: %s", resp.GetRedirectLocation(true)))
	}
}

// CheckStop 检查是否满足停止作业的条件，如果满足则停止作业或继续下一个作业
//
// 该函数会根据多种条件判断是否应该停止当前的fuzzing作业，包括错误率、响应码比例
// 和最大运行时间限制等。当满足任何停止条件时，会相应地调用Stop或Next方法。
func (j *Job) CheckStop() {
	// 只有在收集了足够多的样本（超过50个请求）后才评估停止条件
	if j.Counter > 50 {
		// 如果启用了StopOn403或StopOnAll配置，检查403响应比例是否过高
		if j.Config.StopOn403 || j.Config.StopOnAll {
			// 如果403响应占比超过95%，则停止作业
			if float64(j.Count403)/float64(j.Counter) > 0.95 {
				// 超过95%的请求返回403状态码
				j.Error = "Getting an unusual amount of 403 responses, exiting."
				j.Stop()
			}
		}
		// 如果启用了StopOnErrors或StopOnAll配置，检查错误数量是否过多
		if j.Config.StopOnErrors || j.Config.StopOnAll {
			// 如果虚假错误计数器超过线程数的两倍，则停止作业
			if j.SpuriousErrorCounter > j.Config.Threads*2 {
				// 大部分请求都出现错误
				j.Error = "Receiving spurious errors, exiting."
				j.Stop()
			}

		}
		// 如果启用了StopOnAll配置，检查429响应比例是否过高
		if j.Config.StopOnAll && (float64(j.Count429)/float64(j.Counter) > 0.2) {
			// 如果429响应占比超过20%，则停止作业
			j.Error = "Getting an unusual amount of 429 responses, exiting."
			j.Stop()
		}
	}

	// 检查整个进程的最大运行时间限制
	if j.Config.MaxTime > 0 {
		dur := time.Since(j.startTime)
		runningSecs := int(dur / time.Second)
		// 如果运行时间超过设定的最大时间，则停止整个进程
		if runningSecs >= j.Config.MaxTime {
			j.Error = "Maximum running time for entire process reached, exiting."
			j.Stop()
		}
	}

	// 检查当前作业的最大运行时间限制
	if j.Config.MaxTimeJob > 0 {
		dur := time.Since(j.startTimeJob)
		runningSecs := int(dur / time.Second)
		// 如果当前作业运行时间超过设定的最大时间，则继续下一个作业（如果存在）
		if runningSecs >= j.Config.MaxTimeJob {
			j.Error = "Maximum running time for this job reached, continuing with next job if one exists."
			j.Next()

		}
	}
}

// Stop 停止作业的执行
//
// 该函数用于停止当前正在进行的fuzzing作业。它会将作业的运行状态设置为false，
// 并调用配置中的取消函数来终止所有正在进行的操作。
//
// 参数:
//   - j: 指向需要停止的Job结构体实例的指针
func (j *Job) Stop() {
	j.Running = false // 将运行状态设置为false，表示作业已停止
	j.Config.Cancel() // 调用配置中的取消函数，终止相关操作
}

// Next 停止当前作业并继续到下一个作业
//
// 该函数用于停止当前正在执行的作业，并将 [RunningJob](file://E:\Source\TestScript\GoProjects\ffuf\pkg\ffuf\job.go#L29-L29) 标志设置为 false，
// 表示当前作业已停止运行，系统将自动继续处理队列中的下一个作业（如果存在）。
//
// 参数:
//   - j: 指向需要停止当前作业的 Job 结构体实例的指针
func (j *Job) Next() {
	j.RunningJob = false // 将当前作业运行状态设置为false，表示当前作业已停止
}
