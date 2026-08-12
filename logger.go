package caddyguard

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// WAFLogger 日志器：channel + worker 模式
type WAFLogger struct {
	logDir string
	queue  chan LogEntry // 日志队列（有缓冲 channel）
	done   chan struct{} // 关闭信号

	// 文件句柄缓存（worker 独占，无需额外锁）
	file     *os.File
	fileDate string // 当前文件日期 YYYY-MM-DD
	fileSize int64  // 当前文件大小
}

// LogEntry JSON 日志条目
type LogEntry struct {
	Timestamp    string `json:"@timestamp"`
	ClientIP     string `json:"client_ip"`
	LocalTime    string `json:"local_time"`
	ServerName   string `json:"server_name"`
	UserAgent    string `json:"user_agent"`
	AttackMethod string `json:"attack_method"`
	ReqURL       string `json:"req_url"`
	ReqData      string `json:"req_data"`
	RuleTag      string `json:"rule_tag"`
}

// NewWAFLogger 创建日志器并启动 worker goroutine
func NewWAFLogger(logDir string) *WAFLogger {
	l := &WAFLogger{
		logDir: logDir,
		queue:  make(chan LogEntry, 4096), // 有缓冲队列，高峰期可暂存
		done:   make(chan struct{}),
	}
	go l.worker()
	return l
}

// Record 投递日志到队列（非阻塞）
func (l *WAFLogger) Record(method, reqURL, reqData, ruleTag, clientIP string, r *http.Request, cfg Config) {
	// time.Now() 只调用一次
	now := time.Now()
	entry := LogEntry{
		Timestamp:    now.UTC().Format("2006-01-02T15:04:05Z"),
		ClientIP:     clientIP,
		LocalTime:    now.Format("2006-01-02 15:04:05"),
		ServerName:   getDomain(r),
		UserAgent:    r.UserAgent(),
		AttackMethod: method,
		ReqURL:       reqURL,
		ReqData:      reqData,
		RuleTag:      ruleTag,
	}

	// 非阻塞投递：队列满时丢弃（保护服务不因日志阻塞）
	select {
	case l.queue <- entry:
	default:
		// 队列满，丢弃日志
	}
}

// worker 单 goroutine 消费队列，串行写入文件
func (l *WAFLogger) worker() {
	for {
		select {
		case entry := <-l.queue:
			l.write(entry)
		case <-l.done:
			// 关闭前消费完队列中剩余日志
			for {
				select {
				case entry := <-l.queue:
					l.write(entry)
				default:
					l.closeFile()
					return
				}
			}
		}
	}
}

// write 写入单条日志
// 复用文件句柄，仅在日期变化或文件轮转时重新打开
func (l *WAFLogger) write(entry LogEntry) {
	now := time.Now()
	dateStr := now.Format("2006-01-02")

	// 日期变化 → 关闭旧文件，打开新文件
	if l.fileDate != dateStr {
		l.closeFile()
		l.fileDate = dateStr
		l.fileSize = 0
	}

	// 文件未打开 → 打开（或轮转后重新打开）
	if l.file == nil {
		logPath := filepath.Join(l.logDir, dateStr+"_waf.log")
		// 检查文件是否已存在并获取大小
		if info, err := os.Stat(logPath); err == nil {
			l.fileSize = info.Size()
		}
		// 轮转：超过 100MB 则重命名
		if l.fileSize > 100*1024*1024 {
			os.Rename(logPath, logPath+".old")
			l.fileSize = 0
		}
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return
		}
		l.file = f
	}

	// 写入
	jsonBytes, _ := json.Marshal(entry)
	jsonBytes = append(jsonBytes, '\n')
	n, _ := l.file.Write(jsonBytes)
	l.fileSize += int64(n)
}

// closeFile 关闭当前文件句柄
func (l *WAFLogger) closeFile() {
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
}

// Close 关闭日志器（优雅退出）
func (l *WAFLogger) Close() {
	close(l.done)
}
