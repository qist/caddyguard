package caddyguard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// WAFLogger 日志器：channel + worker 模式
type WAFLogger struct {
	logDir string
	queue  chan LogEntry // 日志队列（有缓冲 channel）
	done   chan struct{} // 关闭信号
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
	entry := LogEntry{
		Timestamp:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ClientIP:     clientIP,
		LocalTime:    time.Now().Format("2006-01-02 15:04:05"),
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
					return
				}
			}
		}
	}
}

// write 写入单条日志
func (l *WAFLogger) write(entry LogEntry) {
	logFile := fmt.Sprintf("%s/%s_waf.log", l.logDir, time.Now().Format("2006-01-02"))

	// 日志轮转：超过 100MB 则重命名
	if info, err := os.Stat(logFile); err == nil {
		if info.Size() > 100*1024*1024 {
			os.Rename(logFile, logFile+".old")
		}
	}

	// 追加写入
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	jsonBytes, _ := json.Marshal(entry)
	f.Write(jsonBytes)
	f.WriteString("\n")
}

// Close 关闭日志器（优雅退出）
func (l *WAFLogger) Close() {
	close(l.done)
}
