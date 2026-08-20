package caddyguard

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// WAFLogger 日志器：同步写入（与 Lua log_record 一致，日志不丢失）
//
// 对应 Lua lib.lua 的 log_record：
//   - 同步写入：io.open → write → flush → close，确保日志落盘后再返回 403
//   - 轮转：文件超过 100MB 时重命名为 .old
//   - 文件路径：{log_dir}/{YYYY-MM-DD}_waf.log
//   - JSON 格式：每行一条 JSON
//
// Go 端与 Lua 的唯一差异：Go 用 sync.Mutex 保证多 goroutine 并发安全
// （Lua 靠 OpenResty 单 worker 模型天然串行，无需锁）
type WAFLogger struct {
	logDir string

	mu       sync.Mutex // 保护并发写入
	file     *os.File
	fileDate string // 当前文件日期 YYYY-MM-DD
	fileSize int64  // 当前文件大小

	// 轮转节流：避免每次写入都 stat 文件大小
	// 对应 Lua 的 log_last_rotation_time（每 60s 检查一次）
	lastRotationCheck int64 // Unix 秒
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

// NewWAFLogger 创建日志器
func NewWAFLogger(logDir string) *WAFLogger {
	return &WAFLogger{
		logDir: logDir,
	}
}

// Record 同步写入日志（不丢失）
// 对应 Lua 的 log_record：同步 open → write → flush → close
// 仅在攻击检测命中时调用，正常流量零开销
func (l *WAFLogger) Record(method, reqURL, reqData, ruleTag, clientIP string, r *http.Request, cfg Config) {
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

	l.write(entry)
}

// write 同步写入单条日志
// 复用文件句柄，仅在日期变化或文件轮转时重新打开
// 对应 Lua：io.open(LOG_NAME, "a") → file:write → file:flush → file:close
func (l *WAFLogger) write(entry LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	dateStr := now.Format("2006-01-02")
	nowUnix := now.Unix()

	// 日期变化 → 关闭旧文件，打开新文件
	if l.fileDate != dateStr {
		l.closeFile()
		l.fileDate = dateStr
		l.fileSize = 0
	}

	logPath := filepath.Join(l.logDir, dateStr+"_waf.log")

	// 轮转节流：每 60s 检查一次文件大小（对应 Lua 的 log_last_rotation_time）
	if l.file == nil {
		// 文件未打开 → 检查是否需要轮转，然后打开
		if info, err := os.Stat(logPath); err == nil {
			l.fileSize = info.Size()
		}
		if l.fileSize > 100*1024*1024 { // 100MB
			os.Rename(logPath, logPath+".old")
			l.fileSize = 0
		}
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return
		}
		l.file = f
		l.lastRotationCheck = nowUnix
	} else if nowUnix-l.lastRotationCheck > 60 {
		// 每 60s 检查一次文件大小是否超过 100MB
		l.lastRotationCheck = nowUnix
		if l.fileSize > 100*1024*1024 {
			l.closeFile()
			os.Rename(logPath, logPath+".old")
			l.fileSize = 0
			f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				return
			}
			l.file = f
		}
	}

	// 同步写入 + flush（对应 Lua 的 file:write + file:flush）
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

// Close 关闭日志器（关闭文件句柄）
func (l *WAFLogger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeFile()
}
