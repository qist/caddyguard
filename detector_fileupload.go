package caddyguard

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

// fileUploadCheck 文件上传检测（multipart header 级别）
// 不完整读取 body，仅解析 multipart header 中的 filename，对 filename 执行规则匹配
// 检测完成后恢复 body 供后续 handler 使用
func (g *Guard) fileUploadCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.FileUploadCheck != "on" {
		return false
	}

	rules := g.ruleCache.GetRule("fileext.rule", cfg.RuleDir)
	if rules == nil {
		return false
	}

	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "multipart/form-data") {
		return false
	}

	// 读取完整 body 以便后续恢复（multipart 解析会消费 reader）
	// 限制读取大小 32MB
	maxSize := int64(32 * 1024 * 1024)
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxSize))
	r.Body.Close()
	if err != nil || len(bodyBytes) == 0 {
		return false
	}

	// 恢复 body 供后续 handler 使用
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// 使用 multipart.Reader 流式解析，只读 header 不读文件内容
	reader := multipart.NewReader(bytes.NewReader(bodyBytes), strings.TrimPrefix(contentType, "multipart/form-data; boundary="))

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		// 只检查 filename，不读取文件内容
		filename := part.FileName()
		if filename == "" {
			part.Close()
			continue
		}

		// 对 filename 进行规则匹配
		if matched := matchRules(filename, rules, false); matched != nil {
			part.Close()
			g.logger.Record("FileUpload", reqURICached(r), filename, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
			g.wafOutput(w, cfg)
			return true
		}

		// 不需要读取文件内容，直接关闭
		part.Close()
	}

	return false
}
