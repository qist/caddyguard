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
// 同时对非文件表单字段值执行 post.rule 扫描（对应 Lua 扫描整个 multipart body）
// 检测完成后恢复 body 供后续 handler 使用
func (g *Guard) fileUploadCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.FileUploadCheck != "on" {
		return false
	}

	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "multipart/form-data") {
		return false
	}

	// 加载文件扩展名规则
	fileRules := g.ruleCache.GetRule("fileext.rule", cfg.RuleDir)

	// 加载 POST 规则（用于扫描非文件表单字段值）
	var postRules []RuleEntry
	if cfg.PostCheck == "on" {
		postRules = g.ruleCache.GetRule("post.rule", cfg.RuleDir)
	}

	if len(fileRules) == 0 && len(postRules) == 0 {
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

		filename := part.FileName()

		// 1. 对 filename 进行 fileext.rule 匹配
		if filename != "" && len(fileRules) > 0 {
			if matched := matchRules(filename, fileRules, false); matched != nil {
				part.Close()
				g.logger.Record("FileUpload", reqURICached(r), filename, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
				g.wafOutput(w, cfg)
				return true
			}
		}

		// 2. 对非文件表单字段值执行 post.rule 扫描
		// 对应 Lua 版 post_attack_check 对整个 multipart body 做 post.rule 扫描
		if filename == "" && len(postRules) > 0 {
			formName := part.FormName()

			// 检查字段名
			if formName != "" {
				if matched := matchRules(formName, postRules, true); matched != nil {
					part.Close()
					g.logger.Record("POST", reqURICached(r), "field:"+formName, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
					g.wafOutput(w, cfg)
					return true
				}
			}

			// 读取字段值（限制大小 1MB）
		 fieldValueBytes, err := io.ReadAll(io.LimitReader(part, 1024*1024))
			if err == nil && len(fieldValueBytes) > 0 {
				// 检查原始值
				if matched := matchRulesBytes(fieldValueBytes, postRules, true); matched != nil {
					logData := string(fieldValueBytes)
					if len(logData) > 1024 {
						logData = logData[:1024] + "..."
					}
					g.logger.Record("POST", reqURICached(r), logData, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
					g.wafOutput(w, cfg)
					return true
				}

				// 检查解码后的值
				fieldValue := string(fieldValueBytes)
				if hasEncodeMarkers(fieldValue) {
					if decoded, changed := fullDecode(fieldValue); changed {
						if matched := matchRules(decoded, postRules, true); matched != nil {
							logData := decoded
							if len(logData) > 1024 {
								logData = logData[:1024] + "..."
							}
							g.logger.Record("POST", reqURICached(r), logData, matched.Raw, g.getClientIPCached(r, cfg), r, cfg)
							g.wafOutput(w, cfg)
							return true
						}
					}
				}
			}
		}

		part.Close()
	}

	return false
}
