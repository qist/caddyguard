package caddyguard

import (
	"io"
	"net/http"
	"strings"
)

// fileUploadCheck 文件上传检测（multipart header 级别）
// 不完整读取 body，仅解析 multipart header 中的 filename，对 filename 执行规则匹配
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

	// 使用 multipart.Reader 流式解析，只读 header 不读文件内容
	reader, err := r.MultipartReader()
	if err != nil {
		return false
	}

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
			g.logger.Record("FileUpload", r.URL.RequestURI(), filename, matched.Raw, g.getClientIP(r, cfg), r, cfg)
			g.wafOutput(w, cfg)
			return true
		}

		// 不需要读取文件内容，直接关闭
		part.Close()
	}

	return false
}
