package caddyguard

import (
	"mime"
	"net/http"
	"path/filepath"
	"strings"
)

// fileUploadCheck 文件上传检测
// 检查 multipart form 中的文件扩展名是否在黑名单中
func (g *Guard) fileUploadCheck(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if cfg.FileUploadEnable != "on" {
		return false
	}

	// 只检测 multipart/form-data
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/form-data") {
		return false
	}

	// 解析 multipart form
	// 限制内存大小 32MB，超出部分写入临时文件
	maxMemory := int64(32 << 20)
	if err := r.ParseMultipartForm(maxMemory); err != nil {
		return false
	}

	if r.MultipartForm == nil || r.MultipartForm.File == nil {
		return false
	}

	rules := g.ruleCache.GetRule("fileext.rule", cfg.RuleDir)

	for _, files := range r.MultipartForm.File {
		for _, fileHeader := range files {
			filename := fileHeader.Filename
			if filename == "" {
				continue
			}

			ext := strings.ToLower(filepath.Ext(filename))

			// 黑名单扩展名检测
			if matched := matchRules(ext, rules, false); matched != nil {
				g.logger.Record("FileUpload", r.URL.String(), filename, matched.Raw, g.getClientIP(r, cfg), r, cfg)
				if cfg.WAFMode == "block" {
					g.wafOutput(w, cfg)
				}
				return true
			}

			// 检查 Content-Type 是否与扩展名匹配
			// 防止通过修改扩展名绕过检测
			if fileHeader.Header != nil {
				declaredCT := fileHeader.Header.Get("Content-Type")
				if declaredCT != "" {
					exts, _ := mime.ExtensionsByType(declaredCT)
					if len(exts) > 0 {
						detectedExt := strings.ToLower(filepath.Ext(exts[0]))
						if detectedExt != "" && detectedExt != ext {
							g.logger.Record("FileUpload", r.URL.String(), filename, "MimeMismatch: "+declaredCT, g.getClientIP(r, cfg), r, cfg)
							if cfg.WAFMode == "block" {
								g.wafOutput(w, cfg)
							}
							return true
						}
					}
				}
			}
		}
	}
	return false
}
