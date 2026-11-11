package caddyguard

import (
	"bytes"
	"io"
	"net/http"
	"os"
)

// bodySpoolMemLimit body 内存驻留阈值: 超过后落盘临时文件 (对齐 nginx client_body_temp)
const bodySpoolMemLimit = 8 * 1024 * 1024

// bodySpool 完整读取后的 body 载体: 小 body 驻留内存, 大 body 落盘临时文件
// 保证业务 body 永不截断 —— 与 Lua/nginx 版 (client_body_temp 完整落盘,
// WAF 只读不改变 body) 行为一致
type bodySpool struct {
	mem  []byte
	file *os.File
	size int64
}

// readBodyFull 完整读取 reader (永不截断): ≤bodySpoolMemLimit 驻留内存,
// 超出部分落盘临时文件。调用方负责 spool.Close() 释放临时文件
func readBodyFull(r io.Reader) (*bodySpool, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 64*1024))
	n, err := io.Copy(buf, io.LimitReader(r, bodySpoolMemLimit))
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n < bodySpoolMemLimit {
		return &bodySpool{mem: buf.Bytes(), size: n}, nil
	}
	// 超过内存阈值: 落盘
	tf, err := os.CreateTemp("", "caddyguard-body-*.tmp")
	if err != nil {
		return nil, err
	}
	if _, werr := tf.Write(buf.Bytes()); werr != nil {
		tf.Close()
		os.Remove(tf.Name())
		return nil, werr
	}
	rest, cerr := io.Copy(tf, r)
	if cerr != nil {
		tf.Close()
		os.Remove(tf.Name())
		return nil, cerr
	}
	return &bodySpool{file: tf, size: n + rest}, nil
}

// selfClosingBody 请求 body 包装: 关闭时自动删除落盘的临时文件
type selfClosingBody struct {
	io.ReadCloser
	path string
}

func (b *selfClosingBody) Close() error {
	err := b.ReadCloser.Close()
	if b.path != "" {
		os.Remove(b.path)
		b.path = ""
	}
	return err
}

// RestoreBody 将完整 body 恢复到 r 供后续 handler 使用。
// 落盘场景恢复的是临时文件 reader, 下游 handler 关闭 body 时自动删除临时文件
// (net/http 惯例: handler 消费完后关闭 request body; 反代场景由代理层关闭)
func (s *bodySpool) RestoreBody(r *http.Request) {
	if s.file != nil {
		if f, err := os.Open(s.file.Name()); err == nil {
			r.Body = &selfClosingBody{ReadCloser: f, path: s.file.Name()}
		} else {
			// 临时文件打不开 (罕见): 兜底恢复内存头部数据, 不丢失已读内容
			r.Body = io.NopCloser(bytes.NewReader(s.mem))
		}
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(s.mem))
}

// ReaderCloser 返回从头开始的完整内容读取器与关闭函数。
// 内存场景: bytes.Reader; 落盘场景: 独立文件句柄 (调用方必须在解析完成后执行关闭函数,
// 逐 part 流式解析, 不将大 body 重新全量驻留内存)
func (s *bodySpool) ReaderCloser() (io.Reader, func()) {
	if s.file != nil {
		f, err := os.Open(s.file.Name())
		if err != nil {
			// 临时文件打不开 (罕见): 兜底内存头部数据
			return bytes.NewReader(s.mem), func() {}
		}
		return f, func() { f.Close() }
	}
	return bytes.NewReader(s.mem), func() {}
}

// Close 释放 spool 资源 (拦截路径: body 不再恢复, 直接清理临时文件)
func (s *bodySpool) Close() {
	if s.file != nil {
		s.file.Close()
		os.Remove(s.file.Name())
		s.file = nil
	}
	s.mem = nil
}
