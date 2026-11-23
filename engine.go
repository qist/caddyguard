package caddyguard

// 三层组合规则引擎（与 nginxguard engine.lua 对齐）
//
//	L1 检测器: url / url_args / post / header / cookie / user_agent / referer /
//	           file_upload / cc / black_ip / dynamic_black_ip
//	L2 表达式: AND / OR / NOT / AT_LEAST + 内联请求条件
//	L3 动作:   BLOCK(默认) / LOG / ALERT / SCORE / CHALLENGE
//
// 规则文件: rule-config/combo.jsonl（JSONL，一行一条，# 开头为注释），10 秒热加载。
// 域名级 rule_dir 存在 combo.jsonl 时优先使用，不存在回退全局。
//
// 与 Lua 版一致的边界:
//   - 内联条件默认忽略大小写（method/protocol 的 eq 除外）
//   - body 只扫描前 2 MiB，超过时 re/eq 为未知，BLOCK/CHALLENGE 按 fail-closed 拦截
//   - 正则加载期预编译，非法规则记录错误并丢弃
//   - 每个检测器每请求最多执行一次，结果缓存在请求 state

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

const (
	comboRuleFile   = "combo.jsonl"
	comboBodyLimit  = 2 * 1024 * 1024
	comboMaxDepth   = 16
	comboTagBlock   = "Combo_BLOCK"
	comboTagLog     = "Combo_LOG"
	comboTagAlert   = "Combo_ALERT"
	comboTagScore   = "Combo_SCORE"
	comboTagScoreBl = "Combo_SCORE_BLOCK"
	comboTagChal    = "Combo_CHALLENGE"
	comboTagUnknown = "Combo_INDETERMINATE"
)

type tri int

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

// DetectorFact 检测器命中事实（对应 Lua 的 {rule=,detail=,tag=}）
type DetectorFact struct {
	Hit    bool
	Tag    string
	Detail string
	Rule   string
}

// comboState 请求级状态：L1 结果缓存、累计分值、body 前缀缓存
type comboState struct {
	facts    map[string]*DetectorFact
	known    map[string]bool // 已执行过的检测器（含未命中）
	bad      map[string]bool // 执行异常，视为未知
	score    int
	body     []byte
	bodyOK   bool
	bodyFull bool
	bodyRead bool
}

type comboStateKey struct{}

func comboStateOf(r *http.Request) *comboState {
	if s, ok := r.Context().Value(comboStateKey{}).(*comboState); ok {
		return s
	}
	s := &comboState{
		facts: make(map[string]*DetectorFact),
		known: make(map[string]bool),
		bad:   make(map[string]bool),
	}
	*r = *r.WithContext(context.WithValue(r.Context(), comboStateKey{}, s))
	return s
}

// comboCapture 用于在 dry-run 调用现有检测器时捕获其日志（第一条）
type comboCapture struct {
	entry  *LogEntry
	stored bool
}

type comboCaptureKey struct{}

// dryRunWriter 拦截输出空实现：组合规则阶段只取检测结果，不真正写响应
type dryRunWriter struct{}

func (dryRunWriter) Header() http.Header         { return http.Header{} }
func (dryRunWriter) Write(b []byte) (int, error) { return len(b), nil }
func (dryRunWriter) WriteHeader(int)             {}

func isDryRunWriter(w http.ResponseWriter) bool {
	_, ok := w.(dryRunWriter)
	return ok
}

// ============================================================
// L1 检测器调用（复用现有 detector，dry-run 捕获日志作为事实）
// ============================================================

func (g *Guard) callDetector(name string, w http.ResponseWriter, r *http.Request, cfg Config) bool {
	switch name {
	case "url":
		return g.urlAttackCheck(w, r, cfg)
	case "url_args":
		return g.urlArgsAttackCheck(w, r, cfg)
	case "post":
		return g.postAttackCheck(w, r, cfg)
	case "header":
		return g.headerAttackCheck(w, r, cfg)
	case "cookie":
		return g.cookieAttackCheck(w, r, cfg)
	case "user_agent":
		return g.userAgentAttackCheck(w, r, cfg)
	case "referer":
		return g.refererCheck(w, r, cfg)
	case "file_upload":
		return g.fileUploadCheck(w, r, cfg)
	case "cc":
		return g.ccAttackCheck(w, r, cfg)
	case "black_ip":
		return g.blackIPCheck(w, r, cfg)
	case "dynamic_black_ip":
		return g.dynamicBlackIPCheck(w, r, cfg)
	default:
		return false
	}
}

var comboDetectorNames = map[string]bool{
	"url": true, "url_args": true, "post": true, "header": true, "cookie": true,
	"user_agent": true, "referer": true, "file_upload": true, "cc": true,
	"black_ip": true, "dynamic_black_ip": true,
}

// detectFact 执行/复用 L1 检测器；返回事实与三态结果
func (g *Guard) detectFact(r *http.Request, cfg Config, name string) (*DetectorFact, tri) {
	st := comboStateOf(r)
	if st.known[name] {
		if st.bad[name] {
			return nil, triUnknown
		}
		f := st.facts[name]
		if f == nil {
			return nil, triUnknown
		}
		if f.Hit {
			return f, triTrue
		}
		return f, triFalse
	}
	if !comboDetectorNames[name] {
		caddy.Log().Error("caddyguard combo: unknown detector", zap.String("detector", name))
		st.known[name] = true
		st.bad[name] = true
		return nil, triUnknown
	}

	cap := &comboCapture{}
	r2 := r.WithContext(context.WithValue(r.Context(), comboCaptureKey{}, cap))
	var hit bool
	func() {
		defer func() {
			if rv := recover(); rv != nil {
				caddy.Log().Error("caddyguard combo: detector panic",
					zap.String("detector", name), zap.Any("error", rv))
				st.bad[name] = true
			}
		}()
		hit = g.callDetector(name, dryRunWriter{}, r2, cfg)
	}()
	st.known[name] = true
	if st.bad[name] {
		return nil, triUnknown
	}
	f := &DetectorFact{Hit: hit}
	if cap.entry != nil {
		f.Tag = cap.entry.AttackMethod
		f.Detail = cap.entry.ReqData
		f.Rule = cap.entry.RuleTag
	}
	st.facts[name] = f
	if hit {
		return f, triTrue
	}
	return f, triFalse
}

// legacyBlock 传统检测链：优先复用 combo 阶段缓存的检测结果，避免重复扫描
func (g *Guard) legacyBlock(w http.ResponseWriter, r *http.Request, cfg Config, name string) bool {
	if st, ok := r.Context().Value(comboStateKey{}).(*comboState); ok {
		if st.known[name] && !st.bad[name] {
			f := st.facts[name]
			if f == nil || !f.Hit {
				return false
			}
			tag := f.Tag
			if tag == "" {
				tag = name
			}
			rule := f.Rule
			if rule == "" {
				rule = "-"
			}
			g.logger.Record(tag, reqURICached(r), f.Detail, rule, g.getClientIPCached(r, cfg), r, cfg)
			g.wafOutput(w, cfg)
			return true
		}
	}
	return g.callDetector(name, w, r, cfg)
}

// ============================================================
// L2: 规则加载
// ============================================================

type comboCond struct {
	field         string
	op            string
	value         string
	num           int
	re            *regexp.Regexp
	icase         *bool
	caseSensitive bool
}

type comboExpr struct {
	kind     string // detector / and / or / not / atleast / inline
	detector string
	children []*comboExpr
	need     int
	cond     *comboCond
}

type comboRule struct {
	ID     string
	Action string
	Score  int
	Expr   *comboExpr
}

type comboFileEntry struct {
	ver           fileVersion
	exists        bool
	rules         []comboRule
	lastCheckNano int64
}

type comboEngine struct {
	mu    sync.RWMutex
	files map[string]*comboFileEntry
}

func newComboEngine() *comboEngine {
	return &comboEngine{files: make(map[string]*comboFileEntry)}
}

func (ce *comboEngine) load(path string) ([]comboRule, bool) {
	ce.mu.RLock()
	entry := ce.files[path]
	ce.mu.RUnlock()

	if entry != nil && !shouldCheck(atomic.LoadInt64(&entry.lastCheckNano)) {
		return entry.rules, entry.exists
	}

	ver, exists := getFileVersion(path)
	if !exists {
		ce.mu.Lock()
		ce.files[path] = &comboFileEntry{exists: false, lastCheckNano: time.Now().UnixNano()}
		ce.mu.Unlock()
		return nil, false
	}

	if entry != nil && entry.exists && entry.ver == ver {
		atomic.StoreInt64(&entry.lastCheckNano, time.Now().UnixNano())
		return entry.rules, true
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	rules := parseComboRules(string(content), path)
	ce.mu.Lock()
	ce.files[path] = &comboFileEntry{
		ver:           ver,
		exists:        true,
		rules:         rules,
		lastCheckNano: time.Now().UnixNano(),
	}
	ce.mu.Unlock()
	return rules, true
}

// rulesFor 返回域名级 combo（文件存在即使用，即使为空）或全局 combo
func (ce *comboEngine) rulesFor(rc *RuleCache, domainRuleDir string) []comboRule {
	if domainRuleDir != "" {
		domainPath := resolveRuleDir(domainRuleDir, rc.ruleDir) + "/" + comboRuleFile
		if rules, exists := ce.load(domainPath); exists {
			return rules
		}
	}
	rules, _ := ce.load(rc.ruleDir + "/" + comboRuleFile)
	return rules
}

func parseComboRules(content, path string) []comboRule {
	var out []comboRule
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var raw interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			comboLogError("bad JSON", path, i+1, err.Error())
			continue
		}
		obj, ok := raw.(map[string]interface{})
		if !ok {
			comboLogError("rule must be a JSON object", path, i+1, "")
			continue
		}
		id, _ := obj["id"].(string)
		if id == "" {
			comboLogError("missing id", path, i+1, "")
			continue
		}
		if enabled, ok := obj["enabled"].(bool); ok && !enabled {
			continue
		}
		action := "BLOCK"
		if v, ok := obj["action"].(string); ok && v != "" {
			action = strings.ToUpper(v)
		}
		switch action {
		case "BLOCK", "LOG", "ALERT", "SCORE", "CHALLENGE":
		default:
			comboLogError("unknown action", path, i+1, id+": "+action)
			continue
		}
		score := 10
		if v, ok := obj["score"].(float64); ok {
			score = int(v)
		} else if v, ok := obj["score"].(string); ok {
			if n, err := strconv.Atoi(v); err == nil {
				score = n
			} else {
				comboLogError("invalid score", path, i+1, id)
				continue
			}
		} else if obj["score"] != nil {
			comboLogError("invalid score", path, i+1, id)
			continue
		}
		if action == "SCORE" && score <= 0 {
			comboLogError("score must be positive", path, i+1, id)
			continue
		}
		exprRaw, exists := obj["if"]
		if !exists {
			comboLogError("missing if expression", path, i+1, id)
			continue
		}
		expr, ok := parseComboExpr(exprRaw, 0, false)
		if !ok {
			comboLogError("invalid expression", path, i+1, id)
			continue
		}
		out = append(out, comboRule{ID: id, Action: action, Score: score, Expr: expr})
	}
	return out
}

func comboLogError(msg, path string, line int, detail string) {
	fields := []zap.Field{zap.String("file", path), zap.Int("line", line)}
	if detail != "" {
		fields = append(fields, zap.String("detail", detail))
	}
	caddy.Log().Error("caddyguard combo: "+msg, fields...)
}

func parseComboExpr(node interface{}, depth int, insideNot bool) (*comboExpr, bool) {
	if depth > comboMaxDepth {
		return nil, false
	}
	switch v := node.(type) {
	case string:
		if insideNot || !comboDetectorNames[v] {
			return nil, false
		}
		return &comboExpr{kind: "detector", detector: v}, true
	case []interface{}:
		if len(v) == 0 {
			return nil, false
		}
		op, ok := v[0].(string)
		if !ok {
			return nil, false
		}
		switch op {
		case "NOT":
			if len(v) != 2 {
				return nil, false
			}
			child, ok := parseComboExpr(v[1], depth+1, true)
			if !ok {
				return nil, false
			}
			return &comboExpr{kind: "not", children: []*comboExpr{child}}, true
		case "AT_LEAST":
			if len(v) < 3 {
				return nil, false
			}
			n, ok := v[1].(float64)
			if !ok || n < 1 || n != float64(int(n)) || int(n) > len(v)-2 {
				return nil, false
			}
			e := &comboExpr{kind: "atleast", need: int(n)}
			for _, item := range v[2:] {
				child, ok := parseComboExpr(item, depth+1, insideNot)
				if !ok {
					return nil, false
				}
				e.children = append(e.children, child)
			}
			return e, true
		case "AND", "OR":
			if len(v) < 2 {
				return nil, false
			}
			e := &comboExpr{kind: strings.ToLower(op)}
			for _, item := range v[1:] {
				child, ok := parseComboExpr(item, depth+1, insideNot)
				if !ok {
					return nil, false
				}
				e.children = append(e.children, child)
			}
			return e, true
		default:
			return nil, false
		}
	case map[string]interface{}:
		return parseComboCond(v)
	default:
		return nil, false
	}
}

func parseComboCond(m map[string]interface{}) (*comboExpr, bool) {
	field, _ := m["cond"].(string)
	switch field {
	case "uri", "args", "method", "protocol", "header", "cookie", "body", "ip",
		"header_count", "content_type", "content_length", "transfer_encoding":
	default:
		return nil, false
	}
	op := "re"
	if v, ok := m["op"].(string); ok && v != "" {
		op = v
	}
	c := &comboCond{field: field, op: op}

	if field == "header_count" {
		switch op {
		case "gte", "lte", "eq":
		default:
			return nil, false
		}
		switch v := m["value"].(type) {
		case float64:
			if v < 0 || v != float64(int(v)) {
				return nil, false
			}
			c.num = int(v)
		case string:
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil, false
			}
			c.num = n
		default:
			return nil, false
		}
		return &comboExpr{kind: "inline", cond: c}, true
	}

	switch op {
	case "re", "eq", "contains", "prefix", "exists":
	default:
		return nil, false
	}
	if value, ok := m["value"].(string); ok {
		c.value = value
	} else if op != "exists" {
		return nil, false
	}
	if v, ok := m["icase"]; ok {
		b, ok := v.(bool)
		if !ok || (op != "contains" && op != "prefix" && op != "eq") {
			return nil, false
		}
		c.icase = &b
	}
	if v, ok := m["case_sensitive"]; ok {
		b, ok := v.(bool)
		if !ok || op != "re" {
			return nil, false
		}
		c.caseSensitive = b
	}
	flags := ""
	if v, ok := m["flags"]; ok {
		s, ok := v.(string)
		if !ok || op != "re" {
			return nil, false
		}
		flags = s
	}
	if op == "re" {
		re, err := compileComboRegex(c.value, flags, c.caseSensitive)
		if err != nil {
			return nil, false
		}
		c.re = re
	}
	return &comboExpr{kind: "inline", cond: c}, true
}

func compileComboRegex(pattern, flags string, caseSensitive bool) (*regexp.Regexp, error) {
	insensitive := !caseSensitive
	if flags != "" {
		insensitive = strings.Contains(flags, "i")
	}
	mods := ""
	if insensitive {
		mods += "i"
	}
	if strings.Contains(flags, "m") {
		mods += "m"
	}
	if strings.Contains(flags, "s") {
		mods += "s"
	}
	if mods != "" {
		pattern = "(?" + mods + ")" + pattern
	}
	return regexp.Compile(pattern)
}

// ============================================================
// L2: 表达式求值
// ============================================================

func (g *Guard) evalComboExpr(r *http.Request, cfg Config, e *comboExpr) tri {
	switch e.kind {
	case "detector":
		_, res := g.detectFact(r, cfg, e.detector)
		return res
	case "inline":
		return g.evalComboCond(r, cfg, e.cond)
	case "not":
		res := g.evalComboExpr(r, cfg, e.children[0])
		if res == triUnknown {
			return triUnknown
		}
		if res == triTrue {
			return triFalse
		}
		return triTrue
	case "and":
		unknown := false
		for _, child := range e.children {
			res := g.evalComboExpr(r, cfg, child)
			if res == triFalse {
				return triFalse
			}
			if res == triUnknown {
				unknown = true
			}
		}
		if unknown {
			return triUnknown
		}
		return triTrue
	case "or":
		unknown := false
		for _, child := range e.children {
			res := g.evalComboExpr(r, cfg, child)
			if res == triTrue {
				return triTrue
			}
			if res == triUnknown {
				unknown = true
			}
		}
		if unknown {
			return triUnknown
		}
		return triFalse
	case "atleast":
		matched, unknown := 0, 0
		for _, child := range e.children {
			res := g.evalComboExpr(r, cfg, child)
			if res == triTrue {
				matched++
				if matched >= e.need {
					return triTrue
				}
			} else if res == triUnknown {
				unknown++
			}
		}
		if matched+unknown >= e.need {
			return triUnknown
		}
		return triFalse
	}
	return triFalse
}

func (g *Guard) evalComboCond(r *http.Request, cfg Config, c *comboCond) tri {
	if c.field == "header_count" {
		n := countRequestHeaders(r)
		switch c.op {
		case "gte":
			if n >= c.num {
				return triTrue
			}
			return triFalse
		case "lte":
			if n <= c.num {
				return triTrue
			}
			return triFalse
		default: // eq
			if n == c.num {
				return triTrue
			}
			return triFalse
		}
	}

	subject, present, complete := g.comboFieldValue(r, cfg, c.field)
	if c.op == "exists" {
		if present {
			return triTrue
		}
		if !complete {
			return triUnknown
		}
		return triFalse
	}
	if !present {
		if !complete {
			return triUnknown
		}
		return triFalse
	}

	switch c.op {
	case "re":
		if !complete {
			return triUnknown
		}
		if c.re.MatchString(subject) {
			return triTrue
		}
		return triFalse
	case "eq":
		if !complete {
			return triUnknown
		}
		icase := true
		if c.field == "method" || c.field == "protocol" {
			icase = false
		}
		if c.icase != nil {
			icase = *c.icase
		}
		if icase {
			if strings.EqualFold(subject, c.value) {
				return triTrue
			}
			return triFalse
		}
		if subject == c.value {
			return triTrue
		}
		return triFalse
	case "contains":
		icase := true
		if c.icase != nil {
			icase = *c.icase
		}
		var matched bool
		if icase {
			matched = strings.Contains(strings.ToLower(subject), strings.ToLower(c.value))
		} else {
			matched = strings.Contains(subject, c.value)
		}
		if matched {
			return triTrue
		}
		if !complete {
			return triUnknown
		}
		return triFalse
	case "prefix":
		if !complete && len(c.value) > len(subject) {
			return triUnknown
		}
		icase := true
		if c.icase != nil {
			icase = *c.icase
		}
		prefix := subject
		if len(prefix) > len(c.value) {
			prefix = prefix[:len(c.value)]
		}
		if icase {
			if strings.EqualFold(prefix, c.value) && len(subject) >= len(c.value) {
				return triTrue
			}
		} else if prefix == c.value && len(subject) >= len(c.value) {
			return triTrue
		}
		return triFalse
	}
	return triUnknown
}

func countRequestHeaders(r *http.Request) int {
	n := 0
	if r.Host != "" {
		n++
	}
	for _, values := range r.Header {
		n += len(values)
	}
	return n
}

func (g *Guard) comboFieldValue(r *http.Request, cfg Config, field string) (string, bool, bool) {
	switch field {
	case "uri":
		return r.URL.Path, true, true
	case "args":
		if r.URL.RawQuery == "" {
			return "", false, true
		}
		return r.URL.RawQuery, true, true
	case "method":
		return r.Method, true, true
	case "protocol":
		return r.Proto, true, true
	case "header":
		return getHeaderTextCached(r), true, true
	case "cookie":
		v, ok := headerFirst(r.Header, "Cookie")
		return v, ok, true
	case "body":
		data, complete, ok := comboReadBody(r)
		if !ok {
			return "", false, false
		}
		return string(data), true, complete
	case "ip":
		return g.getClientIPCached(r, cfg), true, true
	case "content_type":
		v, ok := headerFirst(r.Header, "Content-Type")
		return v, ok, true
	case "content_length":
		v, ok := headerFirst(r.Header, "Content-Length")
		return v, ok, true
	case "transfer_encoding":
		v, ok := headerFirst(r.Header, "Transfer-Encoding")
		if !ok && len(r.TransferEncoding) > 0 {
			return strings.Join(r.TransferEncoding, ","), true, true
		}
		return v, ok, true
	}
	return "", false, true
}

func headerFirst(h http.Header, name string) (string, bool) {
	values, ok := h[http.CanonicalHeaderKey(name)]
	if !ok || len(values) == 0 {
		return "", false
	}
	return values[0], true
}

// comboReadBody 读取前 2 MiB 并把完整 body 恢复到 r.Body，供后续传统检测使用
func comboReadBody(r *http.Request) ([]byte, bool, bool) {
	st := comboStateOf(r)
	if st.bodyRead {
		return st.body, st.bodyFull, st.bodyOK
	}
	st.bodyRead = true
	if r.Body == nil {
		st.body = []byte{}
		st.bodyFull = true
		st.bodyOK = true
		return st.body, true, true
	}
	buf := make([]byte, comboBodyLimit+1)
	n, err := io.ReadFull(r.Body, buf)
	complete := false
	switch {
	case err == nil:
		complete = false
		n = comboBodyLimit + 1
	case err == io.EOF || err == io.ErrUnexpectedEOF:
		complete = true
	default:
		// 读取失败也要把已读部分接回去，避免下游拿到被截断的 body
		r.Body = &prefixRestoredBody{
			Reader: io.MultiReader(bytes.NewReader(buf[:n]), r.Body),
			closer: r.Body,
		}
		st.bodyOK = false
		st.bodyFull = false
		return nil, false, false
	}
	prefix := buf[:n]
	// 恢复完整 body：已读前缀 + 尚未读取的剩余部分
	r.Body = &prefixRestoredBody{
		Reader: io.MultiReader(bytes.NewReader(prefix), r.Body),
		closer: r.Body,
	}
	data := prefix
	if !complete && len(data) > comboBodyLimit {
		data = data[:comboBodyLimit]
	}
	st.body = append([]byte(nil), data...)
	st.bodyFull = complete
	st.bodyOK = true
	return st.body, complete, true
}

type prefixRestoredBody struct {
	io.Reader
	closer io.Closer
}

func (b *prefixRestoredBody) Close() error {
	if b.closer != nil {
		return b.closer.Close()
	}
	return nil
}

// ============================================================
// L3: 动作执行
// ============================================================

func (g *Guard) comboLog(r *http.Request, cfg Config, tag, ruleID, detail string) {
	if detail == "" {
		detail = "-"
	}
	g.logger.Record(tag, reqURICached(r), detail, ruleID, g.getClientIPCached(r, cfg), r, cfg)
}

func (g *Guard) runCombo(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	rules := g.comboRules(cfg)
	if len(rules) == 0 {
		return false
	}
	for i := range rules {
		rule := &rules[i]
		res := g.evalComboExpr(r, cfg, rule.Expr)
		switch res {
		case triTrue:
			if g.applyComboAction(w, r, cfg, rule) {
				return true
			}
		case triUnknown:
			if g.comboIndeterminate(w, r, cfg, rule) {
				return true
			}
		}
	}
	return false
}

func (g *Guard) comboRules(cfg Config) []comboRule {
	if g.ruleCache == nil {
		return nil
	}
	return g.comboEngine().rulesFor(g.ruleCache, cfg.RuleDir)
}

func (g *Guard) applyComboAction(w http.ResponseWriter, r *http.Request, cfg Config, rule *comboRule) bool {
	switch rule.Action {
	case "LOG":
		g.comboLog(r, cfg, comboTagLog, rule.ID, "")
		return false
	case "ALERT":
		g.comboLog(r, cfg, comboTagAlert, rule.ID, "")
		return false
	case "SCORE":
		st := comboStateOf(r)
		total := st.score + rule.Score
		st.score = total
		g.comboLog(r, cfg, comboTagScore, rule.ID,
			fmt.Sprintf("score:%d total:%d", rule.Score, total))
		if cfg.ScoreBlockThreshold > 0 && total >= cfg.ScoreBlockThreshold {
			g.comboLog(r, cfg, comboTagScoreBl, rule.ID, fmt.Sprintf("total:%d", total))
			g.wafOutput(w, cfg)
			return true
		}
		return false
	case "CHALLENGE":
		g.comboLog(r, cfg, comboTagChal, rule.ID, "")
		g.wafOutput(w, cfg)
		return true
	default: // BLOCK
		g.comboLog(r, cfg, comboTagBlock, rule.ID, "")
		g.wafOutput(w, cfg)
		return true
	}
}

func (g *Guard) comboIndeterminate(w http.ResponseWriter, r *http.Request, cfg Config, rule *comboRule) bool {
	g.comboLog(r, cfg, comboTagUnknown, rule.ID, "expression could not be fully evaluated")
	if rule.Action == "BLOCK" || rule.Action == "CHALLENGE" {
		g.wafOutput(w, cfg)
		return true
	}
	return false
}

// ============================================================
// 引擎初始化
// ============================================================

func (g *Guard) comboEngine() *comboEngine {
	g.comboOnce.Do(func() {
		g.combo = newComboEngine()
	})
	return g.combo
}
