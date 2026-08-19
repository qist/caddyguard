package caddyguard

import (
	"net"
	"os"
	"sort"
	"strings"
	"sync"
)

// ipv4Range 预编译的 IPv4 CIDR 范围
type ipv4Range struct {
	lo, hi uint32
}

// ipRuleSet 预编译的 IP 规则集合
// 对应 nginxguard 的 compile_ip_rules + worker_ip_cache
type ipRuleSet struct {
	ipv4Ranges []ipv4Range // 按 lo 排序，支持二分搜索
	ipv6Nets   []*net.IPNet
	exactSet   map[string]bool // 小写精确 IP
	globRegex  []string        // glob 正则（预编译为字符串，matchRegex 会缓存编译后的 *regexp.Regexp）
	hasRules   bool            // 是否有有效规则（全注释/空文件 = false）
}

// ipCacheWorker worker 级别缓存：filepath → *ipRuleSet
// 对应 nginxguard 的 worker_ip_cache
var ipCacheWorker sync.Map // key: filepath → value: *ipRuleSetEntry

// ipRuleSetEntry 带_mtime 的缓存条目，用于 mtime 变更检测
type ipRuleSetEntry struct {
	ruleSet *ipRuleSet
	mtime   int64
}

// compileIPRules 将 []RuleEntry 预编译为 *ipRuleSet
// 对应 nginxguard 的 compile_ip_rules
func compileIPRules(rules []RuleEntry) *ipRuleSet {
	rs := &ipRuleSet{
		exactSet: make(map[string]bool),
	}

	for _, rule := range rules {
		line := rule.Raw
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "/") {
			// CIDR 表示法
			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				continue
			}
			if ipNet.IP.To4() != nil {
				// IPv4 CIDR → 转为 uint32 范围
				ones, bits := ipNet.Mask.Size()
				if bits == 32 {
					ip := ipNet.IP.To4()
					if ip != nil {
						base := ipv4ToUint32(ip)
						var mask uint32
						if ones == 0 {
							mask = 0
						} else if ones == 32 {
							mask = 0xFFFFFFFF
						} else {
							mask = uint32(0xFFFFFFFF) << (32 - ones)
						}
						lo := base & mask
						hi := lo | ^mask
						rs.ipv4Ranges = append(rs.ipv4Ranges, ipv4Range{lo: lo, hi: hi})
					}
				}
			} else {
				// IPv6 CIDR → 保存 *net.IPNet
				rs.ipv6Nets = append(rs.ipv6Nets, ipNet)
			}
		} else if strings.Contains(line, "*") {
			// glob 通配符
			rs.globRegex = append(rs.globRegex, globToRegex(line))
		} else {
			// 精确 IP（小写归一化，支持 IPv6 大小写不敏感）
			rs.exactSet[strings.ToLower(line)] = true
		}
	}

	// 排序 IPv4 ranges 以支持二分搜索
	sort.Slice(rs.ipv4Ranges, func(i, j int) bool {
		return rs.ipv4Ranges[i].lo < rs.ipv4Ranges[j].lo
	})

	rs.hasRules = len(rs.ipv4Ranges) > 0 || len(rs.ipv6Nets) > 0 ||
		len(rs.exactSet) > 0 || len(rs.globRegex) > 0

	return rs
}

// ipv4ToUint32 将 4 字节 IPv4 转为 uint32
func ipv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// binarySearchIPv4 二分搜索 IPv4 范围
func binarySearchIPv4(ranges []ipv4Range, ipVal uint32) bool {
	lo, hi := 0, len(ranges)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		r := ranges[mid]
		if ipVal < r.lo {
			hi = mid - 1
		} else if ipVal > r.hi {
			lo = mid + 1
		} else {
			return true
		}
	}
	return false
}

// matchIPRuleSet 检查 IP 是否匹配预编译的规则集合
// 对应 nginxguard 的 match_compiled_ip
func (rs *ipRuleSet) match(ip string) bool {
	if rs == nil || ip == "" {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// IPv4：二分搜索
	if v4 := parsedIP.To4(); v4 != nil {
		ipVal := ipv4ToUint32(v4)
		if binarySearchIPv4(rs.ipv4Ranges, ipVal) {
			return true
		}
	} else {
		// IPv6：线性扫描
		for _, cidr := range rs.ipv6Nets {
			if cidr.Contains(parsedIP) {
				return true
			}
		}
	}

	// glob 通配符
	for _, pattern := range rs.globRegex {
		if matchRegex(ip, pattern, false) {
			return true
		}
	}

	// 精确匹配
	if rs.exactSet[strings.ToLower(ip)] {
		return true
	}

	return false
}

// getCompiledIPRules 获取预编译的 IP 规则集合（带 mtime 缓存）
// 对应 nginxguard 的 get_compiled_ip_rules
func (g *Guard) getCompiledIPRules(filename string, domainRuleDir string) *ipRuleSet {
	// 确定实际文件路径
	filepath := g.ruleCache.ruleDir + "/" + filename
	if domainRuleDir != "" {
		domainPath := resolveRuleDir(domainRuleDir, g.ruleCache.ruleDir) + "/" + filename
		// 检查域名目录是否有该文件
		if _, exists := getFileMtime(domainPath); exists {
			filepath = domainPath
		}
	}

	// 获取 mtime
	mtime, exists := getFileMtime(filepath)
	if !exists {
		return nil
	}

	// 检查 worker 缓存（mtime 变化时重新编译）
	if v, ok := ipCacheWorker.Load(filepath); ok {
		entry := v.(*ipRuleSetEntry)
		if entry.mtime == mtime {
			return entry.ruleSet
		}
	}

	// 读取并编译（直接读文件，不经过 ruleCache 的节流）
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil
	}

	rules := parseAndCompileRules(string(content))
	if len(rules) == 0 {
		// 文件存在但为空 → 返回空 ruleSet（hasRules=false）
		rs := &ipRuleSet{exactSet: make(map[string]bool)}
		ipCacheWorker.Store(filepath, &ipRuleSetEntry{
			ruleSet: rs,
			mtime:   mtime,
		})
		return rs
	}

	rs := compileIPRules(rules)
	ipCacheWorker.Store(filepath, &ipRuleSetEntry{
		ruleSet: rs,
		mtime:   mtime,
	})

	return rs
}
