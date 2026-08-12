package caddyguard

import (
	"sync"
	"time"
)

// CCStore 定义 CC 限速和 IP 封禁的存储接口
// 单机使用 MemoryStore，多节点部署可切换 RedisStore
type CCStore interface {
	// CC 计数
	Incr(key string, ttl time.Duration) int
	CleanupCounters()

	// IP 封禁
	Ban(ip string, ttl time.Duration)
	IsBanned(ip string) bool
	CleanupBans()
}

// ccEntry CC 计数条目
type ccEntry struct {
	count    int
	expireAt time.Time
}

// MemoryStore 内存存储实现（默认）
type MemoryStore struct {
	mu       sync.Mutex
	counters map[string]*ccEntry // key: IP + URI
	banMu    sync.RWMutex
	bans     map[string]time.Time // key: IP → value: 解封时间
}

// NewMemoryStore 创建内存存储
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		counters: make(map[string]*ccEntry),
		bans:     make(map[string]time.Time),
	}
}

// Incr 原子递增 + 滑动窗口
func (m *MemoryStore) Incr(key string, ttl time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	entry, ok := m.counters[key]

	if !ok || now.After(entry.expireAt) {
		// 新窗口
		m.counters[key] = &ccEntry{
			count:    1,
			expireAt: now.Add(ttl),
		}
		return 1
	}

	entry.count++
	entry.expireAt = now.Add(ttl) // 滑动窗口
	return entry.count
}

// Ban 封禁 IP
func (m *MemoryStore) Ban(ip string, ttl time.Duration) {
	m.banMu.Lock()
	defer m.banMu.Unlock()
	m.bans[ip] = time.Now().Add(ttl)
}

// IsBanned 检查 IP 是否在封禁中
func (m *MemoryStore) IsBanned(ip string) bool {
	m.banMu.RLock()
	defer m.banMu.RUnlock()
	expireAt, ok := m.bans[ip]
	if !ok {
		return false
	}
	if time.Now().After(expireAt) {
		return false // 已过期
	}
	return true
}

// CleanupCounters 清理过期计数器
func (m *MemoryStore) CleanupCounters() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for key, entry := range m.counters {
		if now.After(entry.expireAt) {
			delete(m.counters, key)
		}
	}
}

// CleanupBans 清理过期封禁
func (m *MemoryStore) CleanupBans() {
	m.banMu.Lock()
	defer m.banMu.Unlock()
	now := time.Now()
	for ip, expireAt := range m.bans {
		if now.After(expireAt) {
			delete(m.bans, ip)
		}
	}
}
