package caddyguard

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
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

// ============================================================
// 滑动窗口实现：使用环形时间片桶
// ============================================================

// ccBucket 一个时间片桶，记录该时间片内的请求计数
type ccBucket struct {
	count    int64
	expireAt int64 // unix nano
}

// ccEntry CC 计数条目：用多个时间片桶组成滑动窗口
// windowBuckets 个桶覆盖整个 ttl 时间范围
type ccEntry struct {
	buckets [8]ccBucket // 8 个桶组成滑动窗口
	cursor  uint8       // 当前桶索引（0-7）
}

// ccMaxEntries CC 计数器最大条目数，防止攻击者用随机 URI 耗尽内存
const ccMaxEntries = 1_000_000

// ============================================================
// 分片 MemoryStore：64 分片消除全局锁竞争
// ============================================================

// counterShard CC 计数器分片
type counterShard struct {
	mu      sync.Mutex
	counter map[string]*ccEntry
	keys    int // 当前 key 数量（用于上限检查）
}

// banShard IP 封禁分片
type banShard struct {
	mu   sync.RWMutex
	bans map[string]int64 // key: IP → value: 解封时间 unix nano
}

// MemoryStore 内存存储实现（默认）
// 使用 64 分片消除全局锁竞争，支持滑动窗口 + key 上限
type MemoryStore struct {
	shards     [64]counterShard // CC 计数分片
	banShards  [64]banShard     // IP 封禁分片
	totalCount atomic.Int64     // 全局 key 计数（用于上限检查）
}

// NewMemoryStore 创建内存存储
func NewMemoryStore() *MemoryStore {
	m := &MemoryStore{}
	for i := range m.shards {
		m.shards[i].counter = make(map[string]*ccEntry)
	}
	for i := range m.banShards {
		m.banShards[i].bans = make(map[string]int64)
	}
	return m
}

// shardIndex 根据 key 计算 shard 索引（FNV-1a hash）
func shardIndex(key string) int {
	h := fnv.New32a()
	h.Write([]byte(key))
	return int(h.Sum32() & 63) // 0-63
}

// Incr 原子递增 + 滑动窗口
// 真正的滑动窗口：使用 8 个时间片桶覆盖 ttl 时间范围
// 只有当前时间片桶 + 前面还在窗口内的桶被计入总数
func (m *MemoryStore) Incr(key string, ttl time.Duration) int {
	idx := shardIndex(key)
	shard := &m.shards[idx]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	now := time.Now()
	nowNano := now.UnixNano()
	windowNano := int64(ttl)
	bucketNano := windowNano / 8 // 每个桶覆盖的时间范围

	entry, ok := shard.counter[key]
	if !ok {
		// 检查 key 上限
		if m.totalCount.Load() >= ccMaxEntries {
			// 超过上限：随机淘汰一个过期条目
			m.evictExpiredLocked()
			if m.totalCount.Load() >= ccMaxEntries {
				// 仍然超限，拒绝新增（返回 1 不影响正常请求）
				return 1
			}
		}
		entry = &ccEntry{}
		shard.counter[key] = entry
		shard.keys++
		m.totalCount.Add(1)
	}

	// 滑动窗口逻辑
	// 确定当前应使用的桶
	cur := entry.cursor
	// 如果当前桶已过期，推进 cursor 到新桶
	if entry.buckets[cur].expireAt < nowNano {
		// 推进到下一个桶
		next := (cur + 1) % 8
		// 清理沿途过期的桶
		for i := 0; i < 8; i++ {
			check := (cur + 1 + uint8(i)) % 8
			if entry.buckets[check].expireAt < nowNano {
				entry.buckets[check].count = 0
				entry.buckets[check].expireAt = 0
			}
		}
		cur = next
		entry.cursor = cur
	}

	// 在当前桶计数
	entry.buckets[cur].count++
	entry.buckets[cur].expireAt = nowNano + bucketNano

	// 统计窗口内所有桶的总计数
	var total int64
	for i := 0; i < 8; i++ {
		b := &entry.buckets[i]
		if b.expireAt > nowNano-windowNano {
			// 桶仍在滑动窗口内
			total += b.count
		}
	}

	return int(total)
}

// evictExpiredLocked 清理已过期的条目（调用方持有锁）
func (m *MemoryStore) evictExpiredLocked() {
	nowNano := time.Now().UnixNano()
	for i := range m.shards {
		shard := &m.shards[i]
		for key, entry := range shard.counter {
			// 检查所有桶是否都过期了
			allExpired := true
			for j := range entry.buckets {
				if entry.buckets[j].expireAt > nowNano-int64(2*time.Second) {
					allExpired = false
					break
				}
			}
			if allExpired {
				delete(shard.counter, key)
				shard.keys--
				m.totalCount.Add(-1)
			}
		}
	}
}

// Ban 封禁 IP
func (m *MemoryStore) Ban(ip string, ttl time.Duration) {
	idx := shardIndex(ip)
	shard := &m.banShards[idx]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	shard.bans[ip] = time.Now().Add(ttl).UnixNano()
}

// IsBanned 检查 IP 是否在封禁中
func (m *MemoryStore) IsBanned(ip string) bool {
	idx := shardIndex(ip)
	shard := &m.banShards[idx]
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	expireAt, ok := shard.bans[ip]
	if !ok {
		return false
	}
	if time.Now().UnixNano() > expireAt {
		return false // 已过期
	}
	return true
}

// CleanupCounters 清理过期计数器
func (m *MemoryStore) CleanupCounters() {
	nowNano := time.Now().UnixNano()
	for i := range m.shards {
		shard := &m.shards[i]
		shard.mu.Lock()
		for key, entry := range shard.counter {
			// 检查所有桶是否都过期了
			allExpired := true
			for j := range entry.buckets {
				if entry.buckets[j].expireAt > nowNano {
					allExpired = false
					break
				}
			}
			if allExpired {
				delete(shard.counter, key)
				shard.keys--
				m.totalCount.Add(-1)
			}
		}
		shard.mu.Unlock()
	}
}

// CleanupBans 清理过期封禁
func (m *MemoryStore) CleanupBans() {
	nowNano := time.Now().UnixNano()
	for i := range m.banShards {
		shard := &m.banShards[i]
		shard.mu.Lock()
		for ip, expireAt := range shard.bans {
			if nowNano > expireAt {
				delete(shard.bans, ip)
			}
		}
		shard.mu.Unlock()
	}
}
