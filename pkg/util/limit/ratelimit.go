package limit

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/samber/lo"

	"github.com/fatedier/frp/pkg/util/xlog"
)

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	// 启用限流
	Enable bool
	// 时间窗口大小
	WindowSize time.Duration
	// 窗口内最大连接数
	MaxConnectionsPerWindow int
	// 最大并发连接数
	MaxConcurrentConnections int
	// IP 白名单 (CIDR 格式)
	WhiteList []string
	// IP 黑名单 (CIDR 格式)
	BlackList []string
	// 黑名单封禁时长
	BlackListBanDuration time.Duration
}

// RateLimiter 基于滑动窗口的限流器
type RateLimiter struct {
	config RateLimitConfig

	// 滑动窗口缓存
	windowCache *bigcache.BigCache

	// 动态黑名单
	dynamicBlackList     map[string]time.Time
	dynamicBlackListLock sync.RWMutex

	// 并发连接跟踪
	concurrentConnections    map[string]int
	concurrentConnectionLock sync.RWMutex

	// 预编译的白名单网络
	whiteNets []*net.IPNet
	// 预编译的黑名单网络
	blackNets []*net.IPNet
}

// NewRateLimiter 创建新的限流器
func NewRateLimiter(ctx context.Context,
	config RateLimitConfig) (*RateLimiter, error) {
	if !config.Enable {
		return nil, nil
	}

	// 设置默认值
	if config.WindowSize == 0 {
		config.WindowSize = 60 * time.Second
	}
	if config.MaxConnectionsPerWindow == 0 {
		config.MaxConnectionsPerWindow = 100
	}
	if config.MaxConcurrentConnections == 0 {
		config.MaxConcurrentConnections = 10
	}
	if config.BlackListBanDuration == 0 {
		config.BlackListBanDuration = 1 * time.Hour
	}

	// 创建滑动窗口缓存
	cacheConfig := bigcache.Config{
		Shards:             1024,
		LifeWindow:         config.WindowSize,
		CleanWindow:        config.WindowSize / 2,
		MaxEntriesInWindow: 1000 * 10 * 60,
		MaxEntrySize:       500,
		Verbose:            false,
	}

	cache, err := bigcache.New(ctx, cacheConfig)
	if err != nil {
		return nil, err
	}

	limiter := &RateLimiter{
		config:                config,
		windowCache:           cache,
		dynamicBlackList:      make(map[string]time.Time),
		concurrentConnections: make(map[string]int),
		whiteNets:             make([]*net.IPNet, 0),
		blackNets:             make([]*net.IPNet, 0),
	}

	// 解析白名单
	limiter.whiteNets = append(limiter.whiteNets, parseIPList(config.WhiteList)...)

	// 解析黑名单
	limiter.blackNets = append(limiter.blackNets, parseIPList(config.BlackList)...)

	// 启动清理协程
	go limiter.cleanupDynamicBlackList(ctx)

	return limiter, nil
}

// parseIPList 解析IP列表
func parseIPList(configIpList []string) (ipNetList []*net.IPNet) {
	for _, cidr := range configIpList {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// 尝试作为单个 IP 处理
			ip := net.ParseIP(cidr)
			if ip == nil {
				continue
			}
			// 转换为 CIDR
			if ip.To4() != nil {
				_, ipNet, _ = net.ParseCIDR(cidr + "/32")
			} else {
				_, ipNet, _ = net.ParseCIDR(cidr + "/128")
			}
		}
		ipNetList = append(ipNetList, ipNet)
	}
	return
}

// Allow 检查 IP 是否允许访问
func (r *RateLimiter) Allow(remoteAddr string, xl *xlog.Logger) bool {
	if r == nil {
		return true
	}

	// 提取 IP 地址
	ip := extractIP(remoteAddr)
	if ip == "" {
		xl.Warnf("failed to extract IP from address: %s", remoteAddr)
		return false
	}

	// 1. 检查白名单 (白名单优先级最高)
	if r.isInWhiteList(ip) {
		xl.Debugf("IP [%s] is in whitelist, allowing", ip)
		return true
	}

	// 2. 检查静态黑名单
	if r.isInStaticBlackList(ip) {
		xl.Warnf("IP [%s] is in static blacklist, denying", ip)
		return false
	}

	// 3. 检查动态黑名单
	if r.isInDynamicBlackList(ip) {
		xl.Warnf("IP [%s] is in dynamic blacklist, denying", ip)
		return false
	}

	// 4. 检查并发连接数限制
	if !r.checkConcurrentLimit(ip, xl) {
		// 超过并发限制,加入动态黑名单
		r.addToDynamicBlackList(ip, xl)
		return false
	}

	// 5. 检查滑动窗口速率限制
	if !r.checkRateLimit(ip, xl) {
		// 超过速率限制,加入动态黑名单
		r.addToDynamicBlackList(ip, xl)
		return false
	}

	// 6. 增加计数器
	r.incrementCounter(ip)

	return true
}

// AcquireConcurrentSlot 获取并发连接槽位
func (r *RateLimiter) AcquireConcurrentSlot(remoteAddr string,
	xl *xlog.Logger) bool {
	if r == nil {
		return true
	}

	ip := extractIP(remoteAddr)
	if ip == "" {
		return false
	}

	r.concurrentConnectionLock.Lock()
	defer r.concurrentConnectionLock.Unlock()

	current := r.concurrentConnections[ip]
	if current >= r.config.MaxConcurrentConnections {
		xl.Warnf("IP [%s] exceeded concurrent connection limit: %d/%d",
			ip, current, r.config.MaxConcurrentConnections)
		return false
	}
	current += 1
	r.concurrentConnections[ip] = current
	xl.Debugf("IP [%s] acquired concurrent slot: %d/%d",
		ip, current, r.config.MaxConcurrentConnections)
	return true
}

// ReleaseConcurrentSlot 释放并发连接槽位
func (r *RateLimiter) ReleaseConcurrentSlot(remoteAddr string) {
	if r == nil {
		return
	}

	ip := extractIP(remoteAddr)
	if ip == "" {
		return
	}

	r.concurrentConnectionLock.Lock()
	defer r.concurrentConnectionLock.Unlock()

	if count, ok := r.concurrentConnections[ip]; ok {
		if count <= 1 {
			delete(r.concurrentConnections, ip)
		} else {
			r.concurrentConnections[ip] = count - 1
		}
	}
}

// isInWhiteList 检查 IP 是否在白名单中
func (r *RateLimiter) isInWhiteList(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	_, ok := lo.Find(r.whiteNets, func(ipNet *net.IPNet) bool {
		return ipNet.IP.Equal(parsedIP)
	})

	return ok
}

// isInStaticBlackList 检查 IP 是否在静态黑名单中
func (r *RateLimiter) isInStaticBlackList(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	_, ok := lo.Find(r.blackNets, func(ipNet *net.IPNet) bool {
		return ipNet.IP.Equal(parsedIP)
	})
	return ok
}

// isInDynamicBlackList 检查 IP 是否在动态黑名单中
func (r *RateLimiter) isInDynamicBlackList(ip string) bool {
	r.dynamicBlackListLock.RLock()
	defer r.dynamicBlackListLock.RUnlock()

	expireTime, exists := r.dynamicBlackList[ip]
	if !exists {
		return false
	}

	// 检查是否过期
	if time.Now().After(expireTime) {
		return false
	}

	return true
}

// addToDynamicBlackList 将 IP 添加到动态黑名单
func (r *RateLimiter) addToDynamicBlackList(ip string, xl *xlog.Logger) {
	r.dynamicBlackListLock.Lock()
	defer r.dynamicBlackListLock.Unlock()

	expireTime := time.Now().Add(r.config.BlackListBanDuration)
	r.dynamicBlackList[ip] = expireTime

	xl.Warnf("IP [%s] added to dynamic blacklist until %s", ip, expireTime.Format(time.RFC3339))
}

// checkConcurrentLimit 检查并发连接数限制
func (r *RateLimiter) checkConcurrentLimit(ip string, xl *xlog.Logger) bool {
	r.concurrentConnectionLock.RLock()
	defer r.concurrentConnectionLock.RUnlock()

	current := r.concurrentConnections[ip]
	if current >= r.config.MaxConcurrentConnections {
		xl.Warnf("IP [%s] exceeded concurrent connection limit: %d/%d",
			ip, current, r.config.MaxConcurrentConnections)
		return false
	}

	return true
}

// checkRateLimit 检查滑动窗口速率限制
func (r *RateLimiter) checkRateLimit(ip string, xl *xlog.Logger) bool {
	if r.windowCache == nil {
		return true
	}

	countValue, err := r.windowCache.Get(ip)
	if err != nil {
		// 第一次连接
		return true
	}

	count, err := strconv.Atoi(string(countValue))
	if err != nil {
		xl.Warnf("failed to parse connection count for IP %s: %v", ip, err)
		return true
	}

	if count >= r.config.MaxConnectionsPerWindow {
		xl.Warnf("IP [%s] exceeded rate limit: %d/%d connections in %v window",
			ip, count, r.config.MaxConnectionsPerWindow, r.config.WindowSize)
		return false
	}

	return true
}

// incrementCounter 增加计数器
func (r *RateLimiter) incrementCounter(ip string) {
	if r.windowCache == nil {
		return
	}

	countValue, err := r.windowCache.Get(ip)
	var count int
	if err == nil {
		count, _ = strconv.Atoi(string(countValue))
	}

	_ = r.windowCache.Set(ip, []byte(strconv.Itoa(count+1)))
}

// cleanupDynamicBlackList 定期清理过期的动态黑名单
func (r *RateLimiter) cleanupDynamicBlackList(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.dynamicBlackListLock.Lock()
			now := time.Now()
			for ip, expireTime := range r.dynamicBlackList {
				if now.After(expireTime) {
					delete(r.dynamicBlackList, ip)
				}
			}
			r.dynamicBlackListLock.Unlock()
		}
	}
}

// GetStats 获取统计信息
func (r *RateLimiter) GetStats(ip string) (connectionCount int, concurrentCount int, inBlackList bool) {
	if r == nil {
		return 0, 0, false
	}

	// 获取窗口连接数
	if r.windowCache != nil {
		if countValue, err := r.windowCache.Get(ip); err == nil {
			connectionCount, _ = strconv.Atoi(string(countValue))
		}
	}

	// 获取并发连接数
	r.concurrentConnectionLock.RLock()
	concurrentCount = r.concurrentConnections[ip]
	r.concurrentConnectionLock.RUnlock()

	// 检查是否在黑名单中
	inBlackList = r.isInStaticBlackList(ip) || r.isInDynamicBlackList(ip)

	return
}

// extractIP 从地址中提取 IP
func extractIP(addr string) string {
	// 尝试分离 IP 和端口
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// 可能没有端口,直接返回
		return addr
	}
	return strings.TrimSpace(host)
}
