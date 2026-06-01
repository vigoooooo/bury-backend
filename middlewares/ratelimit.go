package middlewares

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter 速率限制器
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitorInfo
	rate     int // 每分钟允许的请求数
}

type visitorInfo struct {
	count    int
	expiryAt time.Time
}

// NewRateLimiter 创建速率限制器
func NewRateLimiter(ratePerMinute int) *RateLimiter {
	limiter := &RateLimiter{
		visitors: make(map[string]*visitorInfo),
		rate:     ratePerMinute,
	}

	// 启动定期清理过期记录的协程
	go limiter.cleanupExpired()

	return limiter
}

// cleanupExpired 定期清理过期记录
func (rl *RateLimiter) cleanupExpired() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		now := time.Now()
		for ip, info := range rl.visitors {
			if now.After(info.expiryAt) {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Allow 检查是否允许请求
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	info, exists := rl.visitors[ip]

	if !exists || now.After(info.expiryAt) {
		// 新访客或过期记录，重置计数
		rl.visitors[ip] = &visitorInfo{
			count:    1,
			expiryAt: now.Add(time.Minute),
		}
		return true
	}

	info.count++
	if info.count > rl.rate {
		return false
	}

	return true
}

// RateLimitMiddleware 速率限制中间件
func RateLimitMiddleware(ratePerMinute int) gin.HandlerFunc {
	limiter := NewRateLimiter(ratePerMinute)

	return func(c *gin.Context) {
		ip := c.ClientIP()

		if !limiter.Allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests, please try again later",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
