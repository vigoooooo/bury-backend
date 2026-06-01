package middlewares

import (
	"testing"
	"time"
)

// TestRateLimiterAllow 测试速率限制器允许请求
func TestRateLimiterAllow(t *testing.T) {
	limiter := NewRateLimiter(5) // 每分钟5次

	// 前5次请求应该全部允许
	for i := 0; i < 5; i++ {
		if !limiter.Allow("192.168.1.1") {
			t.Fatalf("Request %d should be allowed", i+1)
		}
	}

	// 第6次应该被拒绝
	if limiter.Allow("192.168.1.1") {
		t.Fatal("6th request should be rejected")
	}
}

// TestRateLimiterDifferentIPs 测试不同 IP 独立计数
func TestRateLimiterDifferentIPs(t *testing.T) {
	limiter := NewRateLimiter(3) // 每分钟3次

	// IP1 用完3次
	for i := 0; i < 3; i++ {
		if !limiter.Allow("192.168.1.1") {
			t.Fatalf("IP1 request %d should be allowed", i+1)
		}
	}

	// IP1 第4次应该被拒绝
	if limiter.Allow("192.168.1.1") {
		t.Fatal("IP1 4th request should be rejected")
	}

	// IP2 应该仍然允许
	if !limiter.Allow("192.168.1.2") {
		t.Fatal("IP2 request should be allowed (independent counter)")
	}
}

// TestRateLimiterResetAfterExpiry 测试过期后重置
func TestRateLimiterResetAfterExpiry(t *testing.T) {
	limiter := NewRateLimiter(2)

	// 用完2次
	limiter.Allow("10.0.0.1")
	limiter.Allow("10.0.0.1")

	// 应该被拒绝
	if limiter.Allow("10.0.0.1") {
		t.Fatal("Should be rejected after limit")
	}

	// 手动设置过期（模拟时间流逝）
	limiter.mu.Lock()
	if info, exists := limiter.visitors["10.0.0.1"]; exists {
		info.expiryAt = time.Now().Add(-time.Second) // 已过期
	}
	limiter.mu.Unlock()

	// 过期后应该重新允许
	if !limiter.Allow("10.0.0.1") {
		t.Fatal("Should be allowed after expiry reset")
	}
}

// TestRateLimiterConcurrentSafety 测试并发安全性
func TestRateLimiterConcurrentSafety(t *testing.T) {
	limiter := NewRateLimiter(1000)
	done := make(chan bool, 10)

	// 10个 goroutine 同时访问
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				limiter.Allow("concurrent-ip")
			}
			done <- true
		}(i)
	}

	// 等待所有 goroutine 完成
	for i := 0; i < 10; i++ {
		<-done
	}

	// 如果没有 panic 或 race condition，测试通过
}
