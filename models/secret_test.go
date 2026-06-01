package models

import (
	"testing"
)

// TestHashCodeAndCheckCode 测试 bcrypt 哈希和验证
func TestHashCodeAndCheckCode(t *testing.T) {
	code := "my-secret-extract-code"

	// 测试哈希生成
	hash, err := HashCode(code)
	if err != nil {
		t.Fatalf("HashCode failed: %v", err)
	}

	// 哈希应该不为空
	if hash == "" {
		t.Fatal("Hash should not be empty")
	}

	// 哈希应该与原码不同
	if hash == code {
		t.Fatal("Hash should differ from original code")
	}

	// 正确的码应该验证通过
	if !CheckCode(hash, code) {
		t.Fatal("CheckCode should return true for correct code")
	}

	// 错误的码应该验证失败
	if CheckCode(hash, "wrong-code") {
		t.Fatal("CheckCode should return false for wrong code")
	}

	// 相同的码应该生成不同的哈希（bcrypt 自带 salt）
	hash2, _ := HashCode(code)
	if hash == hash2 {
		t.Fatal("Two hashes of the same code should differ (bcrypt salt)")
	}

	// 但第二个哈希也应该验证通过
	if !CheckCode(hash2, code) {
		t.Fatal("Second hash should also verify correctly")
	}
}

// TestHashCodeEmpty 测试空码
func TestHashCodeEmpty(t *testing.T) {
	_, err := HashCode("")
	if err != nil {
		t.Fatalf("HashCode with empty string should not error: %v", err)
	}
}

// TestCheckCodeWithVariousInputs 测试各种输入
func TestCheckCodeWithVariousInputs(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{"simple", "abc123"},
		{"with spaces", "my code with spaces"},
		{"unicode", "密码🔑"},
		{"long code", "this-is-a-very-long-extract-code-that-should-still-work-with-bcrypt-even-though-it-might-truncate"},
		{"special chars", "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashCode(tt.code)
			if err != nil {
				t.Fatalf("HashCode failed for %s: %v", tt.name, err)
			}
			if !CheckCode(hash, tt.code) {
				t.Fatalf("CheckCode failed for %s", tt.name)
			}
		})
	}
}

// TestGenerateSecureToken 测试安全 token 生成
func TestGenerateSecureToken(t *testing.T) {
	token1, err := GenerateSecureToken()
	if err != nil {
		t.Fatalf("GenerateSecureToken failed: %v", err)
	}

	// Token 不应为空
	if token1 == "" {
		t.Fatal("Token should not be empty")
	}

	// Token 长度应为 64 字符（32 字节的 hex 编码）
	if len(token1) != 64 {
		t.Fatalf("Token length should be 64, got %d", len(token1))
	}

	// 两次生成的 token 应该不同
	token2, _ := GenerateSecureToken()
	if token1 == token2 {
		t.Fatal("Two generated tokens should differ")
	}
}

// TestGenerateSecureTokenUniqueness 批量测试 token 唯一性
func TestGenerateSecureTokenUniqueness(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := GenerateSecureToken()
		if err != nil {
			t.Fatalf("GenerateSecureToken failed at iteration %d: %v", i, err)
		}
		if tokens[token] {
			t.Fatalf("Duplicate token generated at iteration %d", i)
		}
		tokens[token] = true
	}
}
