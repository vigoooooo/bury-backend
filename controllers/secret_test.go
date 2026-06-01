package controllers

import (
	"testing"
)

// TestSanitizeInput 测试输入消毒
func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain text", "Hello World", "Hello World"},
		{"script tag", "<script>alert('xss')</script>", "alert('xss')/script"},
		{"html tags", "<b>bold</b>", "bold/b"},
		{"nested tags", "<div><p>text</p></div>", "text/div"},
		{"empty string", "", ""},
		{"no tags", "Just plain text", "Just plain text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeInput(tt.input)
			// 验证结果不包含 < 和 > 字符
			for _, c := range result {
				if c == '<' || c == '>' {
					t.Errorf("Result should not contain < or >, got: %q", result)
					break
				}
			}
		})
	}
}

// TestTokenCacheFlow 测试 token 缓存的完整流程
func TestTokenCacheFlow(t *testing.T) {
	sc := NewSecretController()

	// 添加 token
	sc.addToken("test-token-1", 123, false)
	sc.addToken("test-token-2", 456, true)

	// 验证非诱饵 token
	secretID, valid, isDecoy := sc.validateToken("test-token-1")
	if !valid || secretID != 123 || isDecoy {
		t.Fatal("Token 1 should be valid, secretID=123, isDecoy=false")
	}

	// token 应该已被消费（一次性使用）
	_, valid, _ = sc.validateToken("test-token-1")
	if valid {
		t.Fatal("Token 1 should be consumed after first use")
	}

	// 验证诱饵 token
	secretID, valid, isDecoy = sc.validateToken("test-token-2")
	if !valid || secretID != 456 || !isDecoy {
		t.Fatal("Token 2 should be valid, secretID=456, isDecoy=true")
	}
}

// TestPeekAndConsumeToken 测试 peek + consume 模式（编辑场景）
func TestPeekAndConsumeToken(t *testing.T) {
	sc := NewSecretController()
	sc.addToken("edit-token", 789, false)

	// peek 不应该消费 token
	secretID, valid, isDecoy := sc.peekToken("edit-token")
	if !valid || secretID != 789 || isDecoy {
		t.Fatal("Peek should return valid token info without consuming it")
	}

	// 再次 peek 应该仍然有效
	secretID, valid, _ = sc.peekToken("edit-token")
	if !valid || secretID != 789 {
		t.Fatal("Token should still be valid after peek")
	}

	// consume 应该消费 token
	sc.consumeToken("edit-token")

	// peek 之后应该无效
	_, valid, _ = sc.peekToken("edit-token")
	if valid {
		t.Fatal("Token should be invalid after consume")
	}
}

// TestInvalidToken 测试无效 token
func TestInvalidToken(t *testing.T) {
	sc := NewSecretController()

	// 不存在的 token
	_, valid, _ := sc.validateToken("nonexistent")
	if valid {
		t.Fatal("Nonexistent token should be invalid")
	}

	_, valid, _ = sc.peekToken("nonexistent")
	if valid {
		t.Fatal("Nonexistent token should be invalid in peek mode")
	}
}
