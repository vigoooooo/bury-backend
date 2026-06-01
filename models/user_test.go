package models

import (
	"testing"
)

// TestIsBcryptHash 测试 bcrypt 哈希检测
func TestIsBcryptHash(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"bcrypt $2a$", "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", true},
		{"bcrypt $2b$", "$2b$12$InvalidHashButCorrectPrefix1234567890123456789012345678", true},
		{"bcrypt $2y$", "$2y$10$AnotherValidPrefixHash1234567890123456789012345678901", true},
		{"plain password", "mypassword123", false},
		{"empty string", "", false},
		{"60 char non-bcrypt", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"$1$ prefix (MD5)", "$1$invalid$hash", false},
		{"$5$ prefix (SHA256)", "$5$invalid$hash", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBcryptHash(tt.input)
			if result != tt.expected {
				t.Errorf("isBcryptHash(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestUserBeforeSavePasswordHashing 测试 BeforeSave 中的密码哈希逻辑
func TestUserBeforeSavePasswordHashing(t *testing.T) {
	user := User{
		Nickname: "TestUser",
		Email:    "test@example.com",
		Password: "plaintext_password",
	}

	// BeforeSave 应该哈希明文密码
	err := user.BeforeSave(nil)
	if err != nil {
		t.Fatalf("BeforeSave failed: %v", err)
	}

	// 密码应该已被哈希
	if user.Password == "plaintext_password" {
		t.Fatal("Password should have been hashed")
	}

	// 哈希后的密码应该以 bcrypt 前缀开头
	if !isBcryptHash(user.Password) {
		t.Fatal("Hashed password should have bcrypt prefix")
	}

	// 再次调用 BeforeSave 不应该重复哈希
	hashedOnce := user.Password
	err = user.BeforeSave(nil)
	if err != nil {
		t.Fatalf("Second BeforeSave failed: %v", err)
	}

	if user.Password != hashedOnce {
		t.Fatal("Password should not be re-hashed")
	}
}

// TestCheckPassword 测试密码验证
func TestCheckPassword(t *testing.T) {
	user := User{
		Nickname: "TestUser",
		Email:    "test@example.com",
		Password: "mypassword",
	}

	// 模拟 BeforeSave 哈希
	err := user.BeforeSave(nil)
	if err != nil {
		t.Fatalf("BeforeSave failed: %v", err)
	}

	// 正确的密码应该验证通过
	if !user.CheckPassword("mypassword") {
		t.Fatal("CheckPassword should return true for correct password")
	}

	// 错误的密码应该验证失败
	if user.CheckPassword("wrongpassword") {
		t.Fatal("CheckPassword should return false for wrong password")
	}
}
