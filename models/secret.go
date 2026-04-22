package models

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"

	"github.com/bwmarrin/snowflake"
	"gorm.io/gorm"
)

// Secret 秘密模型
type Secret struct {
	ID                       uint       `json:"id" gorm:"primaryKey;type:bigint unsigned"`
	UserID                   uint       `json:"user_id" gorm:"not null"`
	SecretTitle              string     `json:"secret_title" gorm:"not null"`
	SecretContent            string     `json:"secret_content" gorm:"not null"`
	ExtractCode              string     `json:"extract_code" gorm:"not null"`
	DestructionMethod        string     `json:"destruction_method" gorm:"not null"`
	MaximumViews             int        `json:"maximum_views" gorm:"default:10"`
	RemainingViews           int        `json:"remaining_views" gorm:"default:10"`
	ShowInSecretsList        bool       `json:"show_in_secrets_list" gorm:"default:true"`
	WrongPasswordDestruction bool       `json:"wrong_password_destruction" gorm:"default:false"`
	FailedAttempts           int        `json:"failed_attempts" gorm:"default:1"`
	RemainingAttempts        int        `json:"remaining_attempts" gorm:"default:1"`
	EnableDecoyPassword      bool       `json:"enable_decoy_password" gorm:"default:false"`
	DecoyContent             string     `json:"decoy_content"`
	DecoyPassword            string     `json:"decoy_password"`
	DestroyOnDecoyAccess     bool       `json:"destroy_on_decoy_access" gorm:"default:false"`
	DestroyTime              *time.Time `json:"destroy_time"`
	IsDeleted                bool       `json:"is_deleted" gorm:"default:false"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
	User                     User       `json:"-" gorm:"foreignKey:UserID"`
}

// TableName 指定表名
func (Secret) TableName() string {
	return "secret_tb"
}

// BeforeCreate 创建前生成雪花ID
func (s *Secret) BeforeCreate(tx *gorm.DB) error {
	// 生成雪花ID
	node, err := snowflake.NewNode(1)
	if err != nil {
		return err
	}
	s.ID = uint(node.Generate())
	return nil
}

// Encrypt 加密数据
func Encrypt(text, key string) (string, error) {
	// 解码 base64 密钥
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	// 创建 AES 加密器
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// 创建 GCM 模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// 生成随机 nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// 加密数据
	ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)

	// 编码为 base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 解密数据
func Decrypt(encryptedText, key string) (string, error) {
	// 尝试解码 base64 加密数据
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		// 如果解码失败，可能是未加密的数据，直接返回
		return encryptedText, nil
	}

	// 解码 base64 密钥
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		// 如果密钥解码失败，直接返回原始文本
		return encryptedText, nil
	}

	// 创建 AES 加密器
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		// 如果创建加密器失败，直接返回原始文本
		return encryptedText, nil
	}

	// 创建 GCM 模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		// 如果创建 GCM 失败，直接返回原始文本
		return encryptedText, nil
	}

	// 检查数据长度
	if len(ciphertext) < gcm.NonceSize() {
		// 如果数据长度不够，可能是未加密的数据，直接返回
		return encryptedText, nil
	}

	// 分离 nonce 和密文
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	// 解密数据
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// 如果解密失败，可能是未加密的数据，直接返回
		return encryptedText, nil
	}

	return string(plaintext), nil
}
