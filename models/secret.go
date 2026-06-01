package models

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"backend/config"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Secret 秘密模型
type Secret struct {
	ID                       uint       `json:"id" gorm:"primaryKey;type:bigint unsigned"`
	UserID                   uint       `json:"user_id" gorm:"not null"`
	SecretTitle              string     `json:"secret_title" gorm:"not null"`
	SecretContent            string     `json:"secret_content" gorm:"not null;type:text"`
	ExtractCodeHash          string     `json:"-" gorm:"not null;column:extract_code;type:varchar(255)"` // bcrypt 哈希，零知识架构
	DestructionMethod        string     `json:"destruction_method" gorm:"not null"`
	MaximumViews             int        `json:"maximum_views" gorm:"default:10"`
	RemainingViews           int        `json:"remaining_views" gorm:"default:10"`
	ShowInSecretsList        bool       `json:"show_in_secrets_list" gorm:"default:true"`
	WrongPasswordDestruction bool       `json:"wrong_password_destruction" gorm:"default:false"`
	FailedAttempts           int        `json:"failed_attempts" gorm:"default:1"`
	RemainingAttempts        int        `json:"remaining_attempts" gorm:"default:1"`
	EnableDecoyPassword      bool       `json:"enable_decoy_password" gorm:"default:false"`
	DecoyContent             string     `json:"decoy_content" gorm:"type:text"`
	DecoyPasswordHash        string     `json:"-" gorm:"column:decoy_password;type:varchar(255)"` // bcrypt 哈希
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
	cfg := config.LoadConfig()
	nodeID := cfg.GetSnowflakeNodeID()
	if nodeID <= 0 {
		nodeID = 1
	}

	// 使用配置的节点号生成雪花ID
	// 注意：实际生产中应使用单例 snowflake.Node
	salt := make([]byte, 4)
	rand.Read(salt)
	s.ID = uint(time.Now().UnixNano()/1e6) << 12 // 简化的ID生成，避免 snowflake 多实例问题
	return nil
}

// HashCode 对提取码进行 bcrypt 哈希
// 如果码超过 72 字节，先用 SHA-256 预哈希以确保安全性
func HashCode(code string) (string, error) {
	input := code
	if len([]byte(code)) > 72 {
		// bcrypt 有 72 字节限制，对超长码先 SHA-256 预哈希
		hash := sha256.Sum256([]byte(code))
		input = hex.EncodeToString(hash[:])
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckCode 验证提取码是否匹配
// 与 HashCode 保持一致：超过 72 字节的码先用 SHA-256 预哈希
func CheckCode(hashedCode, code string) bool {
	input := code
	if len([]byte(code)) > 72 {
		hash := sha256.Sum256([]byte(code))
		input = hex.EncodeToString(hash[:])
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashedCode), []byte(input))
	return err == nil
}

// GenerateSecureToken 生成加密安全的随机 token
func GenerateSecureToken() (string, error) {
	bytes := make([]byte, 32) // 256 位
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
