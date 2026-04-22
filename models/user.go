package models

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// User 用户模型
type User struct {
	ID            uint           `json:"id" gorm:"primaryKey;type:bigint unsigned"`
	Nickname      string         `json:"nickname" gorm:"not null"`
	Email         string         `json:"email" gorm:"unique;not null"`
	Password      string         `json:"-" gorm:"not null"`
	Note          string         `json:"note"`
	Description   string         `json:"description"`
	EncryptionKey string         `json:"-" gorm:"not null;type:varchar(255)"`
	IsDeleted     bool           `json:"is_deleted" gorm:"default:false"`
	Status        string         `json:"status" gorm:"default:active"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `json:"-" gorm:"index"`
}

// BeforeSave 保存前加密密码
func (u *User) BeforeSave(tx *gorm.DB) error {
	// 只有当密码被修改时才进行哈希处理
	// 检查密码是否已经是哈希过的（bcrypt 哈希值长度固定为 60）
	if u.Password != "" && len(u.Password) != 60 {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		u.Password = string(hashedPassword)
	}
	return nil
}

// BeforeCreate 创建前生成加密密钥
func (u *User) BeforeCreate(tx *gorm.DB) error {
	// 生成 32 字节的随机密钥
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return err
	}
	// 编码为 base64 字符串
	u.EncryptionKey = base64.StdEncoding.EncodeToString(key)
	return nil
}

// CheckPassword 检查密码是否正确
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

// TableName 指定表名
func (User) TableName() string {
	return "user_tb"
}
