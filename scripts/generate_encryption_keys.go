package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"backend/config"
	"backend/models"
)

func main() {
	// 加载配置
	cfg := config.LoadConfig()

	// 连接数据库
	if err := models.InitDB(cfg); err != nil {
		fmt.Println("Failed to initialize database:", err)
		return
	}

	// 获取所有没有加密密钥的用户
	var users []models.User
	if result := models.DB.Where("encryption_key = ''").Find(&users); result.Error != nil {
		fmt.Println("Failed to get users:", result.Error)
		return
	}

	// 为每个用户生成加密密钥
	for _, user := range users {
		// 生成 32 字节的随机密钥
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			fmt.Println("Failed to generate key for user", user.ID, ":", err)
			continue
		}
		// 编码为 base64 字符串
		user.EncryptionKey = base64.StdEncoding.EncodeToString(key)

		// 保存用户
		if result := models.DB.Save(&user); result.Error != nil {
			fmt.Println("Failed to save user", user.ID, ":", result.Error)
			continue
		}

		fmt.Printf("Generated encryption key for user %d (%s)\n", user.ID, user.Email)
	}

	fmt.Printf("Generated encryption keys for %d users\n", len(users))
}
