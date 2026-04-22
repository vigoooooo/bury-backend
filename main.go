package main

import (
	"fmt"
	"log"
	"time"

	"backend/config"
	"backend/models"
	"backend/routes"
)

func main() {
	// 加载配置
	cfg := config.LoadConfig()

	// 初始化数据库
	if err := models.InitDB(cfg); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// 启动后台定时任务，每10分钟执行一次
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		// 立即执行一次
		cleanupSecrets()

		for range ticker.C {
			cleanupSecrets()
		}
	}()

	// 设置路由
	r := routes.SetupRouter(cfg)

	// 启动服务器
	serverAddr := fmt.Sprintf(":%s", cfg.ServerPort)
	log.Printf("Server starting on %s", serverAddr)
	if err := r.Run(serverAddr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// cleanupSecrets 清理需要销毁的秘密
func cleanupSecrets() {
	log.Println("Running secret cleanup task...")

	// 1. 清理剩余访问次数为0的秘密
	var viewSecrets []models.Secret
	models.DB.Where("destruction_method = ? AND remaining_views <= 0", "view").Find(&viewSecrets)
	for _, secret := range viewSecrets {
		models.DB.Unscoped().Delete(&secret)
		log.Printf("Deleted secret %d: remaining views reached 0", secret.ID)
	}

	// 2. 清理剩余错误尝试次数为0的秘密
	var attemptSecrets []models.Secret
	models.DB.Where("wrong_password_destruction = ? AND remaining_attempts <= 0", true).Find(&attemptSecrets)
	for _, secret := range attemptSecrets {
		models.DB.Unscoped().Delete(&secret)
		log.Printf("Deleted secret %d: remaining attempts reached 0", secret.ID)
	}

	// 3. 清理到达销毁时间的秘密
	var timeSecrets []models.Secret
	models.DB.Where("destruction_method = ? AND destroy_time <= ?", "time", time.Now()).Find(&timeSecrets)
	for _, secret := range timeSecrets {
		models.DB.Unscoped().Delete(&secret)
		log.Printf("Deleted secret %d: destruction time reached", secret.ID)
	}

	log.Println("Secret cleanup task completed")
}
