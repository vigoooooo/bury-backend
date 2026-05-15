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
	serverAddr := fmt.Sprintf(":%s", cfg.GetServerPort())
	log.Printf("Server starting on %s", serverAddr)
	if err := r.Run(serverAddr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// cleanupSecrets 清理需要销毁的秘密
func cleanupSecrets() {
	log.Println("Running secret cleanup task...")

	// 使用状态机清理过期秘密
	if err := models.CleanupExpired(models.DB); err != nil {
		log.Printf("Error cleaning up expired secrets: %v", err)
	} else {
		log.Println("Secret cleanup task completed")
	}
}
