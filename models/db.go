package models

import (
	"log"

	"backend/config"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// InitDB 初始化数据库连接
func InitDB(cfg *config.Config) error {
	var err error
	DB, err = gorm.Open(mysql.Open(cfg.GetDSN()), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return err
	}

	// 自动迁移模型
	err = DB.AutoMigrate(&User{}, &Secret{})
	if err != nil {
		return err
	}

	log.Println("Database connected and migrated successfully")
	return nil
}
