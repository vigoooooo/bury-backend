package config

import (
	"fmt"
	"os"
)

// Config 应用配置
type Config struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	JWTSecret  string
	ServerPort string
}

// LoadConfig 加载配置
func LoadConfig() *Config {
	return &Config{
		DBHost:     getEnv("MYSQL_HOST", "127.0.0.1"),
		DBPort:     getEnv("MYSQL_PORT", "3306"),
		DBUser:     getEnv("MYSQL_USER", "dev"),
		DBPassword: getEnv("MYSQL_PASSWORD", "tianxiang"),
		DBName:     getEnv("MYSQL_DATABASE", "bury"),
		JWTSecret:  getEnv("JWT_SECRET", "your-secret-key"),
		ServerPort: getEnv("SERVER_PORT", "8080"),
	}
}

// GetDSN 获取数据库连接字符串
func (c *Config) GetDSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName)
}

// getEnv 获取环境变量，如果不存在则返回默认值
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
