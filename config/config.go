package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config 应用配置
type Config struct {
	Database struct {
		Host     string `yaml:"host"`
		Port     string `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Database string `yaml:"database"`
	} `yaml:"database"`
	JWT struct {
		Secret string `yaml:"secret"`
	} `yaml:"jwt"`
	Server struct {
		Port        string `yaml:"port"`
		TLSCertFile string `yaml:"tls_cert_file"`
		TLSKeyFile  string `yaml:"tls_key_file"`
	} `yaml:"server"`
	CORS struct {
		AllowedOrigins []string `yaml:"allowed_origins"`
	} `yaml:"cors"`
	Security struct {
		SnowflakeNodeID int64 `yaml:"snowflake_node_id"`
		RateLimitPerMin int   `yaml:"rate_limit_per_min"`
	} `yaml:"security"`
}

// LoadConfig 加载配置
func LoadConfig() *Config {
	// 获取环境变量，默认为test
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "test"
	}

	// 构建配置文件路径
	configFile := fmt.Sprintf("config_%s.yaml", env)
	configPath := filepath.Join("config", configFile)

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to read config file: %v", err))
	}

	// 解析配置文件
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		panic(fmt.Sprintf("Failed to parse config file: %v", err))
	}

	return &config
}

// GetDSN 获取数据库连接字符串
func (c *Config) GetDSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		c.Database.User, c.Database.Password, c.Database.Host, c.Database.Port, c.Database.Database)
}

// GetDBHost 获取数据库主机
func (c *Config) GetDBHost() string {
	return c.Database.Host
}

// GetDBPort 获取数据库端口
func (c *Config) GetDBPort() string {
	return c.Database.Port
}

// GetDBUser 获取数据库用户
func (c *Config) GetDBUser() string {
	return c.Database.User
}

// GetDBPassword 获取数据库密码
func (c *Config) GetDBPassword() string {
	return c.Database.Password
}

// GetDBName 获取数据库名称
func (c *Config) GetDBName() string {
	return c.Database.Database
}

// GetJWTSecret 获取JWT密钥
func (c *Config) GetJWTSecret() string {
	return c.JWT.Secret
}

// GetServerPort 获取服务器端口
func (c *Config) GetServerPort() string {
	return c.Server.Port
}

// GetTLSCertFile 获取 TLS 证书文件路径
func (c *Config) GetTLSCertFile() string {
	return c.Server.TLSCertFile
}

// GetTLSKeyFile 获取 TLS 私钥文件路径
func (c *Config) GetTLSKeyFile() string {
	return c.Server.TLSKeyFile
}

// IsTLSEnabled 是否启用 TLS
func (c *Config) IsTLSEnabled() bool {
	return c.Server.TLSCertFile != "" && c.Server.TLSKeyFile != ""
}

// GetAllowedOrigins 获取允许的 CORS 来源
func (c *Config) GetAllowedOrigins() []string {
	return c.CORS.AllowedOrigins
}

// GetSnowflakeNodeID 获取雪花ID节点号
func (c *Config) GetSnowflakeNodeID() int64 {
	return c.Security.SnowflakeNodeID
}

// GetRateLimitPerMin 获取每分钟速率限制
func (c *Config) GetRateLimitPerMin() int {
	return c.Security.RateLimitPerMin
}
