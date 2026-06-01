package routes

import (
	"backend/config"
	"backend/controllers"
	"backend/middlewares"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// SetupRouter 设置路由
func SetupRouter(cfg *config.Config) *gin.Engine {
	r := gin.Default()

	// 安全响应头中间件
	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		if cfg.IsTLSEnabled() {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	})

	// 配置 CORS - 使用配置文件中的允许来源
	allowedOrigins := cfg.GetAllowedOrigins()
	if len(allowedOrigins) == 0 {
		// 开发环境兜底
		allowedOrigins = []string{"http://localhost:5173", "http://127.0.0.1:5173"}
	}

	// 构建 origin 白白名单 map（用于 AllowOriginFunc）
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[o] = true
	}

	r.Use(cors.New(cors.Config{
		AllowOriginFunc: func(origin string) bool {
			// 白名单中的 origin 直接允许
			if originSet[origin] {
				return true
			}
			// 允许 Capacitor 自定义协议
			if strings.HasPrefix(origin, "capacitor://") {
				return true
			}
			// 允许 ionic:// 协议
			if strings.HasPrefix(origin, "ionic://") {
				return true
			}
			return false
		},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Extract-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// 全局速率限制
	rateLimit := cfg.GetRateLimitPerMin()
	if rateLimit <= 0 {
		rateLimit = 60 // 默认每分钟60次
	}
	r.Use(middlewares.RateLimitMiddleware(rateLimit))

	// 创建控制器
	authController := controllers.NewAuthController(cfg)
	secretController := controllers.NewSecretController()
	userController := controllers.NewUserController()

	// 认证中间件
	authMiddleware := middlewares.AuthMiddleware(cfg)

	// API 路由组
	api := r.Group("/api/v1")
	{
		// 认证路由
		auth := api.Group("/auth")
		{
			auth.POST("/register", authController.Register)
			auth.POST("/login", authController.Login)
		}

		// 秘密路由
		secret := api.Group("/secret")
		{
			// 需要认证的路由
			authSecret := secret.Group("/")
			authSecret.Use(authMiddleware)
			{
				authSecret.POST("/new", secretController.CreateSecret)
				authSecret.POST("/update", secretController.UpdateSecret)
				authSecret.DELETE("/delete/:id", secretController.DeleteSecret)
				authSecret.DELETE("/delete_all", secretController.DeleteAll)
				authSecret.GET("/query", secretController.QuerySecret)
				authSecret.GET("/get-for-edit/:id", secretController.GetSecretForEdit)
			}

			// 不需要认证的路由（分享提取场景）
			secret.GET("/get/:id", secretController.GetSecret)
			secret.POST("/verify", secretController.VerifySecret)
		}

		// 用户路由（需要认证）
		user := api.Group("/user")
		user.Use(authMiddleware)
		{
			user.GET("/get", userController.GetProfile)
			user.POST("/update", userController.UpdateProfile)
			user.POST("/reset_password", userController.ResetPassword)
			user.POST("/logout", userController.Logout)
			user.DELETE("/delete_account", userController.DeleteAccount)
		}
	}

	return r
}
