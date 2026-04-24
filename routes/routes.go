package routes

import (
	"backend/config"
	"backend/controllers"
	"backend/middlewares"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// SetupRouter 设置路由
func SetupRouter(cfg *config.Config) *gin.Engine {
	r := gin.Default()

	// 配置 CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Extract-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

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

		// 秘密路由（需要认证）
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

			// 不需要认证的路由
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
