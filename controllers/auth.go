package controllers

import (
	"net/http"

	"backend/config"
	"backend/models"
	"backend/utils"

	"github.com/gin-gonic/gin"
)

// AuthController 认证控制器
type AuthController struct {
	cfg *config.Config
}

// NewAuthController 创建认证控制器
func NewAuthController(cfg *config.Config) *AuthController {
	return &AuthController{cfg: cfg}
}

// RegisterRequest 注册请求
type RegisterRequest struct {
	Nickname    string `json:"nickname" binding:"required"`
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required,min=6"`
	Note        string `json:"note"`
	Description string `json:"description"`
}

// LoginRequest 登录请求
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Register 注册接口
func (ac *AuthController) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 检查邮箱是否已存在
	var existingUser models.User
	if result := models.DB.Where("email = ?", req.Email).First(&existingUser); result.Error == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		return
	}

	// 创建新用户
	user := models.User{
		Nickname:    req.Nickname,
		Email:       req.Email,
		Password:    req.Password,
		Note:        req.Note,
		Description: req.Description,
		Status:      "active",
	}

	if result := models.DB.Create(&user); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// 生成 JWT 令牌
	token, err := utils.GenerateToken(user.ID, ac.cfg.GetJWTSecret())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"token":   token,
		"user": gin.H{
			"id":          user.ID,
			"nickname":    user.Nickname,
			"email":       user.Email,
			"note":        user.Note,
			"description": user.Description,
			"status":      user.Status,
			"created_at":  user.CreatedAt,
		},
	})
}

// Login 登录接口
func (ac *AuthController) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 查找用户
	var user models.User
	if result := models.DB.Where("email = ?", req.Email).First(&user); result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// 检查密码
	if !user.CheckPassword(req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// 生成 JWT 令牌
	token, err := utils.GenerateToken(user.ID, ac.cfg.GetJWTSecret())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token,
		"user": gin.H{
			"id":          user.ID,
			"nickname":    user.Nickname,
			"email":       user.Email,
			"note":        user.Note,
			"description": user.Description,
			"status":      user.Status,
			"created_at":  user.CreatedAt,
		},
	})
}
