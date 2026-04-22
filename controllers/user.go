package controllers

import (
	"net/http"

	"backend/models"

	"github.com/gin-gonic/gin"
)

// UserController 用户控制器
type UserController struct {}

// NewUserController 创建用户控制器
func NewUserController() *UserController {
	return &UserController{}
}

// ResetPasswordRequest 重置密码请求
type ResetPasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

// GetProfile 获取用户资料接口
func (uc *UserController) GetProfile(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// 查找用户
	var user models.User
	if result := models.DB.First(&user, userID); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile retrieved successfully",
		"user": gin.H{
			"id":          user.ID,
			"nickname":    user.Nickname,
			"email":       user.Email,
			"note":        user.Note,
			"description": user.Description,
			"status":      user.Status,
			"created_at":  user.CreatedAt,
			"updated_at":  user.UpdatedAt,
		},
	})
}

// ResetPassword 重置密码接口
func (uc *UserController) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// 查找用户
	var user models.User
	if result := models.DB.First(&user, userID); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 检查旧密码
	if !user.CheckPassword(req.OldPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid old password"})
		return
	}

	// 更新密码
	user.Password = req.NewPassword
	if result := models.DB.Save(&user); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

// UpdateProfileRequest 更新用户资料请求
type UpdateProfileRequest struct {
	Nickname string `json:"nickname" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
}

// UpdateProfile 更新用户资料接口
func (uc *UserController) UpdateProfile(c *gin.Context) {
	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// 查找用户
	var user models.User
	if result := models.DB.First(&user, userID); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 检查邮箱是否已被其他用户使用
	if req.Email != user.Email {
		var existingUser models.User
		if result := models.DB.Where("email = ? AND id != ?", req.Email, userID).First(&existingUser); result.Error == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
			return
		}
	}

	// 更新用户信息
	user.Nickname = req.Nickname
	user.Email = req.Email
	if result := models.DB.Save(&user); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

// Logout 退出登录接口
func (uc *UserController) Logout(c *gin.Context) {
	// 验证用户是否已认证
	_, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// 由于 token 是无状态的，后端不需要做特殊处理
	// 前端需要删除本地存储的 token

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// DeleteAccount 删除账户接口
func (uc *UserController) DeleteAccount(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// 软删除用户
	if result := models.DB.Delete(&models.User{}, userID); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account deleted successfully"})
}
