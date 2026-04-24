package controllers

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"backend/models"

	"github.com/gin-gonic/gin"
)

// TokenInfo token 信息
type TokenInfo struct {
	SecretID  uint64
	CreatedAt time.Time
	IsDecoy   bool
}

// SecretController 秘密控制器
type SecretController struct {
	tokenCache map[string]TokenInfo
	mutex      sync.RWMutex
}

// NewSecretController 创建秘密控制器实例
func NewSecretController() *SecretController {
	controller := &SecretController{
		tokenCache: make(map[string]TokenInfo),
	}

	// 启动定时清理过期 token 的协程
	go controller.cleanupExpiredTokens()

	return controller
}

// cleanupExpiredTokens 清理过期的 token
func (sc *SecretController) cleanupExpiredTokens() {
	for {
		time.Sleep(time.Second * 5)
		sc.mutex.Lock()
		now := time.Now()
		for token, info := range sc.tokenCache {
			if now.Sub(info.CreatedAt) > time.Second*60 {
				delete(sc.tokenCache, token)
			}
		}
		sc.mutex.Unlock()
	}
}

// addToken 添加 token 到缓存
func (sc *SecretController) addToken(token string, secretID uint64, isDecoy bool) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	sc.tokenCache[token] = TokenInfo{
		SecretID:  secretID,
		CreatedAt: time.Now(),
		IsDecoy:   isDecoy,
	}
	// 打印添加的 token
	fmt.Printf("Added token: %s, secretID: %d, isDecoy: %v, time: %v\n", token, secretID, isDecoy, time.Now())
}

// validateToken 验证 token 是否有效
func (sc *SecretController) validateToken(token string) (uint64, bool, bool) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	// 打印当前缓存中的所有 token
	fmt.Printf("Current tokens in cache: %d\n", len(sc.tokenCache))
	for t := range sc.tokenCache {
		fmt.Printf("Token in cache: %s\n", t)
	}

	info, exists := sc.tokenCache[token]
	if !exists {
		fmt.Printf("Token not found: %s\n", token)
		return 0, false, false
	}

	// 检查 token 是否过期
	fmt.Printf("Token found: %s, secretID: %d, created at: %v, current time: %v\n", token, info.SecretID, info.CreatedAt, time.Now())
	if time.Now().Sub(info.CreatedAt) > time.Second*60 {
		fmt.Printf("Token expired: %s\n", token)
		delete(sc.tokenCache, token)
		return 0, false, false
	}

	// 验证通过后删除 token，确保只能使用一次
	fmt.Printf("Token validated and removed: %s\n", token)
	delete(sc.tokenCache, token)
	return info.SecretID, true, info.IsDecoy
}

// CreateSecretRequest 创建秘密请求
type CreateSecretRequest struct {
	SecretTitle              string     `json:"secret_title" binding:"required"`
	SecretContent            string     `json:"secret_content" binding:"required"`
	ExtractCode              string     `json:"extract_code" binding:"required"`
	DestructionMethod        string     `json:"destruction_method" binding:"required"`
	MaximumViews             int        `json:"maximum_views"`
	DestroyTime              *time.Time `json:"destroy_time"`
	ShowInSecretsList        bool       `json:"show_in_secrets_list"`
	WrongPasswordDestruction bool       `json:"wrong_password_destruction"`
	FailedAttempts           int        `json:"failed_attempts"`
	EnableDecoyPassword      bool       `json:"enable_decoy_password"`
	DecoyContent             string     `json:"decoy_content"`
	DecoyPassword            string     `json:"decoy_password"`
	DestroyOnDecoyAccess     bool       `json:"destroy_on_decoy_access"`
}

// UpdateSecretRequest 更新秘密请求
type UpdateSecretRequest struct {
	SecretID                 string     `json:"secret_id" binding:"required"`
	ExtractToken             string     `json:"extract_token" binding:"required"`
	SecretTitle              string     `json:"secret_title" binding:"required"`
	SecretContent            string     `json:"secret_content" binding:"required"`
	ExtractCode              string     `json:"extract_code" binding:"required"`
	DestructionMethod        string     `json:"destruction_method" binding:"required"`
	MaximumViews             int        `json:"maximum_views"`
	DestroyTime              *time.Time `json:"destroy_time"`
	ShowInSecretsList        bool       `json:"show_in_secrets_list"`
	WrongPasswordDestruction bool       `json:"wrong_password_destruction"`
	FailedAttempts           int        `json:"failed_attempts"`
	EnableDecoyPassword      bool       `json:"enable_decoy_password"`
	DecoyContent             string     `json:"decoy_content"`
	DecoyPassword            string     `json:"decoy_password"`
	DestroyOnDecoyAccess     bool       `json:"destroy_on_decoy_access"`
}

// CreateSecret 创建秘密接口
func (sc *SecretController) CreateSecret(c *gin.Context) {
	var req CreateSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	secret := models.Secret{
		UserID:                   userID.(uint),
		SecretTitle:              req.SecretTitle,
		SecretContent:            req.SecretContent,
		ExtractCode:              req.ExtractCode,
		DestructionMethod:        req.DestructionMethod,
		MaximumViews:             req.MaximumViews,
		RemainingViews:           req.MaximumViews,
		ShowInSecretsList:        req.ShowInSecretsList,
		WrongPasswordDestruction: req.WrongPasswordDestruction,
		FailedAttempts:           req.FailedAttempts,
		RemainingAttempts:        req.FailedAttempts,
		EnableDecoyPassword:      req.EnableDecoyPassword,
		DecoyContent:             req.DecoyContent,
		DecoyPassword:            req.DecoyPassword,
		DestroyOnDecoyAccess:     req.DestroyOnDecoyAccess,
		DestroyTime:              req.DestroyTime,
	}

	if result := models.DB.Create(&secret); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create secret"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Secret created successfully",
		"secret":  secret,
	})
}

// UpdateSecret 更新秘密接口
func (sc *SecretController) UpdateSecret(c *gin.Context) {
	var req UpdateSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// 验证 extract token
	secretID, err := strconv.ParseUint(req.SecretID, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid secret ID"})
		return
	}

	validSecretID, valid, _ := sc.validateToken(req.ExtractToken)
	if !valid || validSecretID != secretID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired extract token"})
		return
	}

	// 查找秘密
	var secret models.Secret
	if result := models.DB.Where("id = ? AND user_id = ? AND is_deleted = ?", secretID, userID, false).First(&secret); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
		return
	}

	// 更新秘密
	secret.SecretTitle = req.SecretTitle
	secret.SecretContent = req.SecretContent
	secret.ExtractCode = req.ExtractCode
	secret.DestructionMethod = req.DestructionMethod
	secret.MaximumViews = req.MaximumViews
	secret.RemainingViews = req.MaximumViews // 重置剩余查看次数
	secret.ShowInSecretsList = req.ShowInSecretsList
	secret.WrongPasswordDestruction = req.WrongPasswordDestruction
	secret.FailedAttempts = req.FailedAttempts
	secret.RemainingAttempts = req.FailedAttempts // 重置剩余尝试次数
	secret.EnableDecoyPassword = req.EnableDecoyPassword
	secret.DecoyContent = req.DecoyContent
	secret.DecoyPassword = req.DecoyPassword
	secret.DestroyOnDecoyAccess = req.DestroyOnDecoyAccess
	secret.DestroyTime = req.DestroyTime

	if result := models.DB.Save(&secret); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update secret"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Secret updated successfully",
		"secret":  secret,
	})
}

// DeleteSecret 删除秘密接口
func (sc *SecretController) DeleteSecret(c *gin.Context) {
	secretID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid secret ID"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// 检查秘密是否存在且属于当前用户
	var secret models.Secret
	if result := models.DB.Where("id = ? AND user_id = ?", secretID, userID).First(&secret); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
		return
	}

	// 物理删除秘密
	if result := models.DB.Unscoped().Delete(&secret); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete secret"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Secret deleted successfully"})
}

// DeleteAll 删除所有秘密接口
func (sc *SecretController) DeleteAll(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// 物理删除用户的所有秘密
	if result := models.DB.Unscoped().Where("user_id = ?", userID).Delete(&models.Secret{}); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete secrets"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "All secrets deleted successfully"})
}

// SecretResponse 秘密响应结构
type SecretResponse struct {
	ID                   string     `json:"id"`
	SecretTitle          string     `json:"secret_title"`
	DestructionMethod    string     `json:"destruction_method"`
	MaximumViews         int        `json:"maximum_views"`
	RemainingViews       int        `json:"remaining_views"`
	ShowInSecretsList    bool       `json:"show_in_secrets_list"`
	EnableDecoyPassword  bool       `json:"enable_decoy_password"`
	DestroyOnDecoyAccess bool       `json:"destroy_on_decoy_access"`
	DestroyTime          *time.Time `json:"destroy_time"`
	CreatedAt            time.Time  `json:"created_at"`
}

// QuerySecret 查询秘密接口
func (sc *SecretController) QuerySecret(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// 获取分页参数
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	offset := (page - 1) * pageSize

	// 获取用户的加密密钥
	var user models.User
	if result := models.DB.Where("id = ?", userID).First(&user); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user information"})
		return
	}

	// 查询用户的秘密（不包括已删除的），支持分页
	var secrets []models.Secret
	var total int64

	// 获取总数
	models.DB.Model(&models.Secret{}).Where("user_id = ? AND is_deleted = ?", userID, false).Count(&total)

	// 获取分页数据，按更新时间降序排序
	if result := models.DB.Where("user_id = ? AND is_deleted = ?", userID, false).Order("updated_at DESC").Offset(offset).Limit(pageSize).Find(&secrets); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query secrets"})
		return
	}

	// 转换为响应结构
	responseSecrets := make([]SecretResponse, len(secrets))
	for i, secret := range secrets {
		// 创建响应对象
		responseSecrets[i] = SecretResponse{
			ID:                   strconv.FormatUint(uint64(secret.ID), 10),
			SecretTitle:          secret.SecretTitle,
			DestructionMethod:    secret.DestructionMethod,
			MaximumViews:         secret.MaximumViews,
			RemainingViews:       secret.RemainingViews,
			ShowInSecretsList:    secret.ShowInSecretsList,
			EnableDecoyPassword:  secret.EnableDecoyPassword,
			DestroyOnDecoyAccess: secret.DestroyOnDecoyAccess,
			DestroyTime:          secret.DestroyTime,
			CreatedAt:            secret.CreatedAt,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Secrets queried successfully",
		"secrets":    responseSecrets,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": (total + int64(pageSize) - 1) / int64(pageSize),
	})
}

// MinimalSecretResponse 最小秘密响应
type MinimalSecretResponse struct {
	ID            string `json:"id"`
	SecretContent string `json:"secret_content"`
}

// GetSecret 获取秘密接口
func (sc *SecretController) GetSecret(c *gin.Context) {
	secretID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid secret ID"})
		return
	}

	// 获取 token
	extractToken := c.GetHeader("X-Extract-Token")
	if extractToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing extract token"})
		return
	}

	// 验证 token
	validSecretID, valid, isDecoy := sc.validateToken(extractToken)
	if !valid || validSecretID != secretID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired extract token"})
		return
	}

	// 检查秘密是否存在
	var secret models.Secret
	if result := models.DB.Where("id = ? AND is_deleted = ?", secretID, false).First(&secret); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
		return
	}

	// 创建最小响应
	minimalSecret := MinimalSecretResponse{
		ID: strconv.FormatUint(uint64(secret.ID), 10),
	}

	// 使用状态机处理访问
	stateMachine := models.NewSecretStateMachine(&secret, models.DB)
	_, err = stateMachine.ProcessView(isDecoy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process secret view"})
		return
	}

	// 如果是诱饵码，返回诱饵内容
	if isDecoy {
		minimalSecret.SecretContent = secret.DecoyContent
	} else {
		minimalSecret.SecretContent = secret.SecretContent
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Secret retrieved successfully",
		"secret":  minimalSecret,
	})
}

// GetSecretForEdit 获取秘密详情供编辑使用接口
func (sc *SecretController) GetSecretForEdit(c *gin.Context) {
	secretID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid secret ID"})
		return
	}

	// 验证用户身份
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// 获取 token
	extractToken := c.GetHeader("X-Extract-Token")
	if extractToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing extract token"})
		return
	}

	// 验证 token（不删除token，因为还需要用于后续的UpdateSecret操作）
	sc.mutex.RLock()
	info, exists := sc.tokenCache[extractToken]
	sc.mutex.RUnlock()

	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid extract token"})
		return
	}

	// 检查 token 是否过期
	if time.Now().Sub(info.CreatedAt) > time.Second*60 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Expired extract token"})
		return
	}

	// 检查 token 是否对应正确的秘密
	if info.SecretID != secretID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid extract token for this secret"})
		return
	}

	// 检查秘密是否存在且属于当前用户
	var secret models.Secret
	if result := models.DB.Where("id = ? AND user_id = ?", secretID, userID).First(&secret); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
		return
	}

	// 检查秘密是否已删除
	if secret.IsDeleted {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret has been deleted"})
		return
	}

	// 创建完整的编辑响应
	editSecretResponse := struct {
		ID                       string     `json:"id"`
		SecretTitle              string     `json:"secret_title"`
		SecretContent            string     `json:"secret_content"`
		ExtractCode              string     `json:"extract_code"`
		DestructionMethod        string     `json:"destruction_method"`
		MaximumViews             int        `json:"maximum_views"`
		DestroyTime              *time.Time `json:"destroy_time"`
		ShowInSecretsList        bool       `json:"show_in_secrets_list"`
		WrongPasswordDestruction bool       `json:"wrong_password_destruction"`
		FailedAttempts           int        `json:"failed_attempts"`
		EnableDecoyPassword      bool       `json:"enable_decoy_password"`
		DecoyContent             string     `json:"decoy_content"`
		DecoyPassword            string     `json:"decoy_password"`
		DestroyOnDecoyAccess     bool       `json:"destroy_on_decoy_access"`
	}{
		ID:                       strconv.FormatUint(uint64(secret.ID), 10),
		SecretTitle:              secret.SecretTitle,
		SecretContent:            secret.SecretContent,
		ExtractCode:              secret.ExtractCode,
		DestructionMethod:        secret.DestructionMethod,
		MaximumViews:             secret.MaximumViews,
		DestroyTime:              secret.DestroyTime,
		ShowInSecretsList:        secret.ShowInSecretsList,
		WrongPasswordDestruction: secret.WrongPasswordDestruction,
		FailedAttempts:           secret.FailedAttempts,
		EnableDecoyPassword:      secret.EnableDecoyPassword,
		DecoyContent:             secret.DecoyContent,
		DecoyPassword:            secret.DecoyPassword,
		DestroyOnDecoyAccess:     secret.DestroyOnDecoyAccess,
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Secret retrieved successfully for edit",
		"secret":  editSecretResponse,
	})
}

// VerifySecretRequest 验证秘密请求
type VerifySecretRequest struct {
	SecretID string `json:"secret_id" binding:"required"`
	Code     string `json:"code" binding:"required"`
	Mode     string `json:"mode"` // edit 或 view，默认为 view
}

// VerifySecret 验证秘密接口
func (sc *SecretController) VerifySecret(c *gin.Context) {
	var req VerifySecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 转换 secret_id 为 uint64
	secretID, err := strconv.ParseUint(req.SecretID, 10, 64)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"is_valid":      false,
			"extract_token": "",
		})
		return
	}

	// 检查秘密是否存在
	var secret models.Secret
	if result := models.DB.Where("id = ?", secretID).First(&secret); result.Error != nil {
		c.JSON(http.StatusOK, gin.H{
			"is_valid":      false,
			"extract_token": "",
		})
		return
	}

	// 检查是否需要销毁秘密
	if secret.DestructionMethod == "view" && secret.RemainingViews <= 0 {
		// 物理删除秘密
		models.DB.Unscoped().Delete(&secret)
		c.JSON(http.StatusOK, gin.H{
			"is_valid":      false,
			"extract_token": "",
		})
		return
	}

	// 解密提取码和诱饵密码
	const encryptionKey = "bury-secret-key-2026" // 与前端使用相同的密钥

	// 解密提取码
	decryptedExtractCode, err := models.Decrypt(secret.ExtractCode, encryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"is_valid":      false,
			"extract_token": "",
		})
		return
	}

	// 检查是否是诱饵码
	isDecoy := false
	if secret.EnableDecoyPassword && secret.DecoyPassword != "" {
		// 解密诱饵密码
		decryptedDecoyPassword, err := models.Decrypt(secret.DecoyPassword, encryptionKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"is_valid":      false,
				"extract_token": "",
			})
			return
		}
		if decryptedDecoyPassword == req.Code {
			isDecoy = true
		}
	}

	// 验证提取码
	if req.Mode == "edit" {
		// 在edit模式下，只有输入正确的Extractcode才能验证成功
		if decryptedExtractCode != req.Code {
			// 使用状态机处理错误密码
			stateMachine := models.NewSecretStateMachine(&secret, models.DB)
			_, err := stateMachine.ProcessWrongPassword()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"is_valid":      false,
					"extract_token": "",
				})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"is_valid":      false,
				"extract_token": "",
			})
			return
		}
	} else {
		// 在view模式下，真正的提取码或诱饵码都可以通过验证
		if decryptedExtractCode != req.Code && !isDecoy {
			// 使用状态机处理错误密码
			stateMachine := models.NewSecretStateMachine(&secret, models.DB)
			_, err := stateMachine.ProcessWrongPassword()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"is_valid":      false,
					"extract_token": "",
				})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"is_valid":      false,
				"extract_token": "",
			})
			return
		}
	}

	// 重置错误尝试次数
	stateMachine := models.NewSecretStateMachine(&secret, models.DB)
	if err := stateMachine.ResetAttempts(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"is_valid":      false,
			"extract_token": "",
		})
		return
	}

	// 生成 extract_token
	extractToken := "extract_token_" + strconv.FormatUint(secretID, 10) + "_" + strconv.FormatInt(time.Now().Unix(), 10)

	// 将 token 添加到缓存，标记是否为诱饵
	sc.addToken(extractToken, secretID, isDecoy)

	c.JSON(http.StatusOK, gin.H{
		"is_valid":      true,
		"extract_token": extractToken,
	})
}
