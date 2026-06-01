package controllers

import (
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
		time.Sleep(time.Second * 30)
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
}

// validateToken 验证 token 是否有效（一次性使用）
func (sc *SecretController) validateToken(token string) (uint64, bool, bool) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	info, exists := sc.tokenCache[token]
	if !exists {
		return 0, false, false
	}

	// 检查 token 是否过期
	if time.Now().Sub(info.CreatedAt) > time.Second*60 {
		delete(sc.tokenCache, token)
		return 0, false, false
	}

	// 验证通过后删除 token，确保只能使用一次
	delete(sc.tokenCache, token)
	return info.SecretID, true, info.IsDecoy
}

// peekToken 查看 token 信息但不删除（用于编辑场景需要复用 token）
func (sc *SecretController) peekToken(token string) (uint64, bool, bool) {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	info, exists := sc.tokenCache[token]
	if !exists {
		return 0, false, false
	}

	// 检查 token 是否过期
	if time.Now().Sub(info.CreatedAt) > time.Second*60 {
		return 0, false, false
	}

	return info.SecretID, true, info.IsDecoy
}

// consumeToken 消费 token（编辑完成后调用）
func (sc *SecretController) consumeToken(token string) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	delete(sc.tokenCache, token)
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
	DecoyUnchanged           bool       `json:"decoy_unchanged"`
	DestroyOnDecoyAccess     bool       `json:"destroy_on_decoy_access"`
}

// sanitizeInput 基本的输入消毒，防止 XSS
func sanitizeInput(input string) string {
	// 移除潜在的 HTML/JS 标签
	result := make([]byte, 0, len(input))
	inTag := false
	for i := 0; i < len(input); i++ {
		if input[i] == '<' {
			inTag = true
			continue
		}
		if input[i] == '>' {
			inTag = false
			continue
		}
		if !inTag {
			result = append(result, input[i])
		}
	}
	return string(result)
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

	// 对提取码进行 bcrypt 哈希（零知识架构：后端只存哈希，不可逆）
	extractCodeHash, err := models.HashCode(req.ExtractCode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to secure extract code"})
		return
	}

	// 对诱饵密码进行 bcrypt 哈希（如果启用）
	var decoyPasswordHash string
	if req.EnableDecoyPassword && req.DecoyPassword != "" {
		hash, err := models.HashCode(req.DecoyPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to secure decoy password"})
			return
		}
		decoyPasswordHash = hash
	}

	secret := models.Secret{
		UserID:                   userID.(uint),
		SecretTitle:              sanitizeInput(req.SecretTitle),
		SecretContent:            req.SecretContent, // 客户端加密的内容，原样存储
		ExtractCodeHash:          extractCodeHash,
		DestructionMethod:        req.DestructionMethod,
		MaximumViews:             req.MaximumViews,
		RemainingViews:           req.MaximumViews,
		ShowInSecretsList:        req.ShowInSecretsList,
		WrongPasswordDestruction: req.WrongPasswordDestruction,
		FailedAttempts:           req.FailedAttempts,
		RemainingAttempts:        req.FailedAttempts,
		EnableDecoyPassword:      req.EnableDecoyPassword,
		DecoyContent:             req.DecoyContent, // 客户端加密的内容，原样存储
		DecoyPasswordHash:        decoyPasswordHash,
		DestroyOnDecoyAccess:     req.DestroyOnDecoyAccess,
		DestroyTime:              req.DestroyTime,
	}

	if result := models.DB.Create(&secret); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create secret"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Secret created successfully",
		"secret": gin.H{
			"id":      strconv.FormatUint(uint64(secret.ID), 10),
			"title":   secret.SecretTitle,
			"created": secret.CreatedAt,
		},
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

	validSecretID, valid, _ := sc.peekToken(req.ExtractToken)
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

	// 对新的提取码进行 bcrypt 哈希
	extractCodeHash, err := models.HashCode(req.ExtractCode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to secure extract code"})
		return
	}

	// 对新的诱饵密码进行 bcrypt 哈希（如果启用且非不变模式）
	var decoyPasswordHash string
	if req.EnableDecoyPassword && !req.DecoyUnchanged && req.DecoyPassword != "" {
		hash, err := models.HashCode(req.DecoyPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to secure decoy password"})
			return
		}
		decoyPasswordHash = hash
	}

	// 更新秘密
	secret.SecretTitle = sanitizeInput(req.SecretTitle)
	secret.SecretContent = req.SecretContent // 客户端加密的内容
	secret.ExtractCodeHash = extractCodeHash
	secret.DestructionMethod = req.DestructionMethod
	secret.MaximumViews = req.MaximumViews
	secret.RemainingViews = req.MaximumViews
	secret.ShowInSecretsList = req.ShowInSecretsList
	secret.WrongPasswordDestruction = req.WrongPasswordDestruction
	secret.FailedAttempts = req.FailedAttempts
	secret.RemainingAttempts = req.FailedAttempts
	secret.EnableDecoyPassword = req.EnableDecoyPassword
	if req.DecoyUnchanged {
		// 诱饵内容不变，保留原有值
		// secret.DecoyContent 和 secret.DecoyPasswordHash 保持不变
	} else {
		secret.DecoyContent = req.DecoyContent // 客户端加密的内容
		secret.DecoyPasswordHash = decoyPasswordHash
	}
	secret.DestroyOnDecoyAccess = req.DestroyOnDecoyAccess
	secret.DestroyTime = req.DestroyTime

	if result := models.DB.Save(&secret); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update secret"})
		return
	}

	// 更新成功后消费 token
	sc.consumeToken(req.ExtractToken)

	c.JSON(http.StatusOK, gin.H{
		"message": "Secret updated successfully",
		"secret": gin.H{
			"id":      strconv.FormatUint(uint64(secret.ID), 10),
			"title":   secret.SecretTitle,
			"updated": secret.UpdatedAt,
		},
	})
}

// DeleteSecret 删除秘密接口
func (sc *SecretController) DeleteSecret(c *gin.Context) {
	secretID, err := strconv.ParseUint(c.Param("id"), 10, 64)
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

	// 查询用户的秘密（不包括已删除的），支持分页
	var secrets []models.Secret
	var total int64

	models.DB.Model(&models.Secret{}).Where("user_id = ? AND is_deleted = ?", userID, false).Count(&total)

	if result := models.DB.Where("user_id = ? AND is_deleted = ?", userID, false).Order("updated_at DESC").Offset(offset).Limit(pageSize).Find(&secrets); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query secrets"})
		return
	}

	// 转换为响应结构（不含任何加密数据）
	responseSecrets := make([]SecretResponse, len(secrets))
	for i, secret := range secrets {
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

// MinimalSecretResponse 最小秘密响应（查看时使用）
type MinimalSecretResponse struct {
	ID            string `json:"id"`
	SecretContent string `json:"secret_content"`
	IsDecoy       bool   `json:"is_decoy"`
}

// GetSecret 获取秘密接口（查看模式）
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
		ID:      strconv.FormatUint(uint64(secret.ID), 10),
		IsDecoy: isDecoy,
	}

	// 使用状态机处理访问
	stateMachine := models.NewSecretStateMachine(&secret, models.DB)
	_, err = stateMachine.ProcessView(isDecoy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process secret view"})
		return
	}

	// 根据是否为诱饵，返回对应的加密内容（客户端用对应的密钥解密）
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

	// 验证 token（peek 模式，不删除）
	validSecretID, valid, _ := sc.peekToken(extractToken)
	if !valid || validSecretID != secretID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired extract token"})
		return
	}

	// 检查秘密是否存在且属于当前用户
	var secret models.Secret
	if result := models.DB.Where("id = ? AND user_id = ?", secretID, userID).First(&secret); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
		return
	}

	if secret.IsDeleted {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret has been deleted"})
		return
	}

	// 零知识架构：不返回 extract_code 和 decoy_password 的明文
	// 只返回加密的内容和元数据，客户端自行解密
	editSecretResponse := struct {
		ID                       string     `json:"id"`
		SecretTitle              string     `json:"secret_title"`
		SecretContent            string     `json:"secret_content"`
		DestructionMethod        string     `json:"destruction_method"`
		MaximumViews             int        `json:"maximum_views"`
		DestroyTime              *time.Time `json:"destroy_time"`
		ShowInSecretsList        bool       `json:"show_in_secrets_list"`
		WrongPasswordDestruction bool       `json:"wrong_password_destruction"`
		FailedAttempts           int        `json:"failed_attempts"`
		EnableDecoyPassword      bool       `json:"enable_decoy_password"`
		DecoyContent             string     `json:"decoy_content"`
		DestroyOnDecoyAccess     bool       `json:"destroy_on_decoy_access"`
	}{
		ID:                       strconv.FormatUint(uint64(secret.ID), 10),
		SecretTitle:              secret.SecretTitle,
		SecretContent:            secret.SecretContent,
		DestructionMethod:        secret.DestructionMethod,
		MaximumViews:             secret.MaximumViews,
		DestroyTime:              secret.DestroyTime,
		ShowInSecretsList:        secret.ShowInSecretsList,
		WrongPasswordDestruction: secret.WrongPasswordDestruction,
		FailedAttempts:           secret.FailedAttempts,
		EnableDecoyPassword:      secret.EnableDecoyPassword,
		DecoyContent:             secret.DecoyContent,
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
			"is_decoy":      false,
		})
		return
	}

	// 检查秘密是否存在
	var secret models.Secret
	if result := models.DB.Where("id = ?", secretID).First(&secret); result.Error != nil {
		c.JSON(http.StatusOK, gin.H{
			"is_valid":      false,
			"extract_token": "",
			"is_decoy":      false,
		})
		return
	}

	// 检查是否需要销毁秘密
	if secret.DestructionMethod == "view" && secret.RemainingViews <= 0 {
		models.DB.Unscoped().Delete(&secret)
		c.JSON(http.StatusOK, gin.H{
			"is_valid":      false,
			"extract_token": "",
			"is_decoy":      false,
		})
		return
	}

	// 零知识架构：使用 bcrypt 比较而非解密
	// 检查是否是诱饵码
	isDecoy := false
	if secret.EnableDecoyPassword && secret.DecoyPasswordHash != "" {
		if models.CheckCode(secret.DecoyPasswordHash, req.Code) {
			isDecoy = true
		}
	}

	// 验证提取码
	if req.Mode == "edit" {
		// edit 模式下，只有正确的提取码才能验证成功（不接受诱饵码）
		if !models.CheckCode(secret.ExtractCodeHash, req.Code) {
			// 使用状态机处理错误密码
			stateMachine := models.NewSecretStateMachine(&secret, models.DB)
			stateMachine.ProcessWrongPassword()
			c.JSON(http.StatusOK, gin.H{
				"is_valid":      false,
				"extract_token": "",
				"is_decoy":      false,
			})
			return
		}
	} else {
		// view 模式下，提取码或诱饵码都可以通过验证
		if !models.CheckCode(secret.ExtractCodeHash, req.Code) && !isDecoy {
			// 使用状态机处理错误密码
			stateMachine := models.NewSecretStateMachine(&secret, models.DB)
			stateMachine.ProcessWrongPassword()
			c.JSON(http.StatusOK, gin.H{
				"is_valid":      false,
				"extract_token": "",
				"is_decoy":      false,
			})
			return
		}
	}

	// 注意：不再重置错误尝试次数
	// 重置尝试次数会破坏安全设计，攻击者可以无限循环尝试

	// 生成加密安全的随机 extract_token
	extractToken, err := models.GenerateSecureToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"is_valid":      false,
			"extract_token": "",
			"is_decoy":      false,
		})
		return
	}

	// 将 token 添加到缓存，标记是否为诱饵
	sc.addToken(extractToken, secretID, isDecoy)

	c.JSON(http.StatusOK, gin.H{
		"is_valid":      true,
		"extract_token": extractToken,
		"is_decoy":      isDecoy,
	})
}
