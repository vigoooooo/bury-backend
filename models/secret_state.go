package models

import (
	"time"

	"gorm.io/gorm"
)

// SecretState 秘密状态
type SecretState string

const (
	// SecretStateActive 活跃状态
	SecretStateActive SecretState = "active"
	// SecretStateDecoyAccessed 诱饵被访问
	SecretStateDecoyAccessed SecretState = "decoy_accessed"
	// SecretStateDestroyed 已销毁
	SecretStateDestroyed SecretState = "destroyed"
	// SecretStateExpired 已过期
	SecretStateExpired SecretState = "expired"
)

// SecretStateMachine 秘密状态机
type SecretStateMachine struct {
	secret *Secret
	db     *gorm.DB
}

// NewSecretStateMachine 创建秘密状态机
func NewSecretStateMachine(secret *Secret, db *gorm.DB) *SecretStateMachine {
	return &SecretStateMachine{
		secret: secret,
		db:     db,
	}
}

// CheckState 检查秘密状态
func (sm *SecretStateMachine) CheckState() SecretState {
	// 检查是否已被销毁
	if sm.secret.RemainingViews <= 0 && sm.secret.DestructionMethod == "view" {
		return SecretStateDestroyed
	}

	// 检查是否已过期
	if sm.secret.DestructionMethod == "time" && sm.secret.DestroyTime != nil && sm.secret.DestroyTime.Before(time.Now()) {
		return SecretStateExpired
	}

	// 检查错误尝试次数
	if sm.secret.WrongPasswordDestruction && sm.secret.RemainingAttempts <= 0 {
		return SecretStateDestroyed
	}

	return SecretStateActive
}

// ProcessView 处理秘密查看
func (sm *SecretStateMachine) ProcessView(isDecoy bool) (SecretState, error) {
	// 检查当前状态
	currentState := sm.CheckState()
	if currentState != SecretStateActive {
		return currentState, nil
	}

	// 处理诱饵访问
	if isDecoy {
		if sm.secret.DestroyOnDecoyAccess {
			// 物理删除秘密
			if err := sm.db.Unscoped().Delete(sm.secret).Error; err != nil {
				return currentState, err
			}
			return SecretStateDecoyAccessed, nil
		}
		return SecretStateActive, nil
	}

	// 处理正常访问
	if sm.secret.DestructionMethod == "view" {
		sm.secret.RemainingViews--
		if sm.secret.RemainingViews <= 0 {
			// 物理删除秘密
			if err := sm.db.Unscoped().Delete(sm.secret).Error; err != nil {
				return currentState, err
			}
			return SecretStateDestroyed, nil
		}
		// 更新剩余次数
		if err := sm.db.Save(sm.secret).Error; err != nil {
			return currentState, err
		}
	}

	return SecretStateActive, nil
}

// ProcessWrongPassword 处理错误密码
func (sm *SecretStateMachine) ProcessWrongPassword() (SecretState, error) {
	// 检查当前状态
	currentState := sm.CheckState()
	if currentState != SecretStateActive {
		return currentState, nil
	}

	// 处理错误密码尝试
	if sm.secret.WrongPasswordDestruction {
		sm.secret.RemainingAttempts--
		if sm.secret.RemainingAttempts <= 0 {
			// 物理删除秘密
			if err := sm.db.Unscoped().Delete(sm.secret).Error; err != nil {
				return currentState, err
			}
			return SecretStateDestroyed, nil
		}
		// 更新剩余尝试次数
		if err := sm.db.Save(sm.secret).Error; err != nil {
			return currentState, err
		}
	}

	return SecretStateActive, nil
}

// ResetAttempts 重置错误尝试次数
func (sm *SecretStateMachine) ResetAttempts() error {
	if sm.secret.WrongPasswordDestruction && sm.secret.RemainingAttempts != sm.secret.FailedAttempts {
		sm.secret.RemainingAttempts = sm.secret.FailedAttempts
		return sm.db.Save(sm.secret).Error
	}
	return nil
}

// CleanupExpired 清理过期秘密
func CleanupExpired(db *gorm.DB) error {
	// 清理按时间过期的秘密
	if err := db.Unscoped().Where("destruction_method = ? AND destroy_time < ?", "time", time.Now()).Delete(&Secret{}).Error; err != nil {
		return err
	}

	// 清理按查看次数销毁的秘密
	if err := db.Unscoped().Where("destruction_method = ? AND remaining_views <= 0", "view").Delete(&Secret{}).Error; err != nil {
		return err
	}

	// 清理错误尝试次数耗尽的秘密
	if err := db.Unscoped().Where("wrong_password_destruction = ? AND remaining_attempts <= 0", true).Delete(&Secret{}).Error; err != nil {
		return err
	}

	return nil
}
