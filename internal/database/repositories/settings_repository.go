package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SettingsRepository handles database operations for settings
type SettingsRepository struct {
	db *gorm.DB
}

// NewSettingsRepository creates a new settings repository
func NewSettingsRepository(db *gorm.DB) *SettingsRepository {
	return &SettingsRepository{
		db: db,
	}
}

// GetByKey retrieves settings by key
func (r *SettingsRepository) GetByKey(ctx context.Context, key string) (*models.Setting, error) {
	var setting models.Setting
	result := r.db.WithContext(ctx).
		Where("key = ?", key).
		First(&setting)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	return &setting, nil
}

// GetObject retrieves a setting and unmarshals the JSON value into the provided object
func (r *SettingsRepository) GetObject(ctx context.Context, key string, obj interface{}) error {
	setting, err := r.GetByKey(ctx, key)
	if err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(setting.Value), obj); err != nil {
		return fmt.Errorf("failed to unmarshal setting value: %w", err)
	}

	return nil
}

// SetObject marshals an object to JSON and saves it as a setting
func (r *SettingsRepository) SetObject(ctx context.Context, key string, obj interface{}) error {
	// Marshal object to JSON
	jsonValue, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to marshal object to JSON: %w", err)
	}

	// Save the setting
	return r.Set(ctx, key, string(jsonValue))
}

// Set creates or updates a setting
func (r *SettingsRepository) Set(ctx context.Context, key, value string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Check if setting exists
		var count int64
		if err := tx.Model(&models.Setting{}).Where("key = ?", key).Count(&count).Error; err != nil {
			return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
		}

		now := time.Now()

		if count > 0 {
			// Update existing setting
			result := tx.Model(&models.Setting{}).
				Where("key = ?", key).
				Updates(map[string]interface{}{
					"value":      value,
					"updated_at": now,
				})

			if result.Error != nil {
				return fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
			}
		} else {
			// Create new setting
			setting := models.Setting{
				Key:       key,
				Value:     value,
				CreatedAt: now,
				UpdatedAt: now,
			}

			if err := tx.Create(&setting).Error; err != nil {
				return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
			}
		}

		return nil
	})
}

// Delete deletes a setting
func (r *SettingsRepository) Delete(ctx context.Context, key string) error {
	result := r.db.WithContext(ctx).
		Where("key = ?", key).
		Delete(&models.Setting{})

	if result.Error != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// ListKeys retrieves all setting keys
func (r *SettingsRepository) ListKeys(ctx context.Context) ([]string, error) {
	var keys []string
	result := r.db.WithContext(ctx).
		Model(&models.Setting{}).
		Pluck("key", &keys)

	if result.Error != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	return keys, nil
}

// List retrieves all settings
func (r *SettingsRepository) List(ctx context.Context) ([]models.Setting, error) {
	var settings []models.Setting
	result := r.db.WithContext(ctx).
		Find(&settings)

	if result.Error != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	return settings, nil
}

// GetVersioned retrieves a versioned setting
func (r *SettingsRepository) GetVersioned(ctx context.Context, key string, version int) (*models.VersionedSetting, error) {
	var setting models.VersionedSetting
	result := r.db.WithContext(ctx).
		Where("key = ? AND version = ?", key, version).
		First(&setting)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	return &setting, nil
}

// GetLatestVersioned retrieves the latest version of a versioned setting
func (r *SettingsRepository) GetLatestVersioned(ctx context.Context, key string) (*models.VersionedSetting, error) {
	var setting models.VersionedSetting
	result := r.db.WithContext(ctx).
		Where("key = ?", key).
		Order("version DESC").
		First(&setting)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	return &setting, nil
}

// CreateVersioned creates a new version of a versioned setting
func (r *SettingsRepository) CreateVersioned(ctx context.Context, key, value string, metadata map[string]interface{}) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Get the current latest version
		var currentVersion int
		err := tx.Model(&models.VersionedSetting{}).
			Where("key = ?", key).
			Select("COALESCE(MAX(version), 0)").
			Scan(&currentVersion).Error

		if err != nil {
			return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
		}

		// Create new version
		metadataJSON, err := json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		now := time.Now()
		setting := models.VersionedSetting{
			Key:       key,
			Value:     value,
			Version:   currentVersion + 1,
			Metadata:  string(metadataJSON),
			CreatedAt: now,
		}

		if err := tx.Create(&setting).Error; err != nil {
			return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
		}

		return nil
	})
}

// ListVersions lists all versions of a versioned setting
func (r *SettingsRepository) ListVersions(ctx context.Context, key string) ([]models.VersionedSetting, error) {
	var settings []models.VersionedSetting
	result := r.db.WithContext(ctx).
		Where("key = ?", key).
		Order("version DESC").
		Find(&settings)

	if result.Error != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	return settings, nil
}

// OptimisticUpdate updates a setting with optimistic locking
func (r *SettingsRepository) OptimisticUpdate(ctx context.Context, setting *models.Setting) error {
	// Get current version from the database
	var current models.Setting
	if err := r.db.WithContext(ctx).
		Select("updated_at").
		Where("key = ?", setting.Key).
		First(&current).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	// Check if the record has been updated since we loaded it
	if !current.UpdatedAt.Equal(setting.UpdatedAt) {
		return ErrConcurrentUpdate
	}

	// Update the record
	setting.UpdatedAt = time.Now()
	result := r.db.WithContext(ctx).
		Model(setting).
		Clauses(clause.Returning{}).
		Where("key = ? AND updated_at = ?", setting.Key, current.UpdatedAt).
		Updates(map[string]interface{}{
			"value":      setting.Value,
			"updated_at": setting.UpdatedAt,
		})

	if result.Error != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrConcurrentUpdate
	}

	return nil
}
