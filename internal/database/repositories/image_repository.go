package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"gorm.io/gorm"
)

var (
	ErrImageNotFound = errors.New("image not found in database")
)

// ImageRepository defines the interface for image data operations
type ImageRepository interface {
	Create(ctx context.Context, image *models.Image) error
	FindByUserID(ctx context.Context, userID uint) ([]*models.Image, error)
	FindByImageID(ctx context.Context, imageID string) (*models.Image, error)
	FindByID(ctx context.Context, id uint) (*models.Image, error)
	Delete(ctx context.Context, id uint) error
	DeleteByImageID(ctx context.Context, imageID string) error
	// Add other methods as needed (e.g., Update, List, FindByName)
}

// GormImageRepository implements ImageRepository using GORM
type GormImageRepository struct {
	db *gorm.DB
}

// NewGormImageRepository creates a new GORM image repository
func NewGormImageRepository(db *gorm.DB) *GormImageRepository {
	return &GormImageRepository{db: db}
}

// Create adds a new image record to the database
func (r *GormImageRepository) Create(ctx context.Context, image *models.Image) error {
	if err := r.db.WithContext(ctx).Create(image).Error; err != nil {
		return fmt.Errorf("failed to create image record: %w", err)
	}
	return nil
}

// FindByUserID retrieves all images associated with a user ID
func (r *GormImageRepository) FindByUserID(ctx context.Context, userID uint) ([]*models.Image, error) {
	var images []*models.Image
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&images).Error; err != nil {
		return nil, fmt.Errorf("failed to find images by user ID: %w", err)
	}
	return images, nil
}

// FindByImageID retrieves an image by its Docker image ID (SHA)
func (r *GormImageRepository) FindByImageID(ctx context.Context, imageID string) (*models.Image, error) {
	var image models.Image
	// Use First to get only one record or return error if not found
	err := r.db.WithContext(ctx).Where("image_id = ?", imageID).First(&image).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrImageNotFound
		}
		return nil, fmt.Errorf("failed to find image by image ID: %w", err)
	}
	return &image, nil
}

// FindByID retrieves an image by its database ID
func (r *GormImageRepository) FindByID(ctx context.Context, id uint) (*models.Image, error) {
	var image models.Image
	err := r.db.WithContext(ctx).First(&image, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrImageNotFound
		}
		return nil, fmt.Errorf("failed to find image by ID: %w", err)
	}
	return &image, nil
}

// Delete removes an image record by its database ID
func (r *GormImageRepository) Delete(ctx context.Context, id uint) error {
	result := r.db.WithContext(ctx).Delete(&models.Image{}, id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete image by ID: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrImageNotFound // Or handle as needed if delete should be idempotent
	}
	return nil
}

// DeleteByImageID removes all image records associated with a Docker image ID
func (r *GormImageRepository) DeleteByImageID(ctx context.Context, imageID string) error {
	result := r.db.WithContext(ctx).Where("image_id = ?", imageID).Delete(&models.Image{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete images by image ID: %w", result.Error)
	}
	// No error if RowsAffected is 0, as it might have already been deleted
	return nil
}
