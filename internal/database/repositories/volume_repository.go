package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"gorm.io/gorm"
)

// VolumeRepository defines the interface for volume data operations
type VolumeRepository interface {
	Create(ctx context.Context, volume *models.Volume) error
	FindByID(ctx context.Context, id uint) (*models.Volume, error)
	FindByVolumeID(ctx context.Context, volumeID string) (*models.Volume, error)
	FindByUserID(ctx context.Context, userID uint) ([]*models.Volume, error)
	Update(ctx context.Context, volume *models.Volume) error
	Delete(ctx context.Context, id uint) error
	DeleteByVolumeID(ctx context.Context, volumeID string) error
	List(ctx context.Context, options ListOptions) ([]*models.Volume, int64, error)
}

// gormVolumeRepository implements the VolumeRepository interface using GORM
type gormVolumeRepository struct {
	db *gorm.DB
}

// NewGormVolumeRepository creates a new GORM volume repository
func NewGormVolumeRepository(db *gorm.DB) VolumeRepository {
	return &gormVolumeRepository{db: db}
}

// Create creates a new volume record in the database
func (r *gormVolumeRepository) Create(ctx context.Context, volume *models.Volume) error {
	if err := r.db.WithContext(ctx).Create(volume).Error; err != nil {
		// TODO: Handle potential duplicate errors more gracefully
		return fmt.Errorf("failed to create volume record: %w", err)
	}
	return nil
}

// FindByID finds a volume record by its database ID
func (r *gormVolumeRepository) FindByID(ctx context.Context, id uint) (*models.Volume, error) {
	var volume models.Volume
	if err := r.db.WithContext(ctx).First(&volume, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrVolumeNotFound
		}
		return nil, fmt.Errorf("failed to find volume by ID: %w", err)
	}
	return &volume, nil
}

// FindByVolumeID finds a volume record by its Docker Volume ID
func (r *gormVolumeRepository) FindByVolumeID(ctx context.Context, volumeID string) (*models.Volume, error) {
	var volume models.Volume
	if err := r.db.WithContext(ctx).Where("volume_id = ?", volumeID).First(&volume).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrVolumeNotFound
		}
		return nil, fmt.Errorf("failed to find volume by Docker Volume ID: %w", err)
	}
	return &volume, nil
}

// FindByUserID finds all volume records associated with a user ID
func (r *gormVolumeRepository) FindByUserID(ctx context.Context, userID uint) ([]*models.Volume, error) {
	var volumes []*models.Volume
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&volumes).Error; err != nil {
		return nil, fmt.Errorf("failed to find volumes by user ID: %w", err)
	}
	return volumes, nil
}

// Update updates an existing volume record in the database
func (r *gormVolumeRepository) Update(ctx context.Context, volume *models.Volume) error {
	if volume.ID == 0 {
		return errors.New("cannot update volume record without ID")
	}
	result := r.db.WithContext(ctx).Save(volume)
	if result.Error != nil {
		return fmt.Errorf("failed to update volume record: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrVolumeNotFound // Or a more specific update error
	}
	return nil
}

// Delete deletes a volume record by its database ID
func (r *gormVolumeRepository) Delete(ctx context.Context, id uint) error {
	result := r.db.WithContext(ctx).Delete(&models.Volume{}, id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete volume record: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrVolumeNotFound
	}
	return nil
}

// DeleteByVolumeID deletes volume records by Docker Volume ID
func (r *gormVolumeRepository) DeleteByVolumeID(ctx context.Context, volumeID string) error {
	result := r.db.WithContext(ctx).Where("volume_id = ?", volumeID).Delete(&models.Volume{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete volume records by Docker Volume ID: %w", result.Error)
	}
	// Don't return ErrVolumeNotFound here, as it's okay if no records matched
	return nil
}

// List retrieves a paginated list of volumes based on options
func (r *gormVolumeRepository) List(ctx context.Context, options ListOptions) ([]*models.Volume, int64, error) {
	var volumes []*models.Volume
	var total int64

	query := r.db.WithContext(ctx).Model(&models.Volume{})

	// Apply filters
	if options.UserID != 0 {
		query = query.Where("user_id = ?", options.UserID)
	}
	if options.Driver != "" {
		query = query.Where("driver = ?", options.Driver)
	}
	if options.Name != "" {
		// Use LIKE for partial name matching if desired
		query = query.Where("name LIKE ?", "%"+options.Name+"%")
	}
	// TODO: Add label filtering if needed

	// Count total records before pagination
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count volumes: %w", err)
	}

	// Apply sorting
	if options.SortBy != "" {
		order := options.SortBy
		if options.SortOrder == "desc" {
			order += " desc"
		}
		query = query.Order(order)
	} else {
		query = query.Order("created_at desc") // Default sort
	}

	// Apply pagination
	if options.PageSize > 0 {
		offset := (options.Page - 1) * options.PageSize
		query = query.Offset(offset).Limit(options.PageSize)
	}

	// Execute query
	if err := query.Find(&volumes).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list volumes: %w", err)
	}

	return volumes, total, nil
}

// ListOptions defines options for listing repository items
// TODO: Consider moving this to a common place if used by multiple repositories
type ListOptions struct {
	Page      int
	PageSize  int
	SortBy    string
	SortOrder string
	UserID    uint   // Filter by user ID
	Driver    string // Filter by driver
	Name      string // Filter by name (partial match)
	// Add other filters like labels if needed
}

// Common repository errors
var (
	ErrVolumeNotFound = errors.New("volume not found in database")
)
