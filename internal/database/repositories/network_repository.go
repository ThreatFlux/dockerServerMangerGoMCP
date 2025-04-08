package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"gorm.io/gorm"
)

// NetworkRepository defines the interface for network data operations
type NetworkRepository interface {
	Create(ctx context.Context, network *models.Network) error
	FindByID(ctx context.Context, id uint) (*models.Network, error)
	FindByNetworkID(ctx context.Context, networkID string) (*models.Network, error)
	FindByUserID(ctx context.Context, userID uint) ([]*models.Network, error)
	Update(ctx context.Context, network *models.Network) error
	Delete(ctx context.Context, id uint) error
	DeleteByNetworkID(ctx context.Context, networkID string) error
	List(ctx context.Context, options ListOptions) ([]*models.Network, int64, error)
}

// gormNetworkRepository implements the NetworkRepository interface using GORM
type gormNetworkRepository struct {
	db *gorm.DB
}

// NewGormNetworkRepository creates a new GORM network repository
func NewGormNetworkRepository(db *gorm.DB) NetworkRepository {
	return &gormNetworkRepository{db: db}
}

// Create creates a new network record in the database
func (r *gormNetworkRepository) Create(ctx context.Context, network *models.Network) error {
	if err := r.db.WithContext(ctx).Create(network).Error; err != nil {
		// TODO: Handle potential duplicate errors more gracefully
		return fmt.Errorf("failed to create network record: %w", err)
	}
	return nil
}

// FindByID finds a network record by its database ID
func (r *gormNetworkRepository) FindByID(ctx context.Context, id uint) (*models.Network, error) {
	var network models.Network
	if err := r.db.WithContext(ctx).First(&network, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNetworkNotFound
		}
		return nil, fmt.Errorf("failed to find network by ID: %w", err)
	}
	return &network, nil
}

// FindByNetworkID finds a network record by its Docker Network ID
func (r *gormNetworkRepository) FindByNetworkID(ctx context.Context, networkID string) (*models.Network, error) {
	var network models.Network
	if err := r.db.WithContext(ctx).Where("network_id = ?", networkID).First(&network).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNetworkNotFound
		}
		return nil, fmt.Errorf("failed to find network by Docker Network ID: %w", err)
	}
	return &network, nil
}

// FindByUserID finds all network records associated with a user ID
func (r *gormNetworkRepository) FindByUserID(ctx context.Context, userID uint) ([]*models.Network, error) {
	var networks []*models.Network
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&networks).Error; err != nil {
		return nil, fmt.Errorf("failed to find networks by user ID: %w", err)
	}
	return networks, nil
}

// Update updates an existing network record in the database
func (r *gormNetworkRepository) Update(ctx context.Context, network *models.Network) error {
	if network.ID == 0 {
		return errors.New("cannot update network record without ID")
	}
	result := r.db.WithContext(ctx).Save(network)
	if result.Error != nil {
		return fmt.Errorf("failed to update network record: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNetworkNotFound // Or a more specific update error
	}
	return nil
}

// Delete deletes a network record by its database ID
func (r *gormNetworkRepository) Delete(ctx context.Context, id uint) error {
	result := r.db.WithContext(ctx).Delete(&models.Network{}, id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete network record: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNetworkNotFound
	}
	return nil
}

// DeleteByNetworkID deletes network records by Docker Network ID
func (r *gormNetworkRepository) DeleteByNetworkID(ctx context.Context, networkID string) error {
	result := r.db.WithContext(ctx).Where("network_id = ?", networkID).Delete(&models.Network{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete network records by Docker Network ID: %w", result.Error)
	}
	// Don't return ErrNetworkNotFound here, as it's okay if no records matched
	return nil
}

// List retrieves a paginated list of networks based on options
func (r *gormNetworkRepository) List(ctx context.Context, options ListOptions) ([]*models.Network, int64, error) {
	var networks []*models.Network
	var total int64

	query := r.db.WithContext(ctx).Model(&models.Network{})

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
		return nil, 0, fmt.Errorf("failed to count networks: %w", err)
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
	if err := query.Find(&networks).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list networks: %w", err)
	}

	return networks, total, nil
}

// Common repository errors (consider moving to a shared errors package)
var (
	ErrNetworkNotFound = errors.New("network not found in database")
)
