package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Common repository errors
var (
	ErrNotFound          = errors.New("entity not found")
	ErrDuplicateKey      = errors.New("duplicate key violation")
	ErrInvalidInput      = errors.New("invalid input")
	ErrDatabaseOperation = errors.New("database operation failed")
	ErrForeignKey        = errors.New("foreign key violation")
	ErrConcurrentUpdate  = errors.New("concurrent update detected")
)

// UserRepository defines the interface for user data operations
type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id uint) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, id uint) error
	List(ctx context.Context, offset, limit int) ([]models.User, int64, error)
	UpdateRoles(ctx context.Context, userID uint, roles []models.Role) error
	UpdatePassword(ctx context.Context, userID uint, hashedPassword string) error
	UpdateLastLogin(ctx context.Context, userID uint) error
	ActivateUser(ctx context.Context, userID uint) error
	DeactivateUser(ctx context.Context, userID uint) error
	SetEmailVerified(ctx context.Context, userID uint, verified bool) error
	CheckEmailExists(ctx context.Context, email string) (bool, error)
	OptimisticUpdate(ctx context.Context, user *models.User) error
}

// userRepo implements the UserRepository interface
type userRepo struct {
	db *gorm.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB) UserRepository { // Return interface type
	return &userRepo{ // Instantiate concrete type
		db: db,
	}
}

// Create creates a new user
func (r *userRepo) Create(ctx context.Context, user *models.User) error { // Change receiver
	result := r.db.WithContext(ctx).Create(user)
	if result.Error != nil {
		if isDuplicateKeyError(result.Error) {
			return fmt.Errorf("%w: email already in use", ErrDuplicateKey)
		}
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}
	return nil
}

// GetByID finds a user by ID
func (r *userRepo) GetByID(ctx context.Context, id uint) (*models.User, error) { // Change receiver
	var user models.User
	result := r.db.WithContext(ctx).
		Preload("Roles").
		First(&user, id)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	return &user, nil
}

// GetByEmail finds a user by email
func (r *userRepo) GetByEmail(ctx context.Context, email string) (*models.User, error) { // Change receiver
	var user models.User
	result := r.db.WithContext(ctx).
		Preload("Roles").
		Where("email = ?", email).
		First(&user)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	return &user, nil
}

// Update updates a user
func (r *userRepo) Update(ctx context.Context, user *models.User) error { // Change receiver
	result := r.db.WithContext(ctx).
		Model(user).
		Omit("CreatedAt"). // Never update CreatedAt
		Updates(user)

	if result.Error != nil {
		if isDuplicateKeyError(result.Error) {
			return fmt.Errorf("%w: email already in use", ErrDuplicateKey)
		}
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// Delete deletes a user
func (r *userRepo) Delete(ctx context.Context, id uint) error { // Change receiver
	result := r.db.WithContext(ctx).Delete(&models.User{}, id)
	if result.Error != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// List lists users with pagination
func (r *userRepo) List(ctx context.Context, offset, limit int) ([]models.User, int64, error) { // Change receiver
	var users []models.User
	var count int64

	// Get total count
	if err := r.db.WithContext(ctx).Model(&models.User{}).Count(&count).Error; err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	// Get users with pagination
	result := r.db.WithContext(ctx).
		Preload("Roles").
		Offset(offset).
		Limit(limit).
		Find(&users)

	if result.Error != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	return users, count, nil
}

// UpdateRoles updates a user's roles
func (r *userRepo) UpdateRoles(ctx context.Context, userID uint, roles []models.Role) error { // Change receiver
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Delete existing roles
		if err := tx.Where("user_id = ?", userID).Delete(&models.UserRole{}).Error; err != nil {
			return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
		}

		// Create new roles
		for _, role := range roles {
			userRole := models.UserRole{
				UserID:    userID,
				Role:      role,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			if err := tx.Create(&userRole).Error; err != nil {
				return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
			}
		}

		return nil
	})
}

// UpdatePassword updates a user's password
func (r *userRepo) UpdatePassword(ctx context.Context, userID uint, hashedPassword string) error { // Change receiver
	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("password", hashedPassword)

	if result.Error != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdateLastLogin updates a user's last login time
func (r *userRepo) UpdateLastLogin(ctx context.Context, userID uint) error { // Change receiver
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("last_login", now)

	if result.Error != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// ActivateUser activates a user
func (r *userRepo) ActivateUser(ctx context.Context, userID uint) error { // Change receiver
	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("active", true)

	if result.Error != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// DeactivateUser deactivates a user
func (r *userRepo) DeactivateUser(ctx context.Context, userID uint) error { // Change receiver
	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("active", false)

	if result.Error != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// SetEmailVerified sets the email_verified flag for a user
func (r *userRepo) SetEmailVerified(ctx context.Context, userID uint, verified bool) error { // Change receiver
	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("email_verified", verified)

	if result.Error != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// CheckEmailExists checks if an email already exists
func (r *userRepo) CheckEmailExists(ctx context.Context, email string) (bool, error) { // Change receiver
	var count int64
	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("email = ?", email).
		Count(&count)

	if result.Error != nil {
		return false, fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	return count > 0, nil
}

// OptimisticUpdate updates a user with optimistic locking
func (r *userRepo) OptimisticUpdate(ctx context.Context, user *models.User) error { // Change receiver
	// Get current version from the database
	var current models.User
	if err := r.db.WithContext(ctx).
		Select("updated_at").
		Where("id = ?", user.ID).
		First(&current).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	// Check if the record has been updated since we loaded it
	if !current.UpdatedAt.Equal(user.UpdatedAt) {
		return ErrConcurrentUpdate
	}

	// Update the record
	result := r.db.WithContext(ctx).
		Model(user).
		Clauses(clause.Returning{}).
		Where("updated_at = ?", user.UpdatedAt).
		Updates(user)

	if result.Error != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrConcurrentUpdate
	}

	return nil
}

// isDuplicateKeyError checks if an error is a duplicate key error
func isDuplicateKeyError(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "duplicate key") ||
		strings.Contains(err.Error(), "Duplicate entry") ||
		strings.Contains(err.Error(), "UNIQUE constraint failed"))
}
