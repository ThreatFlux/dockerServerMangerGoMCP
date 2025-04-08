package models

import (
	"time"

	"gorm.io/gorm"
)

// Role represents a user role
type Role string

const (
	// RoleAdmin represents an admin user
	RoleAdmin Role = "admin"
	// RoleUser represents a regular user
	RoleUser Role = "user"
	// RoleGuest represents a guest user
	RoleGuest Role = "guest"
)

// User represents a user in the system
type User struct {
	ID            uint           `json:"id" gorm:"primaryKey"`
	Email         string         `json:"email" gorm:"unique;not null"`
	Password      string         `json:"-" gorm:"not null"` // Password is never returned in JSON
	Name          string         `json:"name"`
	Roles         []UserRole     `json:"roles" gorm:"foreignKey:UserID"`
	LastLogin     *time.Time     `json:"last_login,omitempty"`
	EmailVerified bool           `json:"email_verified" gorm:"default:false"`
	Active        bool           `json:"active" gorm:"default:true"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `json:"-" gorm:"index"`
}

// UserRole represents a user's role
type UserRole struct {
	ID        uint      `json:"-" gorm:"primaryKey"`
	UserID    uint      `json:"-" gorm:"index"`
	Role      Role      `json:"role" gorm:"index"`
	CreatedAt time.Time `json:"-"`
	UpdatedAt time.Time `json:"-"`
}

// TableName returns the table name for the UserRole model
func (UserRole) TableName() string {
	return "user_roles"
}

// GetRoleNames returns the role names for a user
func (u *User) GetRoleNames() []string {
	var roles []string
	for _, role := range u.Roles {
		roles = append(roles, string(role.Role))
	}
	return roles
}

// HasRole checks if a user has a specific role
func (u *User) HasRole(role Role) bool {
	for _, r := range u.Roles {
		if r.Role == role {
			return true
		}
	}
	return false
}

// IsAdmin checks if a user is an admin
func (u *User) IsAdmin() bool {
	return u.HasRole(RoleAdmin)
}

// Token represents a JWT token in the database
type Token struct {
	ID        uint           `json:"-" gorm:"primaryKey"`
	UUID      string         `json:"-" gorm:"unique;index"`
	UserID    uint           `json:"-" gorm:"index"`
	Token     string         `json:"-"`
	Type      string         `json:"-"` // "access" or "refresh"
	Blacklist bool           `json:"-" gorm:"default:false;index"`
	ExpiresAt time.Time      `json:"-" gorm:"index"`
	CreatedAt time.Time      `json:"-"`
	UpdatedAt time.Time      `json:"-"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}
