package auth

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Password-related errors
var (
	ErrHashingFailed    = errors.New("failed to hash password")
	ErrEmptyPassword    = errors.New("password cannot be empty")
	ErrPasswordTooShort = errors.New("password is too short")
	ErrPasswordTooLong  = errors.New("password is too long")
	ErrInvalidHash      = errors.New("invalid password hash format")
)

// PasswordConfig contains configuration for password handling
type PasswordConfig struct {
	// MinLength specifies the minimum required length for passwords
	MinLength int

	// MaxLength specifies the maximum allowed length for passwords
	MaxLength int

	// HashCost specifies the cost parameter for bcrypt
	// Higher cost means more secure but slower hashing
	// bcrypt.DefaultCost = 10
	// bcrypt.MinCost = 4 (used for testing)
	// bcrypt.MaxCost = 31
	HashCost int
}

// DefaultPasswordConfig returns the default password configuration
func DefaultPasswordConfig() PasswordConfig {
	return PasswordConfig{
		MinLength: 8,
		MaxLength: 72, // bcrypt limit
		HashCost:  bcrypt.DefaultCost,
	}
}

// PasswordService handles password operations
type PasswordService struct {
	Config PasswordConfig
}

// NewPasswordService creates a new password service with the provided configuration
func NewPasswordService(config PasswordConfig) *PasswordService {
	return &PasswordService{
		Config: config,
	}
}

// HashPassword hashes a password using bcrypt
func (s *PasswordService) HashPassword(password string) (string, error) {
	// Validate password length
	if err := s.ValidatePassword(password); err != nil {
		return "", err
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.Config.HashCost)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrHashingFailed, err)
	}

	return string(hash), nil
}

// CheckPassword verifies if a password matches a hash
func (s *PasswordService) CheckPassword(password, hash string) bool {
	// Validate password and hash
	if password == "" || hash == "" {
		return false
	}

	// Compare password with hash
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ValidatePassword validates a password against the configuration rules
func (s *PasswordService) ValidatePassword(password string) error {
	// Check if password is empty
	if password == "" {
		return ErrEmptyPassword
	}

	// Check minimum length
	if len(password) < s.Config.MinLength {
		return fmt.Errorf("%w: minimum length is %d", ErrPasswordTooShort, s.Config.MinLength)
	}

	// Check maximum length
	if len(password) > s.Config.MaxLength {
		return fmt.Errorf("%w: maximum length is %d", ErrPasswordTooLong, s.Config.MaxLength)
	}

	return nil
}

// IsHashValid checks if a string is a valid bcrypt hash
func (s *PasswordService) IsHashValid(hash string) bool {
	// Check if hash is empty
	if hash == "" {
		return false
	}

	// bcrypt hashes are exactly 60 characters long and start with $2a$, $2b$, or $2y$
	if len(hash) != 60 || (hash[0:4] != "$2a$" && hash[0:4] != "$2b$" && hash[0:4] != "$2y$") {
		return false
	}

	return true
}

// UpgradeHashIfNeeded checks if a hash needs to be upgraded to use a new cost
// Returns true if the hash was upgraded, false otherwise
func (s *PasswordService) UpgradeHashIfNeeded(password, hash string) (newHash string, upgraded bool, err error) {
	// Check if hash is valid
	if !s.IsHashValid(hash) {
		return "", false, ErrInvalidHash
	}

	// Get the cost of the current hash
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return "", false, fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}

	// Check if the hash needs upgrading
	if cost >= s.Config.HashCost {
		// No need to upgrade
		return hash, false, nil
	}

	// Verify the password with the current hash
	if !s.CheckPassword(password, hash) {
		// Password is incorrect, can't upgrade
		return hash, false, nil
	}

	// Hash the password with the new cost
	newHash, err = s.HashPassword(password)
	if err != nil {
		return hash, false, err
	}

	return newHash, true, nil
}
