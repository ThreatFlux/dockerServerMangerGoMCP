package auth

import (
	"strings" // Add import for strings.Repeat
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordService(t *testing.T) {
	// Create a test password configuration with lower cost for faster tests
	config := PasswordConfig{
		MinLength: 8,
		MaxLength: 72,
		HashCost:  bcrypt.MinCost, // Use the minimum cost for faster tests
	}

	// Create a test password service
	passwordService := NewPasswordService(config)
	require.NotNil(t, passwordService)

	// Test ValidatePassword
	t.Run("ValidatePassword", func(t *testing.T) {
		tests := []struct {
			name     string
			password string
			wantErr  bool
			errType  error
		}{
			{
				name:     "Valid password",
				password: "password123",
				wantErr:  false,
			},
			{
				name:     "Empty password",
				password: "",
				wantErr:  true,
				errType:  ErrEmptyPassword,
			},
			{
				name:     "Password too short",
				password: "pass",
				wantErr:  true,
				errType:  ErrPasswordTooShort,
			},
			{
				name:     "Password too long",
				password: "a" + strings.Repeat("b", 72), // 73 characters
				wantErr:  true,
				errType:  ErrPasswordTooLong,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := passwordService.ValidatePassword(tt.password)
				if tt.wantErr {
					require.Error(t, err)
					if tt.errType != nil {
						assert.ErrorIs(t, err, tt.errType)
					}
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	// Test HashPassword
	t.Run("HashPassword", func(t *testing.T) {
		// Test valid password
		t.Run("Valid password", func(t *testing.T) {
			hash, err := passwordService.HashPassword("password123")
			require.NoError(t, err)
			assert.NotEmpty(t, hash)
			assert.True(t, passwordService.IsHashValid(hash))
		})

		// Test invalid passwords
		t.Run("Invalid passwords", func(t *testing.T) {
			// Empty password
			_, err := passwordService.HashPassword("")
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrEmptyPassword)

			// Password too short
			_, err = passwordService.HashPassword("pass")
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrPasswordTooShort)

			// Password too long
			_, err = passwordService.HashPassword("a" + strings.Repeat("b", 72)) // 73 characters
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrPasswordTooLong)
		})
	})

	// Test CheckPassword
	t.Run("CheckPassword", func(t *testing.T) {
		// Hash a password
		password := "password123"
		hash, err := passwordService.HashPassword(password)
		require.NoError(t, err)
		assert.NotEmpty(t, hash)

		// Check correct password
		t.Run("Correct password", func(t *testing.T) {
			result := passwordService.CheckPassword(password, hash)
			assert.True(t, result)
		})

		// Check incorrect password
		t.Run("Incorrect password", func(t *testing.T) {
			result := passwordService.CheckPassword("wrongpassword", hash)
			assert.False(t, result)
		})

		// Check with empty password
		t.Run("Empty password", func(t *testing.T) {
			result := passwordService.CheckPassword("", hash)
			assert.False(t, result)
		})

		// Check with empty hash
		t.Run("Empty hash", func(t *testing.T) {
			result := passwordService.CheckPassword(password, "")
			assert.False(t, result)
		})

		// Check with invalid hash
		t.Run("Invalid hash", func(t *testing.T) {
			result := passwordService.CheckPassword(password, "invalid-hash")
			assert.False(t, result)
		})
	})

	// Test IsHashValid
	t.Run("IsHashValid", func(t *testing.T) {
		tests := []struct {
			name  string
			hash  string
			valid bool
		}{
			{
				name:  "Valid bcrypt hash ($2a$)",
				hash:  "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
				valid: true,
			},
			{
				name:  "Valid bcrypt hash ($2b$)",
				hash:  "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
				valid: true,
			},
			{
				name:  "Valid bcrypt hash ($2y$)",
				hash:  "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
				valid: true,
			},
			{
				name:  "Empty hash",
				hash:  "",
				valid: false,
			},
			{
				name:  "Invalid prefix",
				hash:  "$1a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
				valid: false,
			},
			{
				name:  "Too short",
				hash:  "$2a$",
				valid: false,
			},
			{
				name:  "Plain text",
				hash:  "not-a-hash",
				valid: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := passwordService.IsHashValid(tt.hash)
				assert.Equal(t, tt.valid, result)
			})
		}
	})

	// Test UpgradeHashIfNeeded
	t.Run("UpgradeHashIfNeeded", func(t *testing.T) {
		password := "password123"

		// Create a hash with a lower cost
		lowCostService := NewPasswordService(PasswordConfig{
			MinLength: 8,
			MaxLength: 72,
			HashCost:  bcrypt.MinCost, // 4
		})
		lowCostHash, err := lowCostService.HashPassword(password)
		require.NoError(t, err)

		// Create a service with a higher cost
		highCostService := NewPasswordService(PasswordConfig{
			MinLength: 8,
			MaxLength: 72,
			HashCost:  bcrypt.MinCost + 1, // 5
		})

		// Test with a low-cost hash - should upgrade
		t.Run("Upgrade needed", func(t *testing.T) {
			newHash, upgraded, err := highCostService.UpgradeHashIfNeeded(password, lowCostHash)
			require.NoError(t, err)
			assert.True(t, upgraded)
			assert.NotEqual(t, lowCostHash, newHash)
			assert.True(t, highCostService.IsHashValid(newHash))

			// Verify the new hash works
			assert.True(t, highCostService.CheckPassword(password, newHash))
		})

		// Test with wrong password - should not upgrade
		t.Run("Wrong password", func(t *testing.T) {
			newHash, upgraded, err := highCostService.UpgradeHashIfNeeded("wrongpassword", lowCostHash)
			require.NoError(t, err)
			assert.False(t, upgraded)
			assert.Equal(t, lowCostHash, newHash)
		})

		// Test with invalid hash
		t.Run("Invalid hash", func(t *testing.T) {
			_, _, err := highCostService.UpgradeHashIfNeeded(password, "invalid-hash")
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidHash)
		})

		// Test with a hash that already has the right cost
		t.Run("No upgrade needed", func(t *testing.T) {
			highCostHash, err := highCostService.HashPassword(password)
			require.NoError(t, err)

			newHash, upgraded, err := highCostService.UpgradeHashIfNeeded(password, highCostHash)
			require.NoError(t, err)
			assert.False(t, upgraded)
			assert.Equal(t, highCostHash, newHash)
		})
	})
}

func TestDefaultPasswordConfig(t *testing.T) {
	config := DefaultPasswordConfig()

	// Verify default values
	assert.Equal(t, 8, config.MinLength)
	assert.Equal(t, 72, config.MaxLength)
	assert.Equal(t, bcrypt.DefaultCost, config.HashCost)
}
