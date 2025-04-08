package auth

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus" // Added import
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger" // Use alias for gorm logger
)

// MockDB implements the database.Database interface for testing
type MockDB struct {
	mock.Mock
	mockDB *gorm.DB
}

func (m *MockDB) DB() *gorm.DB {
	return m.mockDB
}

func (m *MockDB) Connect() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDB) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDB) Migrate(models ...interface{}) error { // Updated signature
	args := []interface{}{}
	for _, model := range models {
		args = append(args, model)
	}
	return m.Called(args...).Error(0)
}

func (m *MockDB) Ping() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDB) Transaction(fn func(tx *gorm.DB) error) error {
	args := m.Called(fn)
	return args.Error(0)
}

// MockGormDB implements a mock GORM DB
type MockGormDB struct {
	mock.Mock
}

func (m *MockGormDB) WithContext(ctx context.Context) *MockGormDB {
	m.Called(ctx)
	return m
}

func (m *MockGormDB) Model(value interface{}) *MockGormDB {
	m.Called(value)
	return m
}

func (m *MockGormDB) Where(query interface{}, args ...interface{}) *MockGormDB {
	m.Called(query, args)
	return m
}

func (m *MockGormDB) First(dest interface{}, conds ...interface{}) *MockGormDB {
	m.Called(dest, conds)
	if user, ok := dest.(*models.User); ok && len(conds) == 0 {
		// Simulate loading a user into the dest parameter
		*user = models.User{
			ID:       1,
			Email:    "test@example.com",
			Password: "$2a$10$7gB.oK.TzMXHzSBhZHTGD.4xG9KBx9mwDGEhxHV/XKVWYqUuZs3EG", // hashed "password"
			Name:     "Test User",
			Roles: []models.UserRole{
				{
					Role: models.RoleUser,
				},
			},
			Active: true,
		}
	}
	return m
}

func (m *MockGormDB) Count(count *int64) *MockGormDB {
	m.Called(count)
	*count = 0 // Simulate count = 0 (no existing records)
	return m
}

func (m *MockGormDB) Create(value interface{}) *MockGormDB {
	m.Called(value)
	if user, ok := value.(*models.User); ok {
		// Simulate ID assignment after creation
		user.ID = 1
	}
	return m
}

func (m *MockGormDB) Update(column string, value interface{}) *MockGormDB {
	m.Called(column, value)
	return m
}

func (m *MockGormDB) Error() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockGormDB) Preload(query string, args ...interface{}) *MockGormDB {
	m.Called(query, args)
	return m
}

// MockTokenStore implements the TokenStore interface for testing
type MockTokenStore struct {
	mock.Mock
}

func (m *MockTokenStore) StoreToken(ctx context.Context, userID uint, tokenUUID string, tokenType string, token string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, tokenUUID, tokenType, token, expiresAt)
	return args.Error(0)
}

func (m *MockTokenStore) GetToken(ctx context.Context, tokenUUID string) (*models.Token, error) {
	args := m.Called(ctx, tokenUUID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenStore) BlacklistToken(ctx context.Context, tokenUUID string) error {
	args := m.Called(ctx, tokenUUID)
	return args.Error(0)
}

func (m *MockTokenStore) DeleteToken(ctx context.Context, tokenUUID string) error {
	args := m.Called(ctx, tokenUUID)
	return args.Error(0)
}

func (m *MockTokenStore) DeleteExpiredTokens(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockTokenStore) DeleteUserTokens(ctx context.Context, userID uint) (int, error) {
	args := m.Called(ctx, userID)
	return args.Int(0), args.Error(1)
}

func (m *MockTokenStore) IsTokenBlacklisted(ctx context.Context, tokenUUID string) (bool, error) {
	args := m.Called(ctx, tokenUUID)
	return args.Bool(0), args.Error(1)
}

func TestLogin_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockDB := &MockDB{}
	mockGormDB := &MockGormDB{} // We still use this to mock GORM method calls
	mockTokenStore := &MockTokenStore{}
	logger := logrus.New()             // Add logger
	logger.SetLevel(logrus.FatalLevel) // Suppress logs

	// Create a dummy GORM DB instance (e.g., in-memory SQLite) to satisfy the non-nil requirement
	// The actual DB operations will be mocked by MockGormDB expectations
	dummyGormDB, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent), // Use gormlogger
	})
	require.NoError(t, err, "Failed to open dummy SQLite DB")
	require.NotNil(t, dummyGormDB, "Dummy GORM DB should not be nil")
	mockDB.mockDB = dummyGormDB // Assign the dummy DB to the MockDB struct field
	// Create a real password service for password checking
	passwordService := NewPasswordService(DefaultPasswordConfig())
	hashedPassword, _ := passwordService.HashPassword("password")

	// Setup test user
	user := models.User{
		ID:       1,
		Email:    "test@example.com",
		Password: hashedPassword,
		Name:     "Test User",
		Roles: []models.UserRole{
			{
				Role: models.RoleUser,
			},
		},
		Active: true,
	}

	// Configure mocks
	mockDB.On("DB").Return(dummyGormDB) // Return the non-nil dummy GORM DB instance
	mockGormDB.On("WithContext", ctx).Return(mockGormDB)
	mockGormDB.On("Preload", "Roles", mock.Anything).Return(mockGormDB)
	mockGormDB.On("Where", "email = ?", mock.Anything).Return(mockGormDB)
	mockGormDB.On("First", mock.AnythingOfType("*models.User"), mock.Anything).Run(func(args mock.Arguments) {
		// Set the user data in the argument
		arg := args.Get(0).(*models.User)
		*arg = user
	}).Return(mockGormDB)
	mockGormDB.On("Error").Return(nil)
	mockGormDB.On("Model", mock.AnythingOfType("*models.User")).Return(mockGormDB)
	mockGormDB.On("Update", "last_login", mock.AnythingOfType("time.Time")).Return(mockGormDB)

	// For token generation
	mockTokenStore.On("StoreToken", ctx, uint(1), mock.AnythingOfType("string"), "access", mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)
	mockTokenStore.On("StoreToken", ctx, uint(1), mock.AnythingOfType("string"), "refresh", mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	// Create the service
	jwtConfig := DefaultJWTConfig()
	jwtConfig.AccessTokenSecret = "test-access-secret"
	jwtConfig.RefreshTokenSecret = "test-refresh-secret"

	service := NewService(mockDB, jwtConfig, DefaultPasswordConfig(), mockTokenStore, logger) // Pass logger

	// Call the method
	tokenPair, err := service.Login(ctx, "test@example.com", "password")

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, tokenPair)
	assert.NotEmpty(t, tokenPair.AccessToken)
	assert.NotEmpty(t, tokenPair.RefreshToken)
	assert.False(t, tokenPair.ExpiresAt.IsZero())

	// Verify expectations
	mockDB.AssertExpectations(t)
	mockGormDB.AssertExpectations(t)
	mockTokenStore.AssertExpectations(t)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockDB := &MockDB{}
	mockGormDB := &MockGormDB{}
	mockTokenStore := &MockTokenStore{}
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Create a real password service for password checking
	passwordService := NewPasswordService(DefaultPasswordConfig())
	hashedPassword, _ := passwordService.HashPassword("correct-password")

	// Setup test user
	user := models.User{
		ID:       1,
		Email:    "test@example.com",
		Password: hashedPassword,
		Name:     "Test User",
		Roles: []models.UserRole{
			{
				Role: models.RoleUser,
			},
		},
		Active: true,
	}

	// Configure mocks
	mockDB.On("DB").Return(mockGormDB)
	mockGormDB.On("WithContext", ctx).Return(mockGormDB)
	mockGormDB.On("Preload", "Roles", mock.Anything).Return(mockGormDB)
	mockGormDB.On("Where", "email = ?", mock.Anything).Return(mockGormDB)
	mockGormDB.On("First", mock.AnythingOfType("*models.User"), mock.Anything).Run(func(args mock.Arguments) {
		// Set the user data in the argument
		arg := args.Get(0).(*models.User)
		*arg = user
	}).Return(mockGormDB)
	mockGormDB.On("Error").Return(nil)

	// Create the service
	jwtConfig := DefaultJWTConfig()
	jwtConfig.AccessTokenSecret = "test-access-secret"
	jwtConfig.RefreshTokenSecret = "test-refresh-secret"

	service := NewService(mockDB, jwtConfig, DefaultPasswordConfig(), mockTokenStore, logger) // Pass logger

	// Call the method with wrong password
	tokenPair, err := service.Login(ctx, "test@example.com", "wrong-password")

	// Assertions
	require.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, tokenPair)

	// Verify expectations
	mockDB.AssertExpectations(t)
	mockGormDB.AssertExpectations(t)
	mockTokenStore.AssertExpectations(t)
}

func TestLogin_UserNotFound(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockDB := &MockDB{}
	mockGormDB := &MockGormDB{}
	mockTokenStore := &MockTokenStore{}
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Configure mocks
	mockDB.On("DB").Return(mockGormDB)
	mockGormDB.On("WithContext", ctx).Return(mockGormDB)
	mockGormDB.On("Preload", "Roles", mock.Anything).Return(mockGormDB)
	mockGormDB.On("Where", "email = ?", mock.Anything).Return(mockGormDB)
	mockGormDB.On("First", mock.AnythingOfType("*models.User"), mock.Anything).Return(mockGormDB)
	mockGormDB.On("Error").Return(gorm.ErrRecordNotFound)

	// Create the service
	jwtConfig := DefaultJWTConfig()
	jwtConfig.AccessTokenSecret = "test-access-secret"
	jwtConfig.RefreshTokenSecret = "test-refresh-secret"

	service := NewService(mockDB, jwtConfig, DefaultPasswordConfig(), mockTokenStore, logger) // Pass logger

	// Call the method
	tokenPair, err := service.Login(ctx, "nonexistent@example.com", "password")

	// Assertions
	require.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, tokenPair)

	// Verify expectations
	mockDB.AssertExpectations(t)
	mockGormDB.AssertExpectations(t)
	mockTokenStore.AssertExpectations(t)
}

func TestRegister_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockDB := &MockDB{}
	mockGormDB := &MockGormDB{}
	mockTokenStore := &MockTokenStore{}
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Setup test user
	user := &models.User{
		Email:    "new@example.com",
		Password: "new-password",
		Name:     "New User",
	}

	// Configure mocks
	mockDB.On("DB").Return(mockGormDB)
	mockGormDB.On("WithContext", ctx).Return(mockGormDB)
	mockGormDB.On("Model", mock.AnythingOfType("*models.User")).Return(mockGormDB)
	mockGormDB.On("Where", "email = ?", mock.Anything).Return(mockGormDB)
	mockGormDB.On("Count", mock.AnythingOfType("*int64")).Return(mockGormDB)
	mockGormDB.On("Error").Return(nil) // Mock GORM errors if needed

	// Mock the Transaction call directly, returning nil without executing fn
	mockDB.On("Transaction", mock.AnythingOfType("func(*gorm.DB) error")).Return(nil)

	// Mock the Create call that would happen inside the transaction
	mockGormDB.On("Create", mock.AnythingOfType("*models.User")).Return(mockGormDB)

	// For token generation
	mockTokenStore.On("StoreToken", ctx, uint(1), mock.AnythingOfType("string"), "access", mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)
	mockTokenStore.On("StoreToken", ctx, uint(1), mock.AnythingOfType("string"), "refresh", mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	// Create the service
	jwtConfig := DefaultJWTConfig()
	jwtConfig.AccessTokenSecret = "test-access-secret"
	jwtConfig.RefreshTokenSecret = "test-refresh-secret"

	service := NewService(mockDB, jwtConfig, DefaultPasswordConfig(), mockTokenStore, logger) // Pass logger

	// Call the method
	tokenPair, err := service.Register(ctx, user)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, tokenPair)
	assert.NotEmpty(t, tokenPair.AccessToken)
	assert.NotEmpty(t, tokenPair.RefreshToken)
	assert.False(t, tokenPair.ExpiresAt.IsZero())

	// Verify user modifications
	assert.True(t, user.Active)
	assert.False(t, user.EmailVerified)
	assert.Equal(t, uint(1), user.ID)
	assert.NotEqual(t, "new-password", user.Password) // Password should be hashed

	// Verify roles
	assert.GreaterOrEqual(t, len(user.Roles), 1)
	hasUserRole := false
	for _, role := range user.Roles {
		if role.Role == models.RoleUser {
			hasUserRole = true
			break
		}
	}
	assert.True(t, hasUserRole, "User should have the basic user role")

	// Verify expectations
	mockDB.AssertExpectations(t)
	mockGormDB.AssertExpectations(t)
	mockTokenStore.AssertExpectations(t)
}

func TestVerify_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockDB := &MockDB{}
	mockTokenStore := &MockTokenStore{}
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Create a valid token
	jwtConfig := DefaultJWTConfig()
	jwtConfig.AccessTokenSecret = "test-access-secret"
	jwtConfig.RefreshTokenSecret = "test-refresh-secret"

	jwtService := NewJWTService(jwtConfig, logger) // Pass logger
	user := &models.User{
		ID: 1,
		Roles: []models.UserRole{
			{
				Role: models.RoleUser,
			},
		},
	}
	tokenPair, err := jwtService.GenerateTokenPair(user)
	require.NoError(t, err)

	// Configure mocks
	mockTokenStore.On("IsTokenBlacklisted", ctx, mock.AnythingOfType("string")).Return(false, nil)

	// Create the service
	service := NewService(mockDB, jwtConfig, DefaultPasswordConfig(), mockTokenStore, logger) // Pass logger

	// Call the method
	tokenDetails, err := service.Verify(ctx, tokenPair.AccessToken)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, tokenDetails)
	assert.Equal(t, uint(1), tokenDetails.UserID)
	assert.Equal(t, 1, len(tokenDetails.Roles))
	assert.Equal(t, "user", tokenDetails.Roles[0])
	assert.NotEmpty(t, tokenDetails.TokenUUID)

	// Verify expectations
	mockTokenStore.AssertExpectations(t)
}

func TestVerify_BlacklistedToken(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockDB := &MockDB{}
	mockTokenStore := &MockTokenStore{}
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Create a valid token
	jwtConfig := DefaultJWTConfig()
	jwtConfig.AccessTokenSecret = "test-access-secret"
	jwtConfig.RefreshTokenSecret = "test-refresh-secret"

	jwtService := NewJWTService(jwtConfig, logger) // Pass logger
	user := &models.User{
		ID: 1,
		Roles: []models.UserRole{
			{
				Role: models.RoleUser,
			},
		},
	}
	tokenPair, err := jwtService.GenerateTokenPair(user)
	require.NoError(t, err)

	// Configure mocks
	mockTokenStore.On("IsTokenBlacklisted", ctx, mock.AnythingOfType("string")).Return(true, nil)

	// Create the service
	service := NewService(mockDB, jwtConfig, DefaultPasswordConfig(), mockTokenStore, logger) // Pass logger

	// Call the method
	tokenDetails, err := service.Verify(ctx, tokenPair.AccessToken)

	// Assertions
	require.Error(t, err)
	assert.Equal(t, ErrTokenBlacklisted, err)
	assert.Nil(t, tokenDetails)

	// Verify expectations
	mockTokenStore.AssertExpectations(t)
}

func TestRefresh_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockDB := &MockDB{}
	mockGormDB := &MockGormDB{}
	mockTokenStore := &MockTokenStore{}
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Create a valid token
	jwtConfig := DefaultJWTConfig()
	jwtConfig.AccessTokenSecret = "test-access-secret"
	jwtConfig.RefreshTokenSecret = "test-refresh-secret"

	jwtService := NewJWTService(jwtConfig, logger) // Pass logger
	user := &models.User{
		ID: 1,
		Roles: []models.UserRole{
			{
				Role: models.RoleUser,
			},
		},
		Active: true,
	}
	tokenPair, err := jwtService.GenerateTokenPair(user)
	require.NoError(t, err)

	// Configure mocks
	mockTokenStore.On("IsTokenBlacklisted", ctx, mock.AnythingOfType("string")).Return(false, nil)
	mockDB.On("DB").Return(mockGormDB)
	mockGormDB.On("WithContext", ctx).Return(mockGormDB)
	mockGormDB.On("Preload", "Roles", mock.Anything).Return(mockGormDB)
	mockGormDB.On("First", mock.AnythingOfType("*models.User"), uint(1)).Run(func(args mock.Arguments) {
		arg := args.Get(0).(*models.User)
		*arg = *user // Copy user data
	}).Return(mockGormDB)
	mockGormDB.On("Error").Return(nil)
	mockTokenStore.On("DeleteToken", ctx, mock.AnythingOfType("string")).Return(nil)
	mockTokenStore.On("StoreToken", ctx, uint(1), mock.AnythingOfType("string"), "access", mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)
	mockTokenStore.On("StoreToken", ctx, uint(1), mock.AnythingOfType("string"), "refresh", mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	// Create the service
	service := NewService(mockDB, jwtConfig, DefaultPasswordConfig(), mockTokenStore, logger) // Pass logger

	// Call the method
	newTokenPair, err := service.Refresh(ctx, tokenPair.RefreshToken)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, newTokenPair)
	assert.NotEmpty(t, newTokenPair.AccessToken)
	assert.NotEmpty(t, newTokenPair.RefreshToken)
	assert.NotEqual(t, tokenPair.AccessToken, newTokenPair.AccessToken)
	assert.NotEqual(t, tokenPair.RefreshToken, newTokenPair.RefreshToken)

	// Verify expectations
	mockDB.AssertExpectations(t)
	mockGormDB.AssertExpectations(t)
	mockTokenStore.AssertExpectations(t)
}

func TestLogout_Success(t *testing.T) {
	// Setup
	ctx := context.Background()
	mockDB := &MockDB{}
	mockTokenStore := &MockTokenStore{}
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Create a valid token
	jwtConfig := DefaultJWTConfig()
	jwtConfig.AccessTokenSecret = "test-access-secret"
	jwtConfig.RefreshTokenSecret = "test-refresh-secret"

	jwtService := NewJWTService(jwtConfig, logger) // Pass logger
	user := &models.User{
		ID: 1,
		Roles: []models.UserRole{
			{
				Role: models.RoleUser,
			},
		},
	}
	tokenPair, err := jwtService.GenerateTokenPair(user)
	require.NoError(t, err)

	// Configure mocks
	mockTokenStore.On("IsTokenBlacklisted", ctx, mock.AnythingOfType("string")).Return(false, nil)
	mockTokenStore.On("BlacklistToken", ctx, mock.AnythingOfType("string")).Return(nil)

	// Create the service
	service := NewService(mockDB, jwtConfig, DefaultPasswordConfig(), mockTokenStore, logger) // Pass logger

	// Call the method
	err = service.Logout(ctx, tokenPair.AccessToken)

	// Assertions
	require.NoError(t, err)

	// Verify expectations
	mockTokenStore.AssertExpectations(t)
}
