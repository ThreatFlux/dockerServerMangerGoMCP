package database

import (
	"errors"
	"io" // Add io import
	"testing"

	"github.com/sirupsen/logrus" // Add logrus import
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
	"gorm.io/gorm"
)

func TestDatabaseFactory(t *testing.T) {
	factory := NewFactory()
	require.NotNil(t, factory)

	tests := []struct {
		name      string
		dbType    string
		expectDB  bool
		expectErr bool
	}{
		{
			name:      "postgres",
			dbType:    "postgres",
			expectDB:  true,
			expectErr: false,
		},
		{
			name:      "sqlite",
			dbType:    "sqlite",
			expectDB:  true,
			expectErr: false,
		},
		{
			name:      "unsupported",
			dbType:    "mysql",
			expectDB:  false,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Database.Type = tt.dbType

			// For SQLite, set a path
			if tt.dbType == "sqlite" {
				cfg.Database.SQLite.Path = ":memory:"
			}

			// For Postgres, set required fields
			if tt.dbType == "postgres" {
				cfg.Database.Host = "localhost"
				cfg.Database.Port = 5432
				cfg.Database.User = "postgres"
				cfg.Database.Password = "postgres"
				cfg.Database.Name = "testdb"
			}

			// Create a dummy logger for the test
			testLogger := logrus.New()
			testLogger.SetOutput(io.Discard) // Discard logs during test

			db, err := factory.Create(cfg, testLogger) // Pass logger

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, db)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, db)
			}
		})
	}
}

func TestMockDatabase(t *testing.T) {
	db := &gorm.DB{}
	mockErr := errors.New("mock error")

	// Test successful mock
	t.Run("successful mock", func(t *testing.T) {
		mock := NewMockDatabase(db, nil)
		assert.NotNil(t, mock)
		assert.Equal(t, db, mock.DB())
		assert.Nil(t, mock.Connect())
		assert.Nil(t, mock.Migrate())
		assert.Nil(t, mock.Ping())
		assert.Nil(t, mock.Close())
		assert.True(t, mock.Closed)

		// Test transaction
		err := mock.Transaction(func(tx *gorm.DB) error {
			assert.Equal(t, db, tx)
			return nil
		})
		assert.Nil(t, err)
	})

	// Test error mock
	t.Run("error mock", func(t *testing.T) {
		mock := NewMockDatabase(db, mockErr)
		assert.NotNil(t, mock)
		assert.Equal(t, db, mock.DB())
		assert.Equal(t, mockErr, mock.Connect())
		assert.Equal(t, mockErr, mock.Migrate())
		assert.Equal(t, mockErr, mock.Ping())
		assert.Equal(t, mockErr, mock.Close())
		assert.True(t, mock.Closed)

		// Test transaction
		err := mock.Transaction(func(tx *gorm.DB) error {
			t.Fatal("This function should not be called")
			return nil
		})
		assert.Equal(t, mockErr, err)
	})
}

func TestInitDatabase(t *testing.T) {
	// We'll test this with a mock database
	t.Run("error case", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Database.Type = "unsupported"

		db, err := InitDatabase(cfg)
		assert.Error(t, err)
		assert.Nil(t, db)
	})

	// Test GetDB after initialization - using SQLite in-memory
	t.Run("success case", func(t *testing.T) {
		// Reset GetDB
		GetDB = nil

		cfg := &config.Config{}
		cfg.Database.Type = "sqlite"
		cfg.Database.SQLite.Path = ":memory:"

		// This test assumes NewSQLiteDB will succeed with an in-memory database
		// In a real scenario, we would mock the database connection
		_, err := InitDatabase(cfg)
		assert.NoError(t, err)

		// Verify GetDB is set
		assert.NotNil(t, GetDB)

		// Test GetDB function
		db, err := GetDB()
		assert.NoError(t, err)
		assert.NotNil(t, db)
	})
}
