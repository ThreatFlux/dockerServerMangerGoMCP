package database

import (
	"database/sql"
	"errors"
	"io" // Add io import
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/sirupsen/logrus" // Add logrus import
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger" // Add gorm logger import
)

func setupPostgresMock(t *testing.T) (*PostgresDB, sqlmock.Sqlmock, *sql.DB) {
	// Create a mock database connection
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	// Create GORM DB instance using the mock database
	dialector := postgres.New(postgres.Config{
		Conn:       db,
		DriverName: "postgres",
	})
	gormDB, err := gorm.Open(dialector, &gorm.Config{})
	require.NoError(t, err)

	// Create test config
	cfg := &config.Config{}
	cfg.Database.Type = "postgres"
	cfg.Database.Host = "localhost"
	cfg.Database.Port = 5432
	cfg.Database.User = "testuser" // Renamed from Username
	cfg.Database.Password = "testpass"
	cfg.Database.Name = "testdb"
	cfg.Database.SSLMode = "disable"
	cfg.Database.MaxIdleConns = 10
	cfg.Database.MaxOpenConns = 100
	cfg.Database.ConnMaxLifetime = 3600 * time.Second // Use time.Duration
	// Logger is not part of config.Config

	// Create PostgresDB instance
	postgresDB := &PostgresDB{
		config: cfg,
		db:     gormDB,
		sqlDB:  db,
	}

	return postgresDB, mock, db
}

func TestNewPostgresDB(t *testing.T) {
	// Create test config
	cfg := &config.Config{}
	cfg.Database.Type = "postgres"
	cfg.Database.Host = "localhost"
	cfg.Database.Port = 5432
	cfg.Database.User = "testuser" // Renamed from Username
	cfg.Database.Password = "testpass"
	cfg.Database.Name = "testdb"

	// Create a dummy logger
	testLogger := logrus.New()
	testLogger.SetOutput(io.Discard) // Discard logs

	// Create PostgresDB instance
	db, err := NewPostgresDB(cfg, testLogger) // Pass logger
	require.NoError(t, err)
	assert.NotNil(t, db)
	assert.Equal(t, cfg, db.config)
	assert.Nil(t, db.db)    // db should be nil before Connect() is called
	assert.Nil(t, db.sqlDB) // sqlDB should be nil before Connect() is called
}

func TestPostgresDB_Ping(t *testing.T) {
	// Setup (moved inside subtests)
	// db, mock, _ := setupPostgresMock(t)

	// Test case 1: Successful ping
	t.Run("Success", func(t *testing.T) {
		db, mock, _ := setupPostgresMock(t) // Setup mock inside subtest
		mock.ExpectPing()

		err := db.Ping()
		assert.NoError(t, err)

		err = mock.ExpectationsWereMet()
		assert.NoError(t, err)
	})

	// Test case 2: Failed ping
	t.Run("Failure", func(t *testing.T) {
		db, mock, _ := setupPostgresMock(t) // Setup mock inside subtest
		mock.ExpectPing().WillReturnError(errors.New("ping error"))

		err := db.Ping()
		assert.Error(t, err)

		err = mock.ExpectationsWereMet()
		assert.NoError(t, err)
	})
}

func TestPostgresDB_Close(t *testing.T) {
	// Setup
	db, mock, sqlDB := setupPostgresMock(t)

	// Test closing the database
	mock.ExpectClose()

	err := db.Close()
	assert.NoError(t, err)

	// Attempt to use the closed connection should fail
	err = sqlDB.Ping()
	assert.Error(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

func TestPostgresDB_Transaction(t *testing.T) {
	// Setup
	db, mock, _ := setupPostgresMock(t)

	// Test case 1: Successful transaction
	t.Run("Success", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectCommit()

		err := db.Transaction(func(tx *gorm.DB) error {
			return nil
		})
		assert.NoError(t, err)

		err = mock.ExpectationsWereMet()
		assert.NoError(t, err)
	})

	// Test case 2: Transaction with error
	t.Run("Error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectRollback()

		testErr := errors.New("transaction error")
		err := db.Transaction(func(tx *gorm.DB) error {
			return testErr
		})
		assert.Error(t, err)
		assert.Equal(t, testErr, err)

		err = mock.ExpectationsWereMet()
		assert.NoError(t, err)
	})
}

func TestGetSslMode(t *testing.T) {
	// Test cases
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"Disable", "disable", "disable"},
		{"Require", "require", "require"},
		{"VerifyCa", "verify-ca", "verify-ca"},
		{"VerifyFull", "verify-full", "verify-full"},
		{"Invalid", "invalid", "disable"},
		{"Empty", "", "disable"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getSslMode(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetLogLevel(t *testing.T) {
	// Test cases
	testCases := []struct {
		name     string
		input    string
		expected gormlogger.LogLevel // Use gormlogger.LogLevel
	}{
		{"Debug", "debug", gormlogger.Info}, // GORM logger maps debug to Info level
		{"Info", "info", gormlogger.Info},
		{"Warn", "warn", gormlogger.Warn},
		{"Error", "error", gormlogger.Error},
		{"Invalid", "invalid", gormlogger.Silent},
		{"Empty", "", gormlogger.Silent},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getLogLevel(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestLogrusAdapter(t *testing.T) {
	// Setup
	log := logrus.New() // Create a logrus logger directly
	log.SetLevel(logrus.DebugLevel)
	log.SetOutput(io.Discard) // Discard output for test

	adapter := NewLogrusAdapter(log) // Pass the logrus logger
	assert.NotNil(t, adapter)

	// Test adapter with different message types
	// Note: This test just ensures that the adapter doesn't panic
	// since we can't easily assert on log output in a unit test

	// Test regular message
	adapter.Printf("regular message")

	// Test warning message
	adapter.Printf("warning: this is a warning")

	// Test error message
	adapter.Printf("error: this is an error")
}
