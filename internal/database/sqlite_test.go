package database

import (
	"errors" // Add errors import
	"io"
	"os"
	"path/filepath"
	"strings" // Add strings import
	"testing"
	"time" // Add time import

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
	"gorm.io/gorm"
)

func TestNewSQLiteDB(t *testing.T) {
	// Create test config
	cfg := &config.Config{}
	cfg.Database.Type = "sqlite"
	cfg.Database.SQLite.Path = "test.db" // Use nested path

	// Create a dummy logger
	testLogger := logrus.New()
	testLogger.SetOutput(io.Discard) // Discard logs

	// Create SQLiteDB instance
	db, err := NewSQLiteDB(cfg, testLogger) // Pass logger
	require.NoError(t, err)
	assert.NotNil(t, db)
	assert.Equal(t, cfg, db.config)
	assert.Nil(t, db.db)    // db should be nil before Connect()
	assert.Nil(t, db.sqlDB) // sqlDB should be nil before Connect()
}

func TestSQLiteDB_Connect(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test database path
	dbPath := filepath.Join(tempDir, "test.db")

	// Create test config
	cfg := &config.Config{}
	cfg.Database.Type = "sqlite"
	cfg.Database.SQLite.Path = dbPath // Use nested path
	cfg.Database.MaxIdleConns = 10
	cfg.Database.MaxOpenConns = 100
	cfg.Database.ConnMaxLifetime = 3600 * time.Second // Use time.Duration
	// Logger is not part of config.Config

	// Create a dummy logger
	testLogger := logrus.New()
	testLogger.SetOutput(io.Discard) // Discard logs

	// Create SQLiteDB instance
	db, err := NewSQLiteDB(cfg, testLogger) // Pass logger
	require.NoError(t, err)

	// Connect to database
	err = db.Connect()
	require.NoError(t, err)
	assert.NotNil(t, db.db)
	assert.NotNil(t, db.sqlDB)

	// Check if database file was created
	_, err = os.Stat(dbPath)
	assert.NoError(t, err)

	// Close database connection
	err = db.Close()
	assert.NoError(t, err)
}

func TestSQLiteDB_Connect_CreateDirectory(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test database path with nested directories
	subDir := filepath.Join(tempDir, "subdir", "nested")
	dbPath := filepath.Join(subDir, "test.db")

	// Create test config
	cfg := &config.Config{}
	cfg.Database.Type = "sqlite"
	cfg.Database.SQLite.Path = dbPath // Use nested path
	// Logger is not part of config.Config

	// Create a dummy logger
	testLogger := logrus.New()
	testLogger.SetOutput(io.Discard) // Discard logs

	// Create SQLiteDB instance
	db, err := NewSQLiteDB(cfg, testLogger) // Pass logger
	require.NoError(t, err)

	// Connect to database
	err = db.Connect()
	require.NoError(t, err)

	// Check if database file was created
	_, err = os.Stat(dbPath)
	assert.NoError(t, err)

	// Close database connection
	err = db.Close()
	assert.NoError(t, err)
}
func TestSQLiteDB_DefaultPath(t *testing.T) {
	// Create test config without path
	cfg := &config.Config{}
	cfg.Database.Type = "sqlite"
	// Path will use default from setDefaults() in config pkg
	// Logger is not part of config.Config

	// Create a dummy logger
	testLogger := logrus.New()
	testLogger.SetOutput(io.Discard) // Discard logs

	// Create SQLiteDB instance
	db, err := NewSQLiteDB(cfg, testLogger) // Pass logger
	require.NoError(t, err)
	require.NoError(t, err)

	// Connect to database (will use default path)
	err = db.Connect()
	require.NoError(t, err)

	// Clean up
	err = db.Close()
	assert.NoError(t, err)

	// Remove default database file
	os.Remove("docker_test-server-manager.db")
}

func TestSQLiteDB_Transaction(t *testing.T) {
	// Skip in CI environment
	if os.Getenv("CI") != "" {
		t.Skip("Skipping in CI environment")
	}

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test database path
	dbPath := filepath.Join(tempDir, "transaction_test.db")
	// Create test config
	cfg := &config.Config{}
	cfg.Database.Type = "sqlite"
	cfg.Database.SQLite.Path = dbPath // Use nested path
	// Logger is not part of config.Config

	// Create a dummy logger
	testLogger := logrus.New()
	testLogger.SetOutput(io.Discard) // Discard logs

	// Create SQLiteDB instance
	db, err := NewSQLiteDB(cfg, testLogger) // Pass logger
	require.NoError(t, err)
	require.NoError(t, err)

	// Connect to database
	err = db.Connect()
	require.NoError(t, err)
	defer db.Close()

	// Define a test model
	type TestModel struct {
		ID   uint `gorm:"primarykey"`
		Name string
	}

	// Auto-migrate the test model
	err = db.DB().AutoMigrate(&TestModel{})
	require.NoError(t, err)

	// Test case 1: Successful transaction
	t.Run("Success", func(t *testing.T) {
		err := db.Transaction(func(tx *gorm.DB) error {
			// Create a record
			result := tx.Create(&TestModel{Name: "test1"})
			return result.Error
		})
		assert.NoError(t, err)

		// Verify record was created
		var count int64
		db.DB().Model(&TestModel{}).Where("name = ?", "test1").Count(&count)
		assert.Equal(t, int64(1), count)
	})

	// Test case 2: Failed transaction
	t.Run("Failure", func(t *testing.T) {
		err := db.Transaction(func(tx *gorm.DB) error {
			// Create a record
			result := tx.Create(&TestModel{Name: "test2"})
			if result.Error != nil {
				return result.Error
			}

			// Return an error to trigger rollback
			return errors.New("transaction error")
		})
		assert.Error(t, err)

		// Verify record was not created
		var count int64
		db.DB().Model(&TestModel{}).Where("name = ?", "test2").Count(&count)
		assert.Equal(t, int64(0), count)
	})
}

func TestEnsureDirectoryExists(t *testing.T) {
	// Test with current directory
	err := ensureDirectoryExists("file.db")
	assert.NoError(t, err)

	// Test with new directory
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	newDir := filepath.Join(tempDir, "newdir")
	dbPath := filepath.Join(newDir, "file.db")

	err = ensureDirectoryExists(dbPath)
	assert.NoError(t, err)

	// Check if directory was created
	_, err = os.Stat(newDir)
	assert.NoError(t, err)
}

func TestSetPragmas(t *testing.T) {
	// Skip in CI environment
	if os.Getenv("CI") != "" {
		t.Skip("Skipping in CI environment")
	}

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "sqlite_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test database path
	dbPath := filepath.Join(tempDir, "pragma_test.db")

	// Create test config
	cfg := &config.Config{}
	cfg.Database.Type = "sqlite"
	cfg.Database.SQLite.Path = dbPath // Use nested path
	// Logger is not part of config.Config

	// Create a dummy logger
	testLogger := logrus.New()
	testLogger.SetOutput(io.Discard) // Discard logs

	// Create SQLiteDB instance
	db, err := NewSQLiteDB(cfg, testLogger) // Pass logger
	require.NoError(t, err)

	// Connect to database
	err = db.Connect()
	require.NoError(t, err)
	defer db.Close()

	// Verify pragmas
	var foreignKeys, journalMode, synchronous, tempStore string
	var busyTimeout, cacheSize, mmapSize int

	db.DB().Raw("PRAGMA foreign_keys").Scan(&foreignKeys)
	db.DB().Raw("PRAGMA journal_mode").Scan(&journalMode)
	db.DB().Raw("PRAGMA synchronous").Scan(&synchronous)
	db.DB().Raw("PRAGMA busy_timeout").Scan(&busyTimeout)
	db.DB().Raw("PRAGMA mmap_size").Scan(&mmapSize)
	db.DB().Raw("PRAGMA temp_store").Scan(&tempStore)
	db.DB().Raw("PRAGMA cache_size").Scan(&cacheSize)

	assert.Equal(t, "1", foreignKeys)
	assert.Equal(t, "wal", strings.ToLower(journalMode))
	assert.Equal(t, "1", synchronous) // NORMAL = 1
	assert.Equal(t, 5000, busyTimeout)
	assert.GreaterOrEqual(t, mmapSize, 0)
	assert.Equal(t, "2", tempStore) // MEMORY = 2
	assert.Equal(t, 10000, cacheSize)
}
