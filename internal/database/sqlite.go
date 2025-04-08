package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus" // Added for logger
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// SQLiteDB implements the Database interface for SQLite
type SQLiteDB struct {
	config *config.Config
	db     *gorm.DB
	sqlDB  *sql.DB
	log    *logrus.Logger // Added logger field
}

// NewSQLiteDB creates a new SQLite database instance
func NewSQLiteDB(cfg *config.Config, log *logrus.Logger) (*SQLiteDB, error) { // Added logger parameter
	return &SQLiteDB{
		config: cfg,
		log:    log, // Store logger instance
	}, nil
}

// Connect establishes a connection to the SQLite database
func (s *SQLiteDB) Connect() error {
	// Get database path from config
	databasePath := s.config.Database.SQLite.Path // Corrected path access
	if databasePath == "" {
		databasePath = "docker_test-server-manager.db" // Default path
	}

	// Ensure directory exists
	err := ensureDirectoryExists(databasePath)
	if err != nil {
		return fmt.Errorf("failed to create directory for SQLite database: %w", err)
	}

	// Configure GORM logger using the passed logrus instance
	var logAdapter logger.Writer
	if s.log != nil { // Check if logger instance was provided
		logAdapter = NewLogrusAdapter(s.log) // Pass the logrus logger instance
	} else {
		// Provide a discard writer if no logger is available
		logAdapter = discardWriter{}
	}

	gormLogger := logger.New(
		logAdapter,
		logger.Config{
			SlowThreshold:             time.Second,                         // Log queries slower than 1 second
			LogLevel:                  getLogLevel(s.config.Logging.Level), // Use Logging.Level from config
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	// Connect to database
	db, err := gorm.Open(sqlite.Open(databasePath), &gorm.Config{
		Logger: gormLogger,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to SQLite database: %w", err)
	}

	// Set pragmas for better performance and reliability
	if err := setPragmas(db); err != nil {
		// Log the error but don't necessarily fail the connection
		if s.log != nil {
			s.log.WithError(err).Warn("Failed to set SQLite pragmas")
		}
	}

	// Get underlying SQL DB
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying SQL DB: %w", err)
	}

	// Configure connection pool settings (SQLite typically uses 1 connection)
	sqlDB.SetMaxIdleConns(1) // Recommended for SQLite
	sqlDB.SetMaxOpenConns(1) // Recommended for SQLite
	if s.config.Database.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(s.config.Database.ConnMaxLifetime)
	}
	if s.config.Database.ConnMaxIdleTime > 0 {
		sqlDB.SetConnMaxIdleTime(s.config.Database.ConnMaxIdleTime)
	}

	// Set the DB instances
	s.db = db
	s.sqlDB = sqlDB

	return nil
}

// Close closes the database connection
func (s *SQLiteDB) Close() error {
	if s.sqlDB != nil {
		return s.sqlDB.Close()
	}
	return nil
}

// DB returns the underlying GORM database instance
func (s *SQLiteDB) DB() *gorm.DB {
	return s.db
}

// Ping checks if the database is reachable
func (s *SQLiteDB) Ping() error {
	if s.sqlDB == nil {
		return errors.New("database connection not established")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.sqlDB.PingContext(ctx)
}

// Transaction executes the given function within a transaction
func (s *SQLiteDB) Transaction(fn func(tx *gorm.DB) error) error {
	if s.db == nil {
		return errors.New("database connection not established for transaction")
	}
	return s.db.Transaction(fn)
}

// Migrate runs database migrations
func (s *SQLiteDB) Migrate(models ...interface{}) error { // Updated signature
	if s.db == nil {
		return errors.New("database connection not established for migration")
	}
	// AutoMigrate the given models
	return s.db.AutoMigrate(models...)
}

// ensureDirectoryExists ensures that the directory for the database file exists
func ensureDirectoryExists(databasePath string) error {
	// Get directory from database path
	dir := filepath.Dir(databasePath)

	// If the directory is just the current directory, no need to create it
	if dir == "." || dir == "" {
		return nil
	}

	// Create directory if it doesn't exist
	return os.MkdirAll(dir, 0755) // Use 0755 for directory permissions
}

// setPragmas sets recommended pragmas for SQLite
func setPragmas(db *gorm.DB) error {
	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA busy_timeout = 5000",
		// "PRAGMA mmap_size = 30000000000", // Often large, might cause issues, consider making configurable
		"PRAGMA temp_store = MEMORY",
		// "PRAGMA cache_size = 10000", // Consider making configurable
	}

	for _, pragma := range pragmas {
		if err := db.Exec(pragma).Error; err != nil {
			// Return the first error encountered
			return fmt.Errorf("failed to set pragma '%s': %w", pragma, err)
		}
	}
	return nil
}

// Note: LogrusAdapter and discardWriter are assumed to be defined elsewhere
// (e.g., in postgres.go or a shared utility file) or need to be added here
// if this file is compiled independently in some contexts.
// For simplicity, assuming they are accessible. If not, they need to be copied/defined here.

// Example definitions if needed:

/*
// LogrusAdapter adapts a *logrus.Logger to GORM's logger.Writer interface
type LogrusAdapter struct {
	logger *logrus.Logger
}

// NewLogrusAdapter creates a new Logrus adapter for GORM
func NewLogrusAdapter(log *logrus.Logger) *LogrusAdapter {
	return &LogrusAdapter{
		logger: log,
	}
}

// Printf implements the logger.Writer interface
func (l *LogrusAdapter) Printf(format string, args ...interface{}) {
	if l.logger == nil {
		return
	}
	l.logger.Debugf(format, args...)
}

// discardWriter implements logger.Writer but does nothing
type discardWriter struct{}

// Printf implements the logger.Writer interface for discardWriter
func (dw discardWriter) Printf(format string, args ...interface{}) {
	// Do nothing
}
*/
