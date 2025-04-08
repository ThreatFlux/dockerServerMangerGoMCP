package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus" // Added for logger
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// PostgresDB implements the Database interface for PostgreSQL
type PostgresDB struct {
	config *config.Config
	db     *gorm.DB
	sqlDB  *sql.DB
	log    *logrus.Logger // Added logger field
}

// NewPostgresDB creates a new PostgreSQL database instance
func NewPostgresDB(cfg *config.Config, log *logrus.Logger) (*PostgresDB, error) { // Added logger parameter
	return &PostgresDB{
		config: cfg,
		log:    log, // Store logger instance
	}, nil
}

// Connect establishes a connection to the PostgreSQL database
func (p *PostgresDB) Connect() error {
	cfg := p.config.Database

	// Build connection string
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host,
		cfg.Port,
		cfg.User, // Changed from cfg.Username
		cfg.Password,
		cfg.Name,
		getSslMode(cfg.SSLMode),
	)

	// Configure GORM logger using the passed logrus instance
	var logAdapter logger.Writer
	if p.log != nil { // Check if logger instance was provided
		logAdapter = NewLogrusAdapter(p.log) // Pass the logrus logger instance
	} else {
		// Provide a discard writer if no logger is available
		logAdapter = discardWriter{}
	}

	gormLogger := logger.New(
		logAdapter,
		logger.Config{
			SlowThreshold:             time.Second,                         // Log queries slower than 1 second
			LogLevel:                  getLogLevel(p.config.Logging.Level), // Use Logging.Level from config
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	// Connect to database
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Get underlying SQL DB
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying SQL DB: %w", err)
	}

	// Configure connection pool settings
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetime) * time.Second)
	// Add ConnMaxIdleTime if it exists in config (check config.go if needed)
	if cfg.ConnMaxIdleTime > 0 {
		sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	}

	// Set the DB instances
	p.db = db
	p.sqlDB = sqlDB

	return nil
}

// Close closes the database connection
func (p *PostgresDB) Close() error {
	if p.sqlDB != nil {
		return p.sqlDB.Close()
	}
	return nil
}

// DB returns the underlying GORM database instance
func (p *PostgresDB) DB() *gorm.DB {
	return p.db
}

// Ping checks if the database is reachable
func (p *PostgresDB) Ping() error {
	if p.sqlDB == nil {
		return errors.New("database connection not established")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return p.sqlDB.PingContext(ctx)
}

// Transaction executes the given function within a transaction
func (p *PostgresDB) Transaction(fn func(tx *gorm.DB) error) error {
	if p.db == nil {
		return errors.New("database connection not established for transaction")
	}
	return p.db.Transaction(fn)
}

// Migrate runs database migrations
func (p *PostgresDB) Migrate(models ...interface{}) error {
	if p.db == nil {
		return errors.New("database connection not established for migration")
	}
	// AutoMigrate the given models
	return p.db.AutoMigrate(models...)
}

// Helper function to get SSL mode from config
func getSslMode(mode string) string {
	switch strings.ToLower(mode) { // Use ToLower for case-insensitivity
	case "disable", "require", "verify-ca", "verify-full":
		return mode
	default:
		return "disable"
	}
}

// Helper function to get GORM log level from config
func getLogLevel(level string) logger.LogLevel {
	switch strings.ToLower(level) { // Use ToLower for case-insensitivity
	case "debug", "trace": // Map trace to debug as well
		return logger.Info // GORM's Info level logs SQL
	case "info":
		return logger.Info
	case "warn", "warning":
		return logger.Warn
	case "error", "fatal", "panic":
		return logger.Error
	default:
		return logger.Silent
	}
}

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
	// Log everything at Debug level for simplicity, GORM's level filtering handles the rest
	l.logger.Debugf(format, args...)
}

// discardWriter implements logger.Writer but does nothing
type discardWriter struct{}

// Printf implements the logger.Writer interface for discardWriter
func (dw discardWriter) Printf(format string, args ...interface{}) {
	// Do nothing
}

// --- Removed helper functions containsError, containsWarn, containsIgnoreCase ---
// --- as they are not used with the simplified Printf implementation ---
