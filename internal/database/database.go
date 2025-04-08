package database

import (
	"fmt"

	"github.com/sirupsen/logrus" // Added for logger
	"github.com/threatflux/dockerServerMangerGoMCP/internal/config"
	"gorm.io/gorm"
)

// Database represents the interface for database operations
type Database interface {
	// DB returns the underlying database instance
	DB() *gorm.DB

	// Connect establishes a connection to the database
	Connect() error

	// Close closes the database connection
	Close() error

	// Migrate runs database migrations for the given models
	Migrate(models ...interface{}) error // Updated signature

	// Ping checks if the database is reachable
	Ping() error

	// Transaction executes the given function within a transaction
	Transaction(fn func(tx *gorm.DB) error) error
}

// Factory defines interface for creating database instances
type Factory interface {
	// Create returns a database instance based on the configuration and logger
	Create(cfg *config.Config, log *logrus.Logger) (Database, error) // Added logger parameter
}

// DefaultFactory implements the Factory interface
type DefaultFactory struct{}

// NewFactory creates a new database factory
func NewFactory() Factory {
	return &DefaultFactory{}
}

// Create creates a new database instance based on the configuration and logger
func (f *DefaultFactory) Create(cfg *config.Config, log *logrus.Logger) (Database, error) { // Added logger parameter
	switch cfg.Database.Type {
	case "postgres":
		// Pass logger to NewPostgresDB
		return NewPostgresDB(cfg, log)
	case "sqlite":
		// Pass logger to NewSQLiteDB (assuming it will be updated similarly)
		return NewSQLiteDB(cfg, log)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Database.Type)
	}
}

// DBProvider is a function that returns a database instance
type DBProvider func() (*gorm.DB, error)

// GetDB is a global function to get the database instance
// This will be set during application initialization
var GetDB DBProvider

// InitDatabase initializes the database based on configuration
// It now also initializes and passes the logger.
func InitDatabase(cfg *config.Config) (Database, error) {
	// Initialize logger (basic example, replace with actual logger setup if needed)
	log := logrus.New()
	logLevel, err := logrus.ParseLevel(cfg.Logging.Level)
	if err != nil {
		logLevel = logrus.InfoLevel // Default level
		log.Warnf("Invalid log level '%s' in config, using default 'info'", cfg.Logging.Level)
	}
	log.SetLevel(logLevel)
	if cfg.Logging.Format == "json" {
		log.SetFormatter(&logrus.JSONFormatter{})
	} else {
		log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	}
	// TODO: Add file/syslog output based on config.Logging settings if required

	factory := NewFactory()
	// Pass logger to factory Create method
	db, err := factory.Create(cfg, log)
	if err != nil {
		log.WithError(err).Error("Failed to create database instance")
		return nil, err
	}

	log.Info("Connecting to database...")
	if err := db.Connect(); err != nil {
		log.WithError(err).Error("Failed to connect to database")
		return nil, err
	}
	log.Info("Database connection established.")

	// Set up the global GetDB function
	GetDB = func() (*gorm.DB, error) {
		if db == nil {
			return nil, fmt.Errorf("database not initialized")
		}
		return db.DB(), nil
	}

	return db, nil
}

// MockDatabase is a mock implementation of the Database interface for testing
type MockDatabase struct {
	mockDB *gorm.DB // Renamed field to avoid conflict
	Err    error
	Closed bool
}

// NewMockDatabase creates a new mock database
func NewMockDatabase(db *gorm.DB, err error) *MockDatabase {
	return &MockDatabase{
		mockDB: db, // Use renamed field
		Err:    err,
	}
}

// DB returns the underlying database instance
func (m *MockDatabase) DB() *gorm.DB {
	return m.mockDB // Return renamed field
}

// Connect mock implementation
func (m *MockDatabase) Connect() error {
	return m.Err
}

// Close mock implementation
func (m *MockDatabase) Close() error {
	m.Closed = true
	return m.Err
}

// Migrate mock implementation
func (m *MockDatabase) Migrate(models ...interface{}) error { // Updated signature
	return m.Err
}

// Ping mock implementation
func (m *MockDatabase) Ping() error {
	return m.Err
}

// Transaction mock implementation
func (m *MockDatabase) Transaction(fn func(tx *gorm.DB) error) error {
	if m.Err != nil {
		return m.Err
	}
	// Use the DB() method to get the *gorm.DB instance
	dbInstance := m.DB()
	if dbInstance == nil {
		return fmt.Errorf("mock database instance is nil")
	}
	return fn(dbInstance)
}
