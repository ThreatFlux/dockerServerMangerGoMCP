package database

import (
	"fmt"
	"sort"
	"time"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"gorm.io/gorm"
)

// Migration represents a database migration
type Migration struct {
	// Version is the migration version (e.g., 1, 2, 3, ...)
	Version int

	// Name is a descriptive name for the migration
	Name string

	// Up performs the migration
	Up func(tx *gorm.DB) error

	// Down rolls back the migration
	Down func(tx *gorm.DB) error
}

// MigrationRecord represents a record of a migration in the database
type MigrationRecord struct {
	ID        uint   `gorm:"primaryKey"`
	Version   int    `gorm:"uniqueIndex"`
	Name      string `gorm:"size:255"`
	AppliedAt time.Time
}

// MigrateOptions provides options for migration operations
type MigrateOptions struct {
	// DryRun if true, will only print migration operations without executing them
	DryRun bool

	// Force if true, will allow potentially destructive migration operations
	Force bool

	// Silent if true, will not print output during migration
	Silent bool

	// Logger is a function that logs migration operations
	Logger func(format string, args ...interface{})
}

// DefaultMigrateOptions returns the default migration options
func DefaultMigrateOptions() MigrateOptions {
	return MigrateOptions{
		DryRun: false,
		Force:  false,
		Silent: false,
		Logger: func(format string, args ...interface{}) {
			fmt.Printf(format+"\n", args...)
		},
	}
}

// Migrator manages database migrations
type Migrator struct {
	db         *gorm.DB
	migrations []*Migration
	options    MigrateOptions
}

// NewMigrator creates a new migrator
func NewMigrator(db *gorm.DB, options MigrateOptions) (*Migrator, error) {
	return &Migrator{
		db:         db,
		migrations: []*Migration{},
		options:    options,
	}, nil
}

// AddMigration adds a migration to the migrator
func (m *Migrator) AddMigration(migration *Migration) {
	m.migrations = append(m.migrations, migration)
}

// AddMigrations adds multiple migrations to the migrator
func (m *Migrator) AddMigrations(migrations ...*Migration) {
	m.migrations = append(m.migrations, migrations...)
}

// RegisterAllMigrations registers all application migrations
func (m *Migrator) RegisterAllMigrations() {
	// Add all migrations here
	m.AddMigrations(
		// Initial schema
		&Migration{
			Version: 1,
			Name:    "create_initial_schema",
			Up: func(tx *gorm.DB) error {
				return tx.AutoMigrate(
					&models.User{},
					&models.UserRole{},
					&models.Token{},
					&models.Volume{},
					&models.Network{},
					&models.Image{},
					&models.Container{},         // Added Container model
					&models.ComposeDeployment{}, // Added ComposeDeployment model
					&models.ComposeService{},    // Added ComposeService model
					// Add other models as needed
				)
			},
			Down: func(tx *gorm.DB) error {
				// Drop tables in reverse order of creation
				return tx.Migrator().DropTable(
					&models.ComposeService{},
					&models.ComposeDeployment{},
					&models.Container{},
					&models.Image{},
					&models.Network{},
					&models.Volume{},
					&models.Token{},
					&models.UserRole{},
					&models.User{},
					// Add other models as needed
				)
			},
		},
		// Migration to increase image_id size
		&Migration{
			Version: 2,
			Name:    "increase_image_id_size",
			Up: func(tx *gorm.DB) error {
				// Use AlterColumn for existing tables
				// Adjust type based on your DB (e.g., VARCHAR(128) for PostgreSQL)
				return tx.Migrator().AlterColumn(&models.Image{}, "ImageID")
			},
			Down: func(tx *gorm.DB) error {
				// Revert column type if needed (might cause data loss)
				// Adjust type based on your DB (e.g., VARCHAR(64) for PostgreSQL)
				// Example for PostgreSQL:
				// return tx.Exec("ALTER TABLE images ALTER COLUMN image_id TYPE VARCHAR(64)").Error
				m.log("Warning: Rolling back migration 2 may truncate image_id data.")
				// For simplicity, we might just log a warning or do nothing on rollback
				// depending on the desired rollback behavior.
				// Let's try altering back, but be aware of potential data loss.
				// Need to get the exact previous type. Assuming it was varchar(64).
				// This might fail if data longer than 64 exists.
				return tx.Exec("ALTER TABLE images ALTER COLUMN image_id TYPE VARCHAR(64)").Error
			},
		},
		// Add more migrations here as needed
	)
}

// MigrateUp migrates the database to the latest version
func (m *Migrator) MigrateUp() error {
	// Make sure migration records table exists
	if err := m.db.AutoMigrate(&MigrationRecord{}); err != nil {
		return fmt.Errorf("failed to create migration records table: %w", err)
	}

	// Get current migration version
	currentVersion, err := m.GetCurrentVersion()
	if err != nil {
		return err
	}

	// Sort migrations by version
	m.sortMigrations()

	// Apply pending migrations
	for _, migration := range m.migrations {
		if migration.Version <= currentVersion {
			// Migration already applied
			continue
		}

		// Log migration
		m.log("Migrating to version %d: %s", migration.Version, migration.Name)

		// Skip actual migration in dry run mode
		if m.options.DryRun {
			continue
		}

		// Apply migration in a transaction
		err := m.db.Transaction(func(tx *gorm.DB) error {
			// Apply migration
			if err := migration.Up(tx); err != nil {
				return fmt.Errorf("migration up error (version %d): %w", migration.Version, err)
			}

			// Record migration
			record := MigrationRecord{
				Version:   migration.Version,
				Name:      migration.Name,
				AppliedAt: time.Now(),
			}
			if err := tx.Create(&record).Error; err != nil {
				return fmt.Errorf("failed to record migration (version %d): %w", migration.Version, err)
			}

			return nil
		})

		if err != nil {
			return err
		}

		m.log("Applied migration version %d", migration.Version)
	}

	latestVersion, err := m.GetCurrentVersion()
	if err != nil {
		return err
	}

	m.log("Database is at version %d", latestVersion)
	return nil
}

// MigrateDown rolls back the database to a specific version
func (m *Migrator) MigrateDown(targetVersion int) error {
	// Make sure migration records table exists
	if err := m.db.AutoMigrate(&MigrationRecord{}); err != nil {
		return fmt.Errorf("failed to create migration records table: %w", err)
	}

	// Get current migration version
	currentVersion, err := m.GetCurrentVersion()
	if err != nil {
		return err
	}

	// Sort migrations by version (descending for rollback)
	m.sortMigrationsDesc()

	// Check if the rollback is potentially destructive
	if !m.options.Force && targetVersion < currentVersion {
		return fmt.Errorf("potentially destructive operation, use force option to proceed")
	}

	// Apply rollbacks
	for _, migration := range m.migrations {
		// Skip migrations that are already at or below the target version
		if migration.Version <= targetVersion {
			continue
		}

		// Skip migrations that are above the current version (not applied yet)
		if migration.Version > currentVersion {
			continue
		}

		// Log migration
		m.log("Rolling back version %d: %s", migration.Version, migration.Name)

		// Skip actual rollback in dry run mode
		if m.options.DryRun {
			continue
		}

		// Apply rollback in a transaction
		err := m.db.Transaction(func(tx *gorm.DB) error {
			// Apply rollback
			if err := migration.Down(tx); err != nil {
				return fmt.Errorf("migration down error (version %d): %w", migration.Version, err)
			}

			// Remove migration record
			if err := tx.Where("version = ?", migration.Version).Delete(&MigrationRecord{}).Error; err != nil {
				return fmt.Errorf("failed to remove migration record (version %d): %w", migration.Version, err)
			}

			return nil
		})

		if err != nil {
			return err
		}

		m.log("Rolled back migration version %d", migration.Version)
	}

	latestVersion, err := m.GetCurrentVersion()
	if err != nil {
		return err
	}

	m.log("Database is at version %d", latestVersion)
	return nil
}

// GetCurrentVersion returns the current migration version
func (m *Migrator) GetCurrentVersion() (int, error) {
	// Check if the migration records table exists
	if !m.db.Migrator().HasTable(&MigrationRecord{}) {
		return 0, nil
	}

	var record MigrationRecord
	err := m.db.Order("version desc").First(&record).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to get current migration version: %w", err)
	}

	return record.Version, nil
}

// GetMigrationStatus returns the status of all migrations
func (m *Migrator) GetMigrationStatus() ([]map[string]interface{}, error) {
	// Make sure migration records table exists
	if err := m.db.AutoMigrate(&MigrationRecord{}); err != nil {
		return nil, fmt.Errorf("failed to create migration records table: %w", err)
	}

	// Sort migrations by version
	m.sortMigrations()

	// Get applied migrations
	var records []MigrationRecord
	if err := m.db.Find(&records).Error; err != nil {
		return nil, fmt.Errorf("failed to get migration records: %w", err)
	}

	// Create a map of applied migrations
	appliedMigrations := make(map[int]*MigrationRecord)
	for i := range records {
		appliedMigrations[records[i].Version] = &records[i]
	}

	// Create status list
	var status []map[string]interface{}
	for _, migration := range m.migrations {
		record, applied := appliedMigrations[migration.Version]

		statusEntry := map[string]interface{}{
			"version": migration.Version,
			"name":    migration.Name,
			"applied": applied,
		}

		if applied {
			statusEntry["applied_at"] = record.AppliedAt
		}

		status = append(status, statusEntry)
	}

	return status, nil
}

// Reset resets the database by rolling back all migrations and applying them again
func (m *Migrator) Reset() error {
	// Roll back to version 0
	if err := m.MigrateDown(0); err != nil {
		return err
	}

	// Apply all migrations
	return m.MigrateUp()
}

// sortMigrations sorts migrations by version (ascending)
func (m *Migrator) sortMigrations() {
	sort.Slice(m.migrations, func(i, j int) bool {
		return m.migrations[i].Version < m.migrations[j].Version
	})
}

// sortMigrationsDesc sorts migrations by version (descending)
func (m *Migrator) sortMigrationsDesc() {
	sort.Slice(m.migrations, func(i, j int) bool {
		return m.migrations[i].Version > m.migrations[j].Version
	})
}

// log logs a message with the configured logger
func (m *Migrator) log(format string, args ...interface{}) {
	if !m.options.Silent && m.options.Logger != nil {
		m.options.Logger(format, args...)
	}
}
