package database

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupMigrationTest(t *testing.T) (*gorm.DB, *Migrator, *bytes.Buffer) {
	// Create an in-memory SQLite database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Create a buffer to capture logs
	logBuffer := new(bytes.Buffer)
	logger := func(format string, args ...interface{}) {
		fmt.Fprintf(logBuffer, format+"\n", args...)
	}

	// Create migrator with test options
	options := DefaultMigrateOptions()
	options.Logger = logger

	migrator, err := NewMigrator(db, options)
	require.NoError(t, err)

	// Add test migrations
	migrator.AddMigrations(
		&Migration{
			Version: 1,
			Name:    "create_test_table",
			Up: func(tx *gorm.DB) error {
				return tx.Exec("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)").Error
			},
			Down: func(tx *gorm.DB) error {
				return tx.Exec("DROP TABLE IF EXISTS test_table").Error
			},
		},
		&Migration{
			Version: 2,
			Name:    "add_email_column",
			Up: func(tx *gorm.DB) error {
				return tx.Exec("ALTER TABLE test_table ADD COLUMN email TEXT").Error
			},
			Down: func(tx *gorm.DB) error {
				// SQLite doesn't support dropping columns without recreating the table
				// For test purposes, we'll just do nothing
				return nil
			},
		},
		&Migration{
			Version: 3,
			Name:    "create_another_table",
			Up: func(tx *gorm.DB) error {
				return tx.Exec("CREATE TABLE another_table (id INTEGER PRIMARY KEY, value TEXT)").Error
			},
			Down: func(tx *gorm.DB) error {
				return tx.Exec("DROP TABLE IF EXISTS another_table").Error
			},
		},
	)

	return db, migrator, logBuffer
}

func TestMigrator_MigrateUp(t *testing.T) {
	db, migrator, logBuffer := setupMigrationTest(t)

	// Run migrations
	err := migrator.MigrateUp()
	require.NoError(t, err)

	// Check if tables were created
	tables := []string{"test_table", "another_table", "migration_records"}
	for _, table := range tables {
		assert.True(t, db.Migrator().HasTable(table), "Table %s should exist", table)
	}

	// Check if the migration records were created
	var count int64
	db.Model(&MigrationRecord{}).Count(&count)
	assert.Equal(t, int64(3), count)

	// Check log output
	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "Migrating to version 1: create_test_table")
	assert.Contains(t, logOutput, "Migrating to version 2: add_email_column")
	assert.Contains(t, logOutput, "Migrating to version 3: create_another_table")
	assert.Contains(t, logOutput, "Database is at version 3")
}

func TestMigrator_MigrateDown(t *testing.T) {
	db, migrator, logBuffer := setupMigrationTest(t)

	// First apply all migrations
	err := migrator.MigrateUp()
	require.NoError(t, err)

	// Clear log buffer
	logBuffer.Reset()

	// Roll back to version 1 (requires force)
	migrator.options.Force = true
	err = migrator.MigrateDown(1)
	require.NoError(t, err)

	// Check if tables were modified as expected
	assert.True(t, db.Migrator().HasTable("test_table"), "test_table should still exist")
	assert.False(t, db.Migrator().HasTable("another_table"), "another_table should not exist")

	// Check if the migration records were updated
	var count int64
	db.Model(&MigrationRecord{}).Count(&count)
	assert.Equal(t, int64(1), count)

	// Check log output
	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "Rolling back version 3: create_another_table")
	assert.Contains(t, logOutput, "Rolling back version 2: add_email_column")
	assert.Contains(t, logOutput, "Database is at version 1")
}

func TestMigrator_GetCurrentVersion(t *testing.T) {
	_, migrator, _ := setupMigrationTest(t) // Use _ for unused db

	// Initial version should be 0
	version, err := migrator.GetCurrentVersion()
	require.NoError(t, err)
	assert.Equal(t, 0, version)

	// Apply migrations
	err = migrator.MigrateUp()
	require.NoError(t, err)

	// Version should be 3
	version, err = migrator.GetCurrentVersion()
	require.NoError(t, err)
	assert.Equal(t, 3, version)

	// Roll back to version 1 (requires force)
	migrator.options.Force = true
	err = migrator.MigrateDown(1)
	require.NoError(t, err)

	// Version should be 1
	version, err = migrator.GetCurrentVersion()
	require.NoError(t, err)
	assert.Equal(t, 1, version)
}

func TestMigrator_GetMigrationStatus(t *testing.T) {
	_, migrator, _ := setupMigrationTest(t) // Use _ for unused db

	// Get status before migrations
	status, err := migrator.GetMigrationStatus()
	require.NoError(t, err)
	assert.Len(t, status, 3)
	for _, s := range status {
		assert.False(t, s["applied"].(bool))
	}

	// Apply migrations
	err = migrator.MigrateUp()
	require.NoError(t, err)

	// Get status after migrations
	status, err = migrator.GetMigrationStatus()
	require.NoError(t, err)
	assert.Len(t, status, 3)
	for _, s := range status {
		assert.True(t, s["applied"].(bool))
		assert.NotNil(t, s["applied_at"])
	}

	// Roll back to version 1 (requires force)
	migrator.options.Force = true
	err = migrator.MigrateDown(1)
	require.NoError(t, err)

	// Get status after rollback
	status, err = migrator.GetMigrationStatus()
	require.NoError(t, err)
	assert.Len(t, status, 3)

	// First migration should be applied
	assert.True(t, status[0]["applied"].(bool))
	assert.Equal(t, 1, status[0]["version"])

	// Other migrations should not be applied
	assert.False(t, status[1]["applied"].(bool))
	assert.Equal(t, 2, status[1]["version"])
	assert.False(t, status[2]["applied"].(bool))
	assert.Equal(t, 3, status[2]["version"])
}

func TestMigrator_DryRun(t *testing.T) {
	db, migrator, logBuffer := setupMigrationTest(t)

	// Enable dry run mode
	migrator.options.DryRun = true

	// Run migrations
	err := migrator.MigrateUp()
	require.NoError(t, err)

	// Check if tables were NOT created (dry run)
	tables := []string{"test_table", "another_table"}
	for _, table := range tables {
		assert.False(t, db.Migrator().HasTable(table), "Table %s should not exist in dry run", table)
	}

	// Migration records table should exist but be empty
	assert.True(t, db.Migrator().HasTable(&MigrationRecord{}), "Migration records table should exist")

	var count int64
	db.Model(&MigrationRecord{}).Count(&count)
	assert.Equal(t, int64(0), count)

	// Check log output
	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "Migrating to version 1: create_test_table")
	assert.Contains(t, logOutput, "Migrating to version 2: add_email_column")
	assert.Contains(t, logOutput, "Migrating to version 3: create_another_table")
}

func TestMigrator_Reset(t *testing.T) {
	db, migrator, logBuffer := setupMigrationTest(t)

	// First apply all migrations
	err := migrator.MigrateUp()
	require.NoError(t, err)

	// Clear log buffer
	logBuffer.Reset()

	// Reset migrations (requires force)
	migrator.options.Force = true
	err = migrator.Reset()
	require.NoError(t, err)

	// Check if tables still exist
	tables := []string{"test_table", "another_table"}
	for _, table := range tables {
		assert.True(t, db.Migrator().HasTable(table), "Table %s should exist after reset", table)
	}

	// Check if the migration records were updated
	var count int64
	db.Model(&MigrationRecord{}).Count(&count)
	assert.Equal(t, int64(3), count)

	// Check log output
	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "Rolling back version 3: create_another_table")
	assert.Contains(t, logOutput, "Rolling back version 2: add_email_column")
	assert.Contains(t, logOutput, "Rolling back version 1: create_test_table")
	assert.Contains(t, logOutput, "Database is at version 0")
	assert.Contains(t, logOutput, "Migrating to version 1: create_test_table")
	assert.Contains(t, logOutput, "Migrating to version 2: add_email_column")
	assert.Contains(t, logOutput, "Migrating to version 3: create_another_table")
	assert.Contains(t, logOutput, "Database is at version 3")
}

func TestMigrator_SilentMode(t *testing.T) {
	_, migrator, logBuffer := setupMigrationTest(t) // Use _ for unused db

	// Enable silent mode
	migrator.options.Silent = true

	// Run migrations
	err := migrator.MigrateUp()
	require.NoError(t, err)

	// Check if log buffer is empty
	assert.Empty(t, logBuffer.String())
}

func TestMigrator_Force(t *testing.T) {
	_, migrator, _ := setupMigrationTest(t) // Use _ for unused db

	// First apply all migrations
	err := migrator.MigrateUp()
	require.NoError(t, err)

	// Try to roll back without force option - This SHOULD fail
	migrator.options.Force = false
	err = migrator.MigrateDown(1)
	require.Error(t, err, "MigrateDown should fail without force when target < current")
	assert.True(t, strings.Contains(err.Error(), "potentially destructive operation"), "Error message should indicate destructive operation")

	// Try to roll back completely without force option
	err = migrator.MigrateDown(0)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "potentially destructive operation"))

	// Enable force option and try again
	migrator.options.Force = true
	err = migrator.MigrateDown(0)
	require.NoError(t, err)

	// Check if all tables were dropped
	version, err := migrator.GetCurrentVersion()
	require.NoError(t, err)
	assert.Equal(t, 0, version)
}

func TestMigrator_AddMigration(t *testing.T) {
	_, migrator, _ := setupMigrationTest(t)

	// Clear existing migrations
	migrator.migrations = []*Migration{}

	// Add a single migration
	migration := &Migration{
		Version: 1,
		Name:    "test_migration",
		Up: func(tx *gorm.DB) error {
			return nil
		},
		Down: func(tx *gorm.DB) error {
			return nil
		},
	}
	migrator.AddMigration(migration)

	assert.Len(t, migrator.migrations, 1)
	assert.Equal(t, migration, migrator.migrations[0])
}

func TestMigrator_RegisterAllMigrations(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	migrator, err := NewMigrator(db, DefaultMigrateOptions())
	require.NoError(t, err)

	// Register all migrations
	migrator.RegisterAllMigrations()

	// Check if migrations were registered
	assert.NotEmpty(t, migrator.migrations)
}
