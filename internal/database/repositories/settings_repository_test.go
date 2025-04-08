package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func setupSettingsRepositoryTest(t *testing.T) (*SettingsRepository, sqlmock.Sqlmock, *gorm.DB) {
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

	// Create repository
	repo := NewSettingsRepository(gormDB)

	return repo, mock, gormDB
}

func TestSettingsRepository_GetByKey(t *testing.T) {
	repo, mock, _ := setupSettingsRepositoryTest(t)
	ctx := context.Background()

	// Test case 1: Setting found
	t.Run("Found", func(t *testing.T) {
		// Setup expectations
		now := time.Now()
		rows := sqlmock.NewRows([]string{"id", "key", "value", "created_at", "updated_at"}).
			AddRow(1, "test_key", "test_value", now, now)
		// GORM's First() adds ORDER BY id and LIMIT 1, and soft delete check
		expectedSQL := `SELECT * FROM "settings" WHERE key = $1 AND "settings"."deleted_at" IS NULL ORDER BY "settings"."id" LIMIT $2`
		mock.ExpectQuery(regexp.QuoteMeta(expectedSQL)).
			WithArgs("test_key", 1). // Expect key and limit=1
			WillReturnRows(rows)

		// Call repository method
		setting, err := repo.GetByKey(ctx, "test_key")
		assert.NoError(t, err)
		assert.NotNil(t, setting)
		assert.Equal(t, "test_key", setting.Key)
		assert.Equal(t, "test_value", setting.Value)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: Setting not found
	t.Run("NotFound", func(t *testing.T) {
		// Setup expectations
		// GORM's First() adds ORDER BY id and LIMIT 1, and soft delete check
		expectedSQL := `SELECT * FROM "settings" WHERE key = $1 AND "settings"."deleted_at" IS NULL ORDER BY "settings"."id" LIMIT $2`
		mock.ExpectQuery(regexp.QuoteMeta(expectedSQL)).
			WithArgs("nonexistent_key", 1). // Expect key and limit=1
			WillReturnError(gorm.ErrRecordNotFound)

		// Call repository method
		setting, err := repo.GetByKey(ctx, "nonexistent_key")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))
		assert.Nil(t, setting)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSettingsRepository_GetObject(t *testing.T) {
	repo, mock, _ := setupSettingsRepositoryTest(t)
	ctx := context.Background()

	// Test case 1: Successfully retrieve and unmarshal object
	t.Run("Success", func(t *testing.T) {
		// Test object
		testObj := models.UserSettings{
			UITheme:           "dark",
			ContainersPerPage: 25,
			RefreshInterval:   60,
		}
		jsonStr, _ := json.Marshal(testObj)

		// Setup expectations
		now := time.Now()
		rows := sqlmock.NewRows([]string{"id", "key", "value", "created_at", "updated_at"}).
			AddRow(1, "user_settings", string(jsonStr), now, now)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "settings" WHERE key = $1`)).
			WithArgs("user_settings").
			WillReturnRows(rows)

		// Call repository method
		var result models.UserSettings
		err := repo.GetObject(ctx, "user_settings", &result)
		assert.NoError(t, err)
		assert.Equal(t, testObj.UITheme, result.UITheme)
		assert.Equal(t, testObj.ContainersPerPage, result.ContainersPerPage)
		assert.Equal(t, testObj.RefreshInterval, result.RefreshInterval)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: Setting not found
	t.Run("NotFound", func(t *testing.T) {
		// Setup expectations
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "settings" WHERE key = $1`)).
			WithArgs("nonexistent_key").
			WillReturnError(gorm.ErrRecordNotFound)

		// Call repository method
		var result models.UserSettings
		err := repo.GetObject(ctx, "nonexistent_key", &result)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 3: Invalid JSON
	t.Run("InvalidJSON", func(t *testing.T) {
		// Setup expectations
		now := time.Now()
		rows := sqlmock.NewRows([]string{"id", "key", "value", "created_at", "updated_at"}).
			AddRow(1, "invalid_json", "not a valid json", now, now)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "settings" WHERE key = $1`)).
			WithArgs("invalid_json").
			WillReturnRows(rows)

		// Call repository method
		var result models.UserSettings
		err := repo.GetObject(ctx, "invalid_json", &result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal")

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSettingsRepository_SetObject(t *testing.T) {
	repo, mock, _ := setupSettingsRepositoryTest(t)
	ctx := context.Background()

	// Test object
	testObj := models.SystemSettings{
		DockerHost:      "unix:///var/run/docker_test.sock",
		DockerTLSVerify: false,
		MaxContainers:   200,
	}

	// Test case: Successfully marshal and set object
	t.Run("Success", func(t *testing.T) {
		// Setup expectations for checking if setting exists
		mock.ExpectBegin()
		countRows := sqlmock.NewRows([]string{"count"}).AddRow(0)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "settings" WHERE key = $1`)).
			WithArgs("system_settings").
			WillReturnRows(countRows)

		// Setup expectations for creating new setting
		mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "settings"`)).
			WithArgs(sqlmock.AnyArg(), "system_settings", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), nil).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.SetObject(ctx, "system_settings", testObj)
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSettingsRepository_Set(t *testing.T) {
	repo, mock, _ := setupSettingsRepositoryTest(t)
	ctx := context.Background()

	// Test case 1: Create new setting
	t.Run("Create", func(t *testing.T) {
		// Setup expectations for checking if setting exists
		mock.ExpectBegin()
		countRows := sqlmock.NewRows([]string{"count"}).AddRow(0)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "settings" WHERE key = $1`)).
			WithArgs("new_key").
			WillReturnRows(countRows)

		// Setup expectations for creating new setting
		mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "settings"`)).
			WithArgs(sqlmock.AnyArg(), "new_key", "new_value", sqlmock.AnyArg(), sqlmock.AnyArg(), nil).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.Set(ctx, "new_key", "new_value")
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: Update existing setting
	t.Run("Update", func(t *testing.T) {
		// Setup expectations for checking if setting exists
		mock.ExpectBegin()
		countRows := sqlmock.NewRows([]string{"count"}).AddRow(1)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "settings" WHERE key = $1`)).
			WithArgs("existing_key").
			WillReturnRows(countRows)

		// Setup expectations for updating setting
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "settings" SET "value"=$1,"updated_at"=$2 WHERE key = $3`)).
			WithArgs("updated_value", sqlmock.AnyArg(), "existing_key").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.Set(ctx, "existing_key", "updated_value")
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSettingsRepository_Delete(t *testing.T) {
	repo, mock, _ := setupSettingsRepositoryTest(t)
	ctx := context.Background()

	// Test case 1: Successful delete
	t.Run("Success", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "settings" SET "deleted_at"=$1 WHERE key = $2 AND "settings"."deleted_at" IS NULL`)).
			WithArgs(sqlmock.AnyArg(), "delete_key").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.Delete(ctx, "delete_key")
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: Setting not found
	t.Run("NotFound", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "settings" SET "deleted_at"=$1 WHERE key = $2 AND "settings"."deleted_at" IS NULL`)).
			WithArgs(sqlmock.AnyArg(), "nonexistent_key").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectCommit()

		// Call repository method
		err := repo.Delete(ctx, "nonexistent_key")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSettingsRepository_ListKeys(t *testing.T) {
	repo, mock, _ := setupSettingsRepositoryTest(t)
	ctx := context.Background()

	// Test case: List keys
	t.Run("ListKeys", func(t *testing.T) {
		// Setup expectations
		rows := sqlmock.NewRows([]string{"key"}).
			AddRow("key1").
			AddRow("key2").
			AddRow("key3")
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT "key" FROM "settings"`)).
			WillReturnRows(rows)

		// Call repository method
		keys, err := repo.ListKeys(ctx)
		assert.NoError(t, err)
		assert.Len(t, keys, 3)
		assert.Equal(t, []string{"key1", "key2", "key3"}, keys)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSettingsRepository_List(t *testing.T) {
	repo, mock, _ := setupSettingsRepositoryTest(t)
	ctx := context.Background()

	// Test case: List all settings
	t.Run("ListAll", func(t *testing.T) {
		// Setup expectations
		now := time.Now()
		rows := sqlmock.NewRows([]string{"id", "key", "value", "created_at", "updated_at"}).
			AddRow(1, "key1", "value1", now, now).
			AddRow(2, "key2", "value2", now, now).
			AddRow(3, "key3", "value3", now, now)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "settings"`)).
			WillReturnRows(rows)

		// Call repository method
		settings, err := repo.List(ctx)
		assert.NoError(t, err)
		assert.Len(t, settings, 3)
		assert.Equal(t, "key1", settings[0].Key)
		assert.Equal(t, "key2", settings[1].Key)
		assert.Equal(t, "key3", settings[2].Key)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSettingsRepository_GetVersioned(t *testing.T) {
	repo, mock, _ := setupSettingsRepositoryTest(t)
	ctx := context.Background()

	// Test case 1: Versioned setting found
	t.Run("Found", func(t *testing.T) {
		// Setup expectations
		now := time.Now()
		rows := sqlmock.NewRows([]string{"id", "key", "value", "version", "metadata", "created_at"}).
			AddRow(1, "config", "config_value_v1", 1, "{}", now)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "versioned_settings" WHERE key = $1 AND version = $2`)).
			WithArgs("config", 1).
			WillReturnRows(rows)

		// Call repository method
		setting, err := repo.GetVersioned(ctx, "config", 1)
		assert.NoError(t, err)
		assert.NotNil(t, setting)
		assert.Equal(t, "config", setting.Key)
		assert.Equal(t, "config_value_v1", setting.Value)
		assert.Equal(t, 1, setting.Version)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: Versioned setting not found
	t.Run("NotFound", func(t *testing.T) {
		// Setup expectations
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "versioned_settings" WHERE key = $1 AND version = $2`)).
			WithArgs("nonexistent_key", 1).
			WillReturnError(gorm.ErrRecordNotFound)

		// Call repository method
		setting, err := repo.GetVersioned(ctx, "nonexistent_key", 1)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))
		assert.Nil(t, setting)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSettingsRepository_GetLatestVersioned(t *testing.T) {
	repo, mock, _ := setupSettingsRepositoryTest(t)
	ctx := context.Background()

	// Test case: Get latest versioned setting
	t.Run("GetLatest", func(t *testing.T) {
		// Setup expectations
		now := time.Now()
		rows := sqlmock.NewRows([]string{"id", "key", "value", "version", "metadata", "created_at"}).
			AddRow(3, "config", "config_value_v3", 3, "{}", now)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "versioned_settings" WHERE key = $1 ORDER BY version DESC`)).
			WithArgs("config").
			WillReturnRows(rows)

		// Call repository method
		setting, err := repo.GetLatestVersioned(ctx, "config")
		assert.NoError(t, err)
		assert.NotNil(t, setting)
		assert.Equal(t, "config", setting.Key)
		assert.Equal(t, "config_value_v3", setting.Value)
		assert.Equal(t, 3, setting.Version)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSettingsRepository_CreateVersioned(t *testing.T) {
	repo, mock, _ := setupSettingsRepositoryTest(t)
	ctx := context.Background()

	// Test metadata
	metadata := map[string]interface{}{
		"author":  "test_user",
		"comment": "test update",
	}

	// Test case: Create new versioned setting
	t.Run("Create", func(t *testing.T) {
		// Setup expectations for getting current version
		mock.ExpectBegin()
		versionRows := sqlmock.NewRows([]string{"version"}).AddRow(2)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT COALESCE(MAX(version), 0) FROM "versioned_settings" WHERE key = $1`)).
			WithArgs("config").
			WillReturnRows(versionRows)

		// Setup expectations for creating new version
		mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "versioned_settings"`)).
			WithArgs(sqlmock.AnyArg(), "config", "new_config_value", 3, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(3))
		mock.ExpectCommit()

		// Call repository method
		err := repo.CreateVersioned(ctx, "config", "new_config_value", metadata)
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSettingsRepository_ListVersions(t *testing.T) {
	repo, mock, _ := setupSettingsRepositoryTest(t)
	ctx := context.Background()

	// Test case: List versions of a setting
	t.Run("ListVersions", func(t *testing.T) {
		// Setup expectations
		now := time.Now()
		rows := sqlmock.NewRows([]string{"id", "key", "value", "version", "metadata", "created_at"}).
			AddRow(3, "config", "config_value_v3", 3, "{}", now).
			AddRow(2, "config", "config_value_v2", 2, "{}", now.Add(-time.Hour)).
			AddRow(1, "config", "config_value_v1", 1, "{}", now.Add(-2*time.Hour))
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "versioned_settings" WHERE key = $1 ORDER BY version DESC`)).
			WithArgs("config").
			WillReturnRows(rows)

		// Call repository method
		settings, err := repo.ListVersions(ctx, "config")
		assert.NoError(t, err)
		assert.Len(t, settings, 3)
		assert.Equal(t, 3, settings[0].Version)
		assert.Equal(t, 2, settings[1].Version)
		assert.Equal(t, 1, settings[2].Version)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestSettingsRepository_OptimisticUpdate(t *testing.T) {
	repo, mock, _ := setupSettingsRepositoryTest(t)
	ctx := context.Background()

	// Test setting
	now := time.Now()
	setting := &models.Setting{
		ID:        1,
		Key:       "test_key",
		Value:     "updated_value",
		UpdatedAt: now,
	}

	// Test case 1: Successful update
	t.Run("Success", func(t *testing.T) {
		// Setup expectations for getting current version
		rows := sqlmock.NewRows([]string{"updated_at"}).AddRow(now)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT "updated_at" FROM "settings" WHERE key = $1`)).
			WithArgs("test_key").
			WillReturnRows(rows)

		// Setup expectations for update
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "settings" SET "value"=$1,"updated_at"=$2 WHERE key = $3 AND updated_at = $4`)).
			WithArgs("updated_value", sqlmock.AnyArg(), "test_key", now).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.OptimisticUpdate(ctx, setting)
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: Concurrent update
	t.Run("ConcurrentUpdate", func(t *testing.T) {
		// Setup expectations for getting current version
		differentTime := now.Add(time.Second)
		rows := sqlmock.NewRows([]string{"updated_at"}).AddRow(differentTime)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT "updated_at" FROM "settings" WHERE key = $1`)).
			WithArgs("test_key").
			WillReturnRows(rows)

		// Call repository method
		err := repo.OptimisticUpdate(ctx, setting)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrConcurrentUpdate))

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
