package repositories

import (
	"context"
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

func setupUserRepositoryTest(t *testing.T) (UserRepository, sqlmock.Sqlmock, *gorm.DB) { // Return interface
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
	repo := NewUserRepository(gormDB)

	return repo, mock, gormDB
}

func TestUserRepository_Create(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test user
	user := &models.User{
		Email:    "test@example.com",
		Password: "hashed_password",
		Name:     "Test User",
		Roles: []models.UserRole{
			{
				Role: models.RoleUser,
			},
		},
		Active: true,
	}

	// Test case 1: Successful creation
	t.Run("Success", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "users"`)).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), user.Email, user.Password, user.Name, user.Active, sqlmock.AnyArg(), sqlmock.AnyArg(), nil).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "user_roles"`)).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), 1, string(models.RoleUser), sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.Create(ctx, user)
		assert.NoError(t, err)
		assert.Equal(t, uint(1), user.ID)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: Duplicate email
	t.Run("DuplicateEmail", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "users"`)).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), user.Email, user.Password, user.Name, user.Active, sqlmock.AnyArg(), sqlmock.AnyArg(), nil).
			WillReturnError(errors.New("duplicate key value violates unique constraint"))
		mock.ExpectRollback()

		// Call repository method
		err := repo.Create(ctx, user)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrDuplicateKey))

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_GetByID(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test case 1: User found
	t.Run("Found", func(t *testing.T) {
		// Setup expectations for user query
		rows := sqlmock.NewRows([]string{"id", "email", "password", "name", "active", "last_login", "email_verified", "created_at", "updated_at"}).
			AddRow(1, "test@example.com", "hashed_password", "Test User", true, nil, false, time.Now(), time.Now())
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE "users"."id" = $1`)).
			WithArgs(1).
			WillReturnRows(rows)

		// Setup expectations for roles query
		roleRows := sqlmock.NewRows([]string{"id", "user_id", "role", "created_at", "updated_at"}).
			AddRow(1, 1, string(models.RoleUser), time.Now(), time.Now())
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_id" = $1`)).
			WithArgs(1).
			WillReturnRows(roleRows)

		// Call repository method
		user, err := repo.GetByID(ctx, 1)
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, uint(1), user.ID)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Len(t, user.Roles, 1)
		assert.Equal(t, models.RoleUser, user.Roles[0].Role)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: User not found
	t.Run("NotFound", func(t *testing.T) {
		// Setup expectations
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE "users"."id" = $1`)).
			WithArgs(999).
			WillReturnError(gorm.ErrRecordNotFound)

		// Call repository method
		user, err := repo.GetByID(ctx, 999)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))
		assert.Nil(t, user)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_GetByEmail(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test case 1: User found
	t.Run("Found", func(t *testing.T) {
		// Setup expectations for user query
		rows := sqlmock.NewRows([]string{"id", "email", "password", "name", "active", "last_login", "email_verified", "created_at", "updated_at"}).
			AddRow(1, "test@example.com", "hashed_password", "Test User", true, nil, false, time.Now(), time.Now())
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1`)).
			WithArgs("test@example.com").
			WillReturnRows(rows)

		// Setup expectations for roles query
		roleRows := sqlmock.NewRows([]string{"id", "user_id", "role", "created_at", "updated_at"}).
			AddRow(1, 1, string(models.RoleUser), time.Now(), time.Now())
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_id" = $1`)).
			WithArgs(1).
			WillReturnRows(roleRows)

		// Call repository method
		user, err := repo.GetByEmail(ctx, "test@example.com")
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, "test@example.com", user.Email)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: User not found
	t.Run("NotFound", func(t *testing.T) {
		// Setup expectations
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1`)).
			WithArgs("nonexistent@example.com").
			WillReturnError(gorm.ErrRecordNotFound)

		// Call repository method
		user, err := repo.GetByEmail(ctx, "nonexistent@example.com")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))
		assert.Nil(t, user)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_Update(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test user
	user := &models.User{
		ID:     1,
		Email:  "updated@example.com",
		Name:   "Updated User",
		Active: true,
	}

	// Test case 1: Successful update
	t.Run("Success", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET`)).
			WithArgs(sqlmock.AnyArg(), user.Email, user.Name, user.Active, 1).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.Update(ctx, user)
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: User not found
	t.Run("NotFound", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET`)).
			WithArgs(sqlmock.AnyArg(), user.Email, user.Name, user.Active, 1).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectCommit()

		// Call repository method
		err := repo.Update(ctx, user)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 3: Duplicate email
	t.Run("DuplicateEmail", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET`)).
			WithArgs(sqlmock.AnyArg(), user.Email, user.Name, user.Active, 1).
			WillReturnError(errors.New("duplicate key value violates unique constraint"))
		mock.ExpectRollback()

		// Call repository method
		err := repo.Update(ctx, user)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrDuplicateKey))

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_Delete(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test case 1: Successful delete
	t.Run("Success", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "deleted_at"=$1 WHERE "users"."id" = $2 AND "users"."deleted_at" IS NULL`)).
			WithArgs(sqlmock.AnyArg(), 1).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.Delete(ctx, 1)
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: User not found
	t.Run("NotFound", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "deleted_at"=$1 WHERE "users"."id" = $2 AND "users"."deleted_at" IS NULL`)).
			WithArgs(sqlmock.AnyArg(), 999).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectCommit()

		// Call repository method
		err := repo.Delete(ctx, 999)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_List(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test case: List users
	t.Run("ListUsers", func(t *testing.T) {
		// Setup count expectation
		countRows := sqlmock.NewRows([]string{"count"}).AddRow(2)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "users"`)).
			WillReturnRows(countRows)

		// Setup user rows
		userRows := sqlmock.NewRows([]string{"id", "email", "password", "name", "active", "last_login", "email_verified", "created_at", "updated_at"}).
			AddRow(1, "user1@example.com", "hash1", "User 1", true, nil, false, time.Now(), time.Now()).
			AddRow(2, "user2@example.com", "hash2", "User 2", true, nil, false, time.Now(), time.Now())

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" LIMIT 10 OFFSET 0`)).
			WillReturnRows(userRows)

		// Setup roles for first user
		roleRows1 := sqlmock.NewRows([]string{"id", "user_id", "role", "created_at", "updated_at"}).
			AddRow(1, 1, string(models.RoleUser), time.Now(), time.Now())
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_id" IN ($1,$2)`)).
			WithArgs(1, 2).
			WillReturnRows(roleRows1)

		// Call repository method
		users, count, err := repo.List(ctx, 0, 10)
		assert.NoError(t, err)
		assert.Equal(t, int64(2), count)
		assert.Len(t, users, 2)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_UpdateRoles(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test roles
	roles := []models.Role{models.RoleAdmin, models.RoleUser}

	// Test case: Update roles
	t.Run("UpdateRoles", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "user_roles" WHERE user_id = $1`)).
			WithArgs(1).
			WillReturnResult(sqlmock.NewResult(0, 1))

		mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "user_roles"`)).
			WithArgs(1, string(models.RoleAdmin), sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

		mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "user_roles"`)).
			WithArgs(1, string(models.RoleUser), sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(2))

		mock.ExpectCommit()

		// Call repository method
		err := repo.UpdateRoles(ctx, 1, roles)
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_UpdatePassword(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test case 1: Successful update
	t.Run("Success", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "password"=$1 WHERE id = $2`)).
			WithArgs("new_hash", 1).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.UpdatePassword(ctx, 1, "new_hash")
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: User not found
	t.Run("NotFound", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "password"=$1 WHERE id = $2`)).
			WithArgs("new_hash", 999).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectCommit()

		// Call repository method
		err := repo.UpdatePassword(ctx, 999, "new_hash")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_UpdateLastLogin(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test case: Update last login
	t.Run("UpdateLastLogin", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "last_login"=$1 WHERE id = $2`)).
			WithArgs(sqlmock.AnyArg(), 1).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.UpdateLastLogin(ctx, 1)
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_ActivateDeactivateUser(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test case 1: Activate user
	t.Run("ActivateUser", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "active"=$1 WHERE id = $2`)).
			WithArgs(true, 1).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.ActivateUser(ctx, 1)
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: Deactivate user
	t.Run("DeactivateUser", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "active"=$1 WHERE id = $2`)).
			WithArgs(false, 1).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.DeactivateUser(ctx, 1)
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_SetEmailVerified(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test case: Set email verified
	t.Run("SetEmailVerified", func(t *testing.T) {
		// Setup expectations
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "email_verified"=$1 WHERE id = $2`)).
			WithArgs(true, 1).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.SetEmailVerified(ctx, 1, true)
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_CheckEmailExists(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test case 1: Email exists
	t.Run("EmailExists", func(t *testing.T) {
		// Setup expectations
		rows := sqlmock.NewRows([]string{"count"}).AddRow(1)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "users" WHERE email = $1`)).
			WithArgs("existing@example.com").
			WillReturnRows(rows)

		// Call repository method
		exists, err := repo.CheckEmailExists(ctx, "existing@example.com")
		assert.NoError(t, err)
		assert.True(t, exists)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: Email does not exist
	t.Run("EmailDoesNotExist", func(t *testing.T) {
		// Setup expectations
		rows := sqlmock.NewRows([]string{"count"}).AddRow(0)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "users" WHERE email = $1`)).
			WithArgs("new@example.com").
			WillReturnRows(rows)

		// Call repository method
		exists, err := repo.CheckEmailExists(ctx, "new@example.com")
		assert.NoError(t, err)
		assert.False(t, exists)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_OptimisticUpdate(t *testing.T) {
	repo, mock, _ := setupUserRepositoryTest(t)
	ctx := context.Background()

	// Test user
	now := time.Now()
	user := &models.User{
		ID:        1,
		Email:     "test@example.com",
		Name:      "Test User",
		UpdatedAt: now,
	}

	// Test case 1: Successful update
	t.Run("Success", func(t *testing.T) {
		// Setup expectations for getting current version
		rows := sqlmock.NewRows([]string{"updated_at"}).AddRow(now)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT "updated_at" FROM "users" WHERE id = $1`)).
			WithArgs(1).
			WillReturnRows(rows)

		// Setup expectations for update
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET`)).
			WithArgs(sqlmock.AnyArg(), user.Email, user.Name, 1, now).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		// Call repository method
		err := repo.OptimisticUpdate(ctx, user)
		assert.NoError(t, err)

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: Concurrent update
	t.Run("ConcurrentUpdate", func(t *testing.T) {
		// Setup expectations for getting current version
		differentTime := now.Add(time.Second)
		rows := sqlmock.NewRows([]string{"updated_at"}).AddRow(differentTime)
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT "updated_at" FROM "users" WHERE id = $1`)).
			WithArgs(1).
			WillReturnRows(rows)

		// Call repository method
		err := repo.OptimisticUpdate(ctx, user)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrConcurrentUpdate))

		// Verify expectations
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestIsDuplicateKeyError(t *testing.T) {
	// Test cases
	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{"PostgresDuplicateKey", errors.New("duplicate key value violates unique constraint"), true},
		{"MySQLDuplicateKey", errors.New("Duplicate entry 'test@example.com' for key 'users.email'"), true},
		{"SQLiteDuplicateKey", errors.New("UNIQUE constraint failed: users.email"), true},
		{"OtherError", errors.New("some other error"), false},
		{"NilError", nil, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isDuplicateKeyError(tc.err)
			assert.Equal(t, tc.expected, result)
		})
	}
}
