package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetEnv(t *testing.T) {
	// Test when environment variable is not set
	os.Unsetenv("DSM_TEST_ENV_VAR")
	value := GetEnv("TEST_ENV_VAR", "default") // GetEnv adds the prefix internally
	assert.Equal(t, "default", value)

	// Test when environment variable is set
	os.Setenv("DSM_TEST_ENV_VAR", "test-value")
	value = GetEnv("TEST_ENV_VAR", "default") // GetEnv adds the prefix internally
	assert.Equal(t, "test-value", value)

	// Cleanup
	os.Unsetenv("DSM_TEST_ENV_VAR")
}

func TestRequireEnv(t *testing.T) {
	// Test when environment variable is set
	os.Setenv("DSM_TEST_ENV_VAR", "test-value")
	value := RequireEnv("TEST_ENV_VAR") // RequireEnv adds the prefix internally
	assert.Equal(t, "test-value", value)

	// Test when environment variable is not set
	os.Unsetenv("DSM_TEST_ENV_VAR")
	assert.Panics(t, func() {
		RequireEnv("TEST_ENV_VAR") // RequireEnv adds the prefix internally
	})
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		setEnv   bool
		defValue bool
		expected bool
	}{
		{"not set", "", false, true, true},
		{"not set", "", false, false, false},
		{"true", "true", true, false, true},
		{"yes", "yes", true, false, true},
		{"1", "1", true, false, true},
		{"false", "false", true, true, false},
		{"no", "no", true, true, false},
		{"0", "0", true, true, false},
		{"invalid", "invalid", true, true, true},
		{"invalid", "invalid", true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				os.Setenv("DSM_TEST_ENV_VAR", tt.envValue)
			} else {
				os.Unsetenv("DSM_TEST_ENV_VAR")
			}

			value := GetEnvBool("TEST_ENV_VAR", tt.defValue)
			assert.Equal(t, tt.expected, value)
		})
	}

	// Cleanup
	os.Unsetenv("DSM_TEST_ENV_VAR")
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		setEnv   bool
		defValue int
		expected int
	}{
		{"not set", "", false, 42, 42},
		{"valid", "123", true, 42, 123},
		{"invalid", "abc", true, 42, 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				os.Setenv("DSM_TEST_ENV_VAR", tt.envValue)
			} else {
				os.Unsetenv("DSM_TEST_ENV_VAR")
			}

			value := GetEnvInt("TEST_ENV_VAR", tt.defValue)
			assert.Equal(t, tt.expected, value)
		})
	}

	// Cleanup
	os.Unsetenv("DSM_TEST_ENV_VAR")
}

func TestGetEnvDuration(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		setEnv   bool
		defValue time.Duration
		expected time.Duration
	}{
		{"not set", "", false, 30 * time.Second, 30 * time.Second},
		{"valid", "1m30s", true, 30 * time.Second, 90 * time.Second},
		{"invalid", "abc", true, 30 * time.Second, 30 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				os.Setenv("DSM_TEST_ENV_VAR", tt.envValue)
			} else {
				os.Unsetenv("DSM_TEST_ENV_VAR")
			}

			value := GetEnvDuration("TEST_ENV_VAR", tt.defValue)
			assert.Equal(t, tt.expected, value)
		})
	}

	// Cleanup
	os.Unsetenv("DSM_TEST_ENV_VAR")
}

func TestGetEnvArray(t *testing.T) {
	tests := []struct {
		name      string
		envValue  string
		setEnv    bool
		defValue  []string
		separator string
		expected  []string
	}{
		{"not set", "", false, []string{"a", "b"}, ",", []string{"a", "b"}},
		{"valid", "x,y,z", true, []string{"a", "b"}, ",", []string{"x", "y", "z"}},
		{"empty string", "", true, []string{"a", "b"}, ",", []string{""}},
		{"custom separator", "x:y:z", true, []string{"a", "b"}, ":", []string{"x", "y", "z"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				os.Setenv("DSM_TEST_ENV_VAR", tt.envValue)
			} else {
				os.Unsetenv("DSM_TEST_ENV_VAR")
			}

			value := GetEnvArray("TEST_ENV_VAR", tt.defValue, tt.separator)
			assert.Equal(t, tt.expected, value)
		})
	}

	// Cleanup
	os.Unsetenv("DSM_TEST_ENV_VAR")
}

func TestIsEnvSet(t *testing.T) {
	// Test when environment variable is not set
	os.Unsetenv("DSM_TEST_ENV_VAR")
	assert.False(t, IsEnvSet("TEST_ENV_VAR")) // IsEnvSet adds prefix internally

	// Test when environment variable is set
	os.Setenv("DSM_TEST_ENV_VAR", "test-value")
	assert.True(t, IsEnvSet("TEST_ENV_VAR")) // IsEnvSet adds prefix internally

	// Cleanup
	os.Unsetenv("DSM_TEST_ENV_VAR")
}

func TestEnvironmentChecks(t *testing.T) {
	// Test IsProduction
	os.Setenv("DSM_ENV", "production")
	assert.True(t, IsProduction())
	assert.False(t, IsDevelopment())
	assert.False(t, IsTest())

	// Test IsDevelopment
	os.Setenv("DSM_ENV", "development")
	assert.False(t, IsProduction())
	assert.True(t, IsDevelopment())
	assert.False(t, IsTest())

	// Test dev shorthand
	os.Setenv("DSM_ENV", "dev")
	assert.False(t, IsProduction())
	assert.True(t, IsDevelopment())
	assert.False(t, IsTest())

	// Test IsTest
	os.Setenv("DSM_ENV", "test")
	assert.False(t, IsProduction())
	assert.False(t, IsDevelopment())
	assert.True(t, IsTest())

	// Test default
	os.Unsetenv("DSM_ENV")
	assert.False(t, IsProduction())
	assert.True(t, IsDevelopment())
	assert.False(t, IsTest())

	// Cleanup
	os.Unsetenv("DSM_ENV")
}
