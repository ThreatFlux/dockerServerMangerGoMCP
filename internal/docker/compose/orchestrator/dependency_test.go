package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/docker_test/compose" // Removed old import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Added models import
)

// TestNewDependencyManager tests the NewDependencyManager function
func TestNewDependencyManager(t *testing.T) {
	// Create dependency manager
	logger := logrus.New()
	manager := NewDependencyManager(DependencyManagerOptions{
		Logger: logger,
	})

	// Assert
	assert.NotNil(t, manager)
	assert.Equal(t, logger, manager.Logger) // Use capitalized Logger
}

// TestBuildServiceOrder tests the BuildServiceOrder function
func TestBuildServiceOrder(t *testing.T) {
	// Create dependency manager
	manager := NewDependencyManager(DependencyManagerOptions{})

	// Create test compose file
	composeFile := &models.ComposeFile{ // Use models.ComposeFile
		Version: "3",
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service1": {},
			"service2": {
				DependsOn: []string{"service1"},
			},
			"service3": {
				DependsOn: []string{"service2"},
			},
			"service4": {
				DependsOn: []string{"service1", "service3"},
			},
		},
	}

	// Build service order
	order, err := manager.BuildServiceOrder(context.Background(), composeFile, DependencyOrderOptions{
		Timeout: 1 * time.Second,
	})

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, []string{"service1", "service2", "service3", "service4"}, order)
}

// TestBuildServiceOrderWithCycle tests the BuildServiceOrder function with a cycle
func TestBuildServiceOrderWithCycle(t *testing.T) {
	// Create dependency manager
	manager := NewDependencyManager(DependencyManagerOptions{})

	// Create test compose file with cycle
	composeFile := &models.ComposeFile{ // Use models.ComposeFile
		Version: "3",
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service1": {
				DependsOn: []string{"service3"},
			},
			"service2": {
				DependsOn: []string{"service1"},
			},
			"service3": {
				DependsOn: []string{"service2"},
			},
		},
	}

	// Build service order (should fail due to cycle)
	_, err := manager.BuildServiceOrder(context.Background(), composeFile, DependencyOrderOptions{
		Timeout: 1 * time.Second,
	})

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dependency cycle detected")
}

// TestBuildServiceOrderReverse tests the BuildServiceOrderReverse function
func TestBuildServiceOrderReverse(t *testing.T) {
	// Create dependency manager
	manager := NewDependencyManager(DependencyManagerOptions{})

	// Create test compose file
	composeFile := &models.ComposeFile{ // Use models.ComposeFile
		Version: "3",
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service1": {},
			"service2": {
				DependsOn: []string{"service1"},
			},
			"service3": {
				DependsOn: []string{"service2"},
			},
			"service4": {
				DependsOn: []string{"service1", "service3"},
			},
		},
	}

	// Build reverse service order
	order, err := manager.BuildServiceOrderReverse(context.Background(), composeFile, DependencyOrderOptions{
		Timeout: 1 * time.Second,
	})

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, []string{"service4", "service3", "service2", "service1"}, order)
}

// TestGetServiceDependencies tests the GetServiceDependencies function
func TestGetServiceDependencies(t *testing.T) {
	// Create dependency manager
	manager := NewDependencyManager(DependencyManagerOptions{})

	// Create test compose file
	composeFile := &models.ComposeFile{ // Use models.ComposeFile
		Version: "3",
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service1": {},
			"service2": {
				DependsOn: []string{"service1"},
			},
			"service3": {
				DependsOn: []string{"service2"},
			},
			"service4": {
				DependsOn: []string{"service1", "service3"},
			},
		},
	}

	// Test cases
	testCases := []struct {
		serviceName    string
		expectedDeps   []string
		expectError    bool
		errorSubstring string
	}{
		{
			serviceName:  "service1",
			expectedDeps: []string{},
			expectError:  false,
		},
		{
			serviceName:  "service2",
			expectedDeps: []string{"service1"},
			expectError:  false,
		},
		{
			serviceName:  "service3",
			expectedDeps: []string{"service1", "service2"},
			expectError:  false,
		},
		{
			serviceName:  "service4",
			expectedDeps: []string{"service1", "service2", "service3"},
			expectError:  false,
		},
		{
			serviceName:    "nonexistent",
			expectedDeps:   nil,
			expectError:    true,
			errorSubstring: "does not exist",
		},
	}

	// Run tests
	for _, tc := range testCases {
		t.Run(tc.serviceName, func(t *testing.T) {
			// Get dependencies
			deps, err := manager.GetServiceDependencies(composeFile, tc.serviceName)

			// Assert
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorSubstring != "" {
					assert.Contains(t, err.Error(), tc.errorSubstring)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedDeps, deps)
			}
		})
	}
}

// TestGetServiceDependents tests the GetServiceDependents function
func TestGetServiceDependents(t *testing.T) {
	// Create dependency manager
	manager := NewDependencyManager(DependencyManagerOptions{})

	// Create test compose file
	composeFile := &models.ComposeFile{ // Use models.ComposeFile
		Version: "3",
		Services: map[string]models.ServiceConfig{ // Use models.ServiceConfig
			"service1": {},
			"service2": {
				DependsOn: []string{"service1"},
			},
			"service3": {
				DependsOn: []string{"service2"},
			},
			"service4": {
				DependsOn: []string{"service1", "service3"},
			},
		},
	}

	// Test cases
	testCases := []struct {
		serviceName        string
		expectedDependents []string
		expectError        bool
		errorSubstring     string
	}{
		{
			serviceName:        "service1",
			expectedDependents: []string{"service2", "service4"},
			expectError:        false,
		},
		{
			serviceName:        "service2",
			expectedDependents: []string{"service3"},
			expectError:        false,
		},
		{
			serviceName:        "service3",
			expectedDependents: []string{"service4"},
			expectError:        false,
		},
		{
			serviceName:        "service4",
			expectedDependents: []string{},
			expectError:        false,
		},
		{
			serviceName:        "nonexistent",
			expectedDependents: nil,
			expectError:        true,
			errorSubstring:     "does not exist",
		},
	}

	// Run tests
	for _, tc := range testCases {
		t.Run(tc.serviceName, func(t *testing.T) {
			// Get dependents
			deps, err := manager.GetServiceDependents(composeFile, tc.serviceName)

			// Assert
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorSubstring != "" {
					assert.Contains(t, err.Error(), tc.errorSubstring)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedDependents, deps)
			}
		})
	}
}
