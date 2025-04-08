package compose

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// TestComposeOperations tests Docker Compose operation endpoints
func TestComposeOperations(t *testing.T) {
	// Set up test server (uses the modified setup from parser_test.go)
	ts, err := setupTestServer(t)
	require.NoError(t, err)
	defer ts.cleanup() // Cleans up DB, HTTP server

	// Create test user and get token
	token := createTestUser(t, ts)

	// Simple compose file for testing
	// Use a unique suffix for network/volume names to avoid conflicts between test runs
	testSuffix := fmt.Sprintf("test%d", time.Now().UnixNano())
	projectName := fmt.Sprintf("compose-ops-%s", testSuffix) // Define project name based on suffix
	simpleCompose := fmt.Sprintf(`
version: '3.8'
services:
  web:
    image: nginx:alpine
    ports:
      - "8081:80" # Use a different port to avoid conflicts
  db:
    image: postgres:14-alpine # Use a specific alpine version
    environment:
      - POSTGRES_PASSWORD=password
      - POSTGRES_USER=user
      - POSTGRES_DB=mydb
    volumes:
      - db_data:/var/lib/postgresql/data # Mount the named volume
networks:
  default:
    name: compose_test_network_%s
volumes:
  db_data:
    name: compose_test_volume_%s
`, testSuffix, testSuffix)

	// NOTE: uploadComposeFile helper removed as /up endpoint now expects JSON via sendComposeUpRequest

	// Test deploying a compose stack
	t.Run("DeployComposeStack", func(t *testing.T) {
		// Use sendComposeUpRequest helper from helpers_test.go
		resp, deploymentID := sendComposeUpRequest(t, ts, token, projectName, simpleCompose)
		require.NotEqual(t, http.StatusInternalServerError, resp.StatusCode, "API returned internal server error") // Basic check
		require.Equal(t, http.StatusAccepted, resp.StatusCode, "Deploy API call failed")
		require.NotEmpty(t, deploymentID, "Deployment ID should not be empty")
		// Deployment ID should match project name for compose operations
		require.Equal(t, projectName, deploymentID, "Deployment ID should match project name")
		defer resp.Body.Close()

		// Add cleanup for this deployment
		t.Cleanup(func() {
			cleanupComposeStack(t, ts.Docker, deploymentID)
		})

		// Parse response
		var deployResp struct {
			DeploymentID string `json:"deployment_id"`
			Message      string `json:"message"`
		}
		err = json.NewDecoder(resp.Body).Decode(&deployResp)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, deploymentID, deployResp.DeploymentID)
		assert.Contains(t, deployResp.Message, "Deployment process started") // Updated message check

		// Verify containers were created and are running (eventually)
		assertContainerCountAndStatus(t, ts.Docker, deploymentID, 2, "running")
	})

	// Test scaling a service - NOTE: Scaling via API might not be directly supported by backend compose logic yet
	// t.Run("ScaleService", func(t *testing.T) {
	// 	// ... (Requires backend implementation for scaling API)
	// })

	// Test stack status
	t.Run("StackStatus", func(t *testing.T) {
		// First deploy a stack
		respDeploy, deploymentID := sendComposeUpRequest(t, ts, token, projectName, simpleCompose) // Use new helper
		require.Equal(t, http.StatusAccepted, respDeploy.StatusCode)
		require.NotEmpty(t, deploymentID)
		require.Equal(t, projectName, deploymentID)
		respDeploy.Body.Close()

		t.Cleanup(func() {
			cleanupComposeStack(t, ts.Docker, deploymentID)
		})

		// Wait a bit for containers to potentially start
		assertContainerCountAndStatus(t, ts.Docker, deploymentID, 2, "running") // Verify running first

		// Create request for status
		req, err := http.NewRequest("GET", ts.HttpServer.URL+"/api/v1/compose/"+deploymentID+"/status", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		// Send request
		httpClient := &http.Client{}    // Renamed variable
		resp, err := httpClient.Do(req) // Use renamed variable
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response using anonymous struct matching expected structure
		var statusResp struct {
			DeploymentID string                          `json:"deployment_id"`
			Status       string                          `json:"status"`
			Services     []models.ComposeServiceResponse `json:"services"` // Use correct model type
		}
		err = json.NewDecoder(resp.Body).Decode(&statusResp)
		require.NoError(t, err, "Failed to decode status response")

		// Check response
		assert.Equal(t, deploymentID, statusResp.DeploymentID)
		assert.NotEmpty(t, statusResp.Status) // Status might be "running" or similar
		require.Len(t, statusResp.Services, 2, "Should have status for 2 services")

		// Check actual Docker state matches reported status (basic check)
		runningCount := 0
		for _, s := range statusResp.Services {
			assert.NotEmpty(t, s.Name)
			assert.NotEmpty(t, s.Status) // e.g., "running", "exited"
			// Correct comparison using the defined constant
			if s.Status == models.ContainerStatusRunning {
				runningCount++
			}
		}
		assert.Equal(t, 2, runningCount, "Expected 2 services to be reported as running")
	})

	// Test stopping a stack
	t.Run("StopStack", func(t *testing.T) {
		// First deploy a stack
		respDeploy, deploymentID := sendComposeUpRequest(t, ts, token, projectName, simpleCompose) // Use new helper
		require.Equal(t, http.StatusAccepted, respDeploy.StatusCode)
		require.NotEmpty(t, deploymentID)
		require.Equal(t, projectName, deploymentID)
		respDeploy.Body.Close()

		t.Cleanup(func() {
			cleanupComposeStack(t, ts.Docker, deploymentID)
		})

		// Wait for containers to be running
		assertContainerCountAndStatus(t, ts.Docker, deploymentID, 2, "running")

		// Create request to stop the stack
		req, err := http.NewRequest("POST", ts.HttpServer.URL+"/api/v1/compose/"+deploymentID+"/stop", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		// Send request
		httpClient := &http.Client{}    // Renamed variable
		resp, err := httpClient.Do(req) // Use renamed variable
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var stopResp struct {
			DeploymentID string `json:"deployment_id"`
			Message      string `json:"message"`
		}
		err = json.NewDecoder(resp.Body).Decode(&stopResp)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, deploymentID, stopResp.DeploymentID)
		assert.Contains(t, stopResp.Message, "stopped successfully") // Check specific message

		// Verify containers are stopped (or stopping)
		assertContainerCountAndStatus(t, ts.Docker, deploymentID, 2, "exited") // Check they are exited
	})

	// Test starting a stopped stack
	t.Run("StartStack", func(t *testing.T) {
		// First deploy a stack
		respDeploy, deploymentID := sendComposeUpRequest(t, ts, token, projectName, simpleCompose) // Use new helper
		require.Equal(t, http.StatusAccepted, respDeploy.StatusCode)
		require.NotEmpty(t, deploymentID)
		require.Equal(t, projectName, deploymentID)
		respDeploy.Body.Close()

		t.Cleanup(func() {
			cleanupComposeStack(t, ts.Docker, deploymentID)
		})

		// Wait for containers to be running, then stop them
		assertContainerCountAndStatus(t, ts.Docker, deploymentID, 2, "running")
		reqStop, err := http.NewRequest("POST", ts.HttpServer.URL+"/api/v1/compose/"+deploymentID+"/stop", nil)
		require.NoError(t, err)
		reqStop.Header.Set("Authorization", "Bearer "+token)
		httpClient := &http.Client{}            // Renamed variable
		respStop, err := httpClient.Do(reqStop) // Use renamed variable
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, respStop.StatusCode)
		respStop.Body.Close()
		assertContainerCountAndStatus(t, ts.Docker, deploymentID, 2, "exited") // Verify stopped

		// Now start it again
		reqStart, err := http.NewRequest("POST", ts.HttpServer.URL+"/api/v1/compose/"+deploymentID+"/start", nil)
		require.NoError(t, err)
		reqStart.Header.Set("Authorization", "Bearer "+token)

		respStart, err := httpClient.Do(reqStart) // Use renamed variable
		require.NoError(t, err)
		defer respStart.Body.Close()

		// Check status code
		require.Equal(t, http.StatusOK, respStart.StatusCode)

		// Parse response
		var startResp struct {
			DeploymentID string `json:"deployment_id"`
			Message      string `json:"message"`
		}
		err = json.NewDecoder(respStart.Body).Decode(&startResp)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, deploymentID, startResp.DeploymentID)
		assert.Contains(t, startResp.Message, "started successfully")

		// Verify containers are running again
		assertContainerCountAndStatus(t, ts.Docker, deploymentID, 2, "running")
	})

	// Test removing a stack
	t.Run("RemoveStack", func(t *testing.T) {
		// First deploy a stack
		respDeploy, deploymentID := sendComposeUpRequest(t, ts, token, projectName, simpleCompose) // Use new helper
		require.Equal(t, http.StatusAccepted, respDeploy.StatusCode)
		require.NotEmpty(t, deploymentID)
		require.Equal(t, projectName, deploymentID)
		respDeploy.Body.Close()

		// No t.Cleanup here, the test itself is the cleanup

		// Wait for containers to be running
		assertContainerCountAndStatus(t, ts.Docker, deploymentID, 2, "running")

		// Create request to remove the stack
		req, err := http.NewRequest("DELETE", ts.HttpServer.URL+"/api/v1/compose/"+deploymentID, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		// Send request
		httpClient := &http.Client{}    // Renamed variable
		resp, err := httpClient.Do(req) // Use renamed variable
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var removeResp struct {
			DeploymentID string `json:"deployment_id"`
			Message      string `json:"message"`
		}
		err = json.NewDecoder(resp.Body).Decode(&removeResp)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, deploymentID, removeResp.DeploymentID)
		assert.Contains(t, removeResp.Message, "removed successfully")

		// Verify containers are removed
		assertContainerCountAndStatus(t, ts.Docker, deploymentID, 0, "") // Expect 0 containers
	})
}
