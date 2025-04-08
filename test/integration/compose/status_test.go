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

// TestComposeStatusTracking tests the Docker Compose status tracking functionality
func TestComposeStatusTracking(t *testing.T) {
	// Set up test server
	ts, err := setupTestServer(t) // Uses setup from parser_test.go
	require.NoError(t, err)
	defer ts.cleanup()

	// Create test user and get token
	token := createTestUser(t, ts)

	// Simple compose file for testing status tracking
	testSuffix := fmt.Sprintf("statustest%d", time.Now().UnixNano())
	projectName := fmt.Sprintf("compose-status-%s", testSuffix) // Use different project name prefix
	testCompose := fmt.Sprintf(`
version: '3.8'
services:
  web:
    image: nginx:alpine
    depends_on:
      - db
    ports:
      - "8082:80" # Use different port
  db:
    image: postgres:14-alpine
    environment:
      - POSTGRES_PASSWORD=password
      - POSTGRES_USER=user
      - POSTGRES_DB=mydb
    volumes:
      - db_data:/var/lib/postgresql/data
  redis:
    image: redis:alpine
networks:
  default:
    name: compose_status_test_network_%s
volumes:
  db_data:
    name: compose_status_test_volume_%s
`, testSuffix, testSuffix)

	// NOTE: uploadComposeFile helper removed as /up endpoint now expects JSON via sendComposeUpRequest

	// Test status tracking during deployment
	t.Run("StatusTracking", func(t *testing.T) {
		// Upload and deploy compose file using the correct endpoint and helper
		resp, deploymentID := sendComposeUpRequest(t, ts, token, projectName, testCompose) // Use sendComposeUpRequest
		require.Equal(t, http.StatusAccepted, resp.StatusCode, "Deploy API call failed")
		require.NotEmpty(t, deploymentID, "Deployment ID should not be empty")
		require.Equal(t, projectName, deploymentID) // Check project name match
		defer resp.Body.Close()

		t.Cleanup(func() {
			cleanupComposeStack(t, ts.Docker, deploymentID)
		})

		// Wait briefly for deployment to progress
		assertContainerCountAndStatus(t, ts.Docker, deploymentID, 3, "running") // Check containers are up

		// Create request for status
		req, err := http.NewRequest("GET", ts.HttpServer.URL+"/api/v1/compose/"+deploymentID+"/status", nil) // Use /api/v1 base
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		// Send request
		httpClient := &http.Client{} // Renamed to avoid conflict
		respStatus, err := httpClient.Do(req)
		require.NoError(t, err)
		defer respStatus.Body.Close()

		// Check status code
		require.Equal(t, http.StatusOK, respStatus.StatusCode)

		// Parse response (using correct model type for services)
		var statusResp struct {
			DeploymentID string                          `json:"deployment_id"`
			Status       string                          `json:"status"`
			Services     []models.ComposeServiceResponse `json:"services"`   // Correct type
			StartTime    time.Time                       `json:"start_time"` // Expect time.Time
			ElapsedTime  string                          `json:"elapsed_time"`
		}
		err = json.NewDecoder(respStatus.Body).Decode(&statusResp)
		require.NoError(t, err, "Failed to decode status response")

		// Check response
		assert.Equal(t, deploymentID, statusResp.DeploymentID)
		assert.NotEmpty(t, statusResp.Status) // e.g., "running"
		require.Len(t, statusResp.Services, 3, "Should have status for 3 services")
		assert.False(t, statusResp.StartTime.IsZero(), "Start time should not be zero")
		assert.NotEmpty(t, statusResp.ElapsedTime)

		// Check service details
		foundWeb := false
		foundDb := false
		foundRedis := false
		runningCount := 0

		for _, service := range statusResp.Services {
			assert.NotEmpty(t, service.Name)
			assert.NotEmpty(t, service.Status)
			if service.Status == models.ContainerStatusRunning { // Correct comparison
				runningCount++
			}
			switch service.Name {
			case "web":
				foundWeb = true
			case "db":
				foundDb = true
			case "redis":
				foundRedis = true
			}
		}

		assert.True(t, foundWeb, "Web service not found in status")
		assert.True(t, foundDb, "DB service not found in status")
		assert.True(t, foundRedis, "Redis service not found in status")
		assert.Equal(t, 3, runningCount, "Expected 3 services to be running")
	})

	// Test detailed service status
	t.Run("DetailedServiceStatus", func(t *testing.T) {
		// Upload and deploy compose file using the correct endpoint and helper
		respDeploy, deploymentID := sendComposeUpRequest(t, ts, token, projectName, testCompose) // Use sendComposeUpRequest
		require.Equal(t, http.StatusAccepted, respDeploy.StatusCode)
		require.NotEmpty(t, deploymentID)
		require.Equal(t, projectName, deploymentID)
		respDeploy.Body.Close()

		t.Cleanup(func() {
			cleanupComposeStack(t, ts.Docker, deploymentID)
		})

		// Wait for deployment
		assertContainerCountAndStatus(t, ts.Docker, deploymentID, 3, "running")

		// Create request for detailed service status
		req, err := http.NewRequest("GET", ts.HttpServer.URL+"/api/v1/compose/"+deploymentID+"/services/web", nil) // Use /api/v1 base
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		// Send request
		httpClient := &http.Client{} // Renamed to avoid conflict
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response using the correct model type
		var serviceResp models.ComposeServiceResponse
		err = json.NewDecoder(resp.Body).Decode(&serviceResp)
		require.NoError(t, err, "Failed to decode service status response")

		// Check response fields that exist on ComposeServiceResponse
		assert.Equal(t, "web", serviceResp.Name)
		assert.Equal(t, models.ContainerStatusRunning, serviceResp.Status) // Check specific status
		// Corrected field name: ContainerID (singular) and check if not empty
		assert.NotEmpty(t, serviceResp.ContainerID, "Should have a container ID")
		// Cannot assert length of ContainerID as it's a single string
		// Cannot assert Image, DependsOn, Ports as they are not in ComposeServiceResponse
	})

	// Test status events
	t.Run("StatusEvents", func(t *testing.T) {
		// Upload and deploy compose file using the correct endpoint and helper
		respDeploy, deploymentID := sendComposeUpRequest(t, ts, token, projectName, testCompose) // Use sendComposeUpRequest
		require.Equal(t, http.StatusAccepted, respDeploy.StatusCode)
		require.NotEmpty(t, deploymentID)
		require.Equal(t, projectName, deploymentID)
		respDeploy.Body.Close()

		t.Cleanup(func() {
			cleanupComposeStack(t, ts.Docker, deploymentID)
		})

		// Wait for deployment to likely finish
		assertContainerCountAndStatus(t, ts.Docker, deploymentID, 3, "running")
		time.Sleep(1 * time.Second) // Extra buffer

		// Create request for status events
		req, err := http.NewRequest("GET", ts.HttpServer.URL+"/api/v1/compose/"+deploymentID+"/events", nil) // Use /api/v1 base
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		// Send request
		httpClient := &http.Client{} // Renamed to avoid conflict
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check status code
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response using correct model type
		var eventsResp struct {
			DeploymentID string                    `json:"deployment_id"`
			Updates      []models.DeploymentUpdate `json:"updates"` // Correct type
		}
		err = json.NewDecoder(resp.Body).Decode(&eventsResp)
		require.NoError(t, err, "Failed to decode events response")

		// Check response
		assert.Equal(t, deploymentID, eventsResp.DeploymentID)
		require.NotEmpty(t, eventsResp.Updates, "Should have received deployment updates/events")

		// Check event details (basic checks)
		hasStarted := false
		hasCompletedOrRunning := false // Renamed for clarity
		for _, update := range eventsResp.Updates {
			assert.False(t, update.Timestamp.IsZero())
			assert.NotEmpty(t, update.Status) // Status is interface{}, check underlying type if needed
			// Cannot assert Message as it doesn't exist on DeploymentUpdate
			// Check status against known DeploymentStatus constants
			if statusStr, ok := update.Status.(string); ok {
				status := models.DeploymentStatus(statusStr)
				if status == models.DeploymentStatusRunning { // Check for Running status
					hasCompletedOrRunning = true
				}
				if status == models.DeploymentStatusDeploying {
					hasStarted = true
				}
			} else {
				t.Logf("Warning: DeploymentUpdate status was not a string: %T", update.Status)
			}
		}
		assert.True(t, hasStarted, "Should have seen a 'deploying' status event")
		assert.True(t, hasCompletedOrRunning, "Should have seen a 'running' status event")
	})
}
