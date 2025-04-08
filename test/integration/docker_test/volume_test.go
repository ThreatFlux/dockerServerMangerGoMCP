package docker_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/docker" // Remove unused import
	"github.com/threatflux/dockerServerMangerGoMCP/test/integration" // Import integration helpers
	// "github.com/threatflux/dockerServerMangerGoMCP/internal/docker_test/volume/manager" // Unused
	dockertypesvolume "github.com/docker/docker/api/types/volume" // Import docker_test volume types
)

// TestVolumeOperations tests volume-related endpoints
func TestVolumeOperations(t *testing.T) {
	// Set up test server
	ts, httpServer, err := setupTestServer(t)
	require.NoError(t, err)
	defer httpServer.Close()
	defer ts.DB.Close()

	// Create test user and get token
	token, _ := createTestUser(t, ts)

	// Get mock Docker client
	mockDocker, ok := ts.Docker.(*integration.MockDockerManager) // Rename var back, assert correct type
	require.True(t, ok, "Docker client is not a MockClient")

	// Add some mock volumes
	mockDocker.AddMockVolume(&integration.MockVolume{ // Use integration.MockVolume
		Name:       "test-volume-1",
		Driver:     "local",
		Mountpoint: "/var/lib/docker_test/volumes/test-volume-1/_data",
		CreatedAt:  "2024-01-01T00:00:00Z",
		Labels: map[string]string{
			"com.example.description": "Test volume 1",
		},
	})

	mockDocker.AddMockVolume(&integration.MockVolume{ // Use integration.MockVolume
		Name:       "test-volume-2",
		Driver:     "local",
		Mountpoint: "/var/lib/docker_test/volumes/test-volume-2/_data",
		CreatedAt:  "2024-01-02T00:00:00Z",
		Labels: map[string]string{
			"com.example.description": "Test volume 2",
		},
	})

	// Test listing volumes
	t.Run("ListVolumes", func(t *testing.T) {
		// Send request to list volumes
		resp := authRequest(t, httpServer.URL, "GET", "/api/volumes", nil, token)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var listResp struct {
			Volumes []map[string]interface{} `json:"volumes"`
			Total   int                      `json:"total"`
		}
		err := json.NewDecoder(resp.Body).Decode(&listResp)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, 2, listResp.Total)
		assert.Len(t, listResp.Volumes, 2)

		// Check volume details
		foundVolume1 := false
		foundVolume2 := false

		for _, volume := range listResp.Volumes {
			name, _ := volume["name"].(string)

			if name == "test-volume-1" {
				foundVolume1 = true
				driver, _ := volume["driver"].(string)
				assert.Equal(t, "local", driver)

				labels, ok := volume["labels"].(map[string]interface{})
				require.True(t, ok, "Labels not found in response")
				assert.Equal(t, "Test volume 1", labels["com.example.description"])
			} else if name == "test-volume-2" {
				foundVolume2 = true
				driver, _ := volume["driver"].(string)
				assert.Equal(t, "local", driver)

				labels, ok := volume["labels"].(map[string]interface{})
				require.True(t, ok, "Labels not found in response")
				assert.Equal(t, "Test volume 2", labels["com.example.description"])
			}
		}

		assert.True(t, foundVolume1, "Volume 1 not found")
		assert.True(t, foundVolume2, "Volume 2 not found")
	})

	// Test getting volume details
	t.Run("GetVolume", func(t *testing.T) {
		// Send request to get volume
		resp := authRequest(t, httpServer.URL, "GET", "/api/volumes/test-volume-1", nil, token)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var volume map[string]interface{}
		err := json.NewDecoder(resp.Body).Decode(&volume)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, "test-volume-1", volume["name"])
		assert.Equal(t, "local", volume["driver"])
		assert.Equal(t, "/var/lib/docker_test/volumes/test-volume-1/_data", volume["mountpoint"])

		// Check labels
		labels, ok := volume["labels"].(map[string]interface{})
		require.True(t, ok, "Labels not found in response")
		assert.Equal(t, "Test volume 1", labels["com.example.description"])
	})

	// Test creating a volume
	t.Run("CreateVolume", func(t *testing.T) {
		// Create volume request
		createReq := dockertypesvolume.CreateOptions{ // Keep using Docker SDK type
			Name:   "new-test-volume",
			Driver: "local",
			DriverOpts: map[string]string{
				"type":   "tmpfs",
				"device": "tmpfs",
			},
			Labels: map[string]string{
				"com.example.description": "New test volume",
				"com.example.environment": "test",
			},
		}

		// Send request to create volume
		resp := authRequest(t, httpServer.URL, "POST", "/api/volumes", createReq, token)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		// Parse response
		var createResp struct {
			Name   string            `json:"name"`
			Driver string            `json:"driver"`
			Labels map[string]string `json:"labels"`
		}
		err := json.NewDecoder(resp.Body).Decode(&createResp)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, "new-test-volume", createResp.Name)
		assert.Equal(t, "local", createResp.Driver)
		assert.Equal(t, "New test volume", createResp.Labels["com.example.description"])
		assert.Equal(t, "test", createResp.Labels["com.example.environment"])

		// Verify volume was created in mock client
		volume, err := mockDocker.GetVolume("new-test-volume")
		require.NoError(t, err)
		assert.Equal(t, "new-test-volume", volume.Name)
		assert.Equal(t, "local", volume.Driver)
		assert.Equal(t, "New test volume", volume.Labels["com.example.description"])
	})

	// Test removing a volume
	t.Run("RemoveVolume", func(t *testing.T) {
		// Add volume to remove
		mockDocker.AddMockVolume(&integration.MockVolume{ // Use integration.MockVolume
			Name:       "volume-to-remove",
			Driver:     "local",
			Mountpoint: "/var/lib/docker_test/volumes/volume-to-remove/_data",
			CreatedAt:  "2024-01-03T00:00:00Z",
		})

		// Send request to remove volume
		resp := authRequest(t, httpServer.URL, "DELETE", "/api/volumes/volume-to-remove", nil, token)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		// Verify volume was removed from mock client
		_, err := mockDocker.GetVolume("volume-to-remove")
		assert.Error(t, err, "Volume should be removed")
	})

	// Test pruning unused volumes
	t.Run("PruneVolumes", func(t *testing.T) {
		// Add volumes to prune
		mockDocker.AddMockVolume(&integration.MockVolume{ // Use integration.MockVolume
			Name:       "unused-volume-1",
			Driver:     "local",
			Mountpoint: "/var/lib/docker_test/volumes/unused-volume-1/_data",
			CreatedAt:  "2024-01-04T00:00:00Z",
			InUse:      false,
		})

		mockDocker.AddMockVolume(&integration.MockVolume{ // Use integration.MockVolume
			Name:       "unused-volume-2",
			Driver:     "local",
			Mountpoint: "/var/lib/docker_test/volumes/unused-volume-2/_data",
			CreatedAt:  "2024-01-04T00:00:00Z",
			InUse:      false,
		})

		// Add a volume that's in use (shouldn't be pruned)
		mockDocker.AddMockVolume(&integration.MockVolume{ // Use integration.MockVolume
			Name:       "used-volume",
			Driver:     "local",
			Mountpoint: "/var/lib/docker_test/volumes/used-volume/_data",
			CreatedAt:  "2024-01-04T00:00:00Z",
			InUse:      true,
		})

		// Create prune request
		pruneReq := struct{}{} // Empty request body

		// Send request to prune volumes
		resp := authRequest(t, httpServer.URL, "POST", "/api/volumes/prune", pruneReq, token)
		defer resp.Body.Close()

		// Check status code
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Parse response
		var pruneResp struct {
			VolumesDeleted []string `json:"volumesDeleted"`
			SpaceReclaimed int64    `json:"spaceReclaimed"`
		}
		err := json.NewDecoder(resp.Body).Decode(&pruneResp)
		require.NoError(t, err)

		// Check response
		assert.Len(t, pruneResp.VolumesDeleted, 2)
		assert.Contains(t, pruneResp.VolumesDeleted, "unused-volume-1")
		assert.Contains(t, pruneResp.VolumesDeleted, "unused-volume-2")
		assert.Greater(t, pruneResp.SpaceReclaimed, int64(0))

		// Verify unused volumes were removed from mock client
		_, err = mockDocker.GetVolume("unused-volume-1")
		assert.Error(t, err, "Unused volume 1 should be removed")

		_, err = mockDocker.GetVolume("unused-volume-2")
		assert.Error(t, err, "Unused volume 2 should be removed")

		// Verify used volume still exists
		usedVolume, err := mockDocker.GetVolume("used-volume")
		require.NoError(t, err)
		assert.Equal(t, "used-volume", usedVolume.Name)
	})
}

// TestVolumeSecurity tests security aspects of volume management
func TestVolumeSecurity(t *testing.T) {
	// Set up test server
	ts, httpServer, err := setupTestServer(t)
	require.NoError(t, err)
	defer httpServer.Close()
	defer ts.DB.Close()

	// Create test user and get token
	token, _ := createTestUser(t, ts)

	// Test unauthorized access
	t.Run("UnauthorizedAccess", func(t *testing.T) {
		// Send request without token
		resp := authRequest(t, httpServer.URL, "GET", "/api/volumes", nil, "")
		defer resp.Body.Close()

		// Check status code (should be 401 Unauthorized)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// Test creating a volume with invalid options
	t.Run("InvalidDriverOptions", func(t *testing.T) {
		// Create volume request with invalid driver options
		createReq := dockertypesvolume.CreateOptions{ // Keep using Docker SDK type
			Name:   "invalid-options-volume",
			Driver: "local",
			DriverOpts: map[string]string{
				"size": "invalid-size", // Invalid size format
			},
		}

		// Send request to create volume
		resp := authRequest(t, httpServer.URL, "POST", "/api/volumes", createReq, token)
		defer resp.Body.Close()

		// Check status code (should be 400 Bad Request)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// Parse error response
		var errorResp struct {
			Error string `json:"error"`
		}
		err := json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)

		// Check error message
		assert.Contains(t, errorResp.Error, "driver options")
	})

	// Test creating a volume with invalid driver
	t.Run("InvalidDriver", func(t *testing.T) {
		// Create volume request with invalid driver
		createReq := dockertypesvolume.CreateOptions{ // Keep using Docker SDK type
			Name:   "invalid-driver-volume",
			Driver: "nonexistent-driver",
		}

		// Send request to create volume
		resp := authRequest(t, httpServer.URL, "POST", "/api/volumes", createReq, token)
		defer resp.Body.Close()

		// Check status code (should be 400 Bad Request)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// Parse error response
		var errorResp struct {
			Error string `json:"error"`
		}
		err := json.NewDecoder(resp.Body).Decode(&errorResp)
		require.NoError(t, err)

		// Check error message
		assert.Contains(t, errorResp.Error, "driver")
	})
}
