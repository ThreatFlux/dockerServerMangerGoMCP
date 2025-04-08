package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// TestListVolumes tests the volume listing functionality
func TestListVolumes(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/volumes", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		// Parse query parameters
		query := r.URL.Query()
		filters := query.Get("filters")

		var volumeList struct {
			Volumes  []models.Volume `json:"Volumes"`
			Warnings []string        `json:"Warnings"`
		}

		// Generate volumes based on filters
		if filters != "" {
			var filtersMap map[string][]string
			err := json.Unmarshal([]byte(filters), &filtersMap)
			require.NoError(t, err)

			// Check for name filter
			if names, ok := filtersMap["name"]; ok && len(names) > 0 {
				// Return volumes matching the name filter
				for _, name := range names {
					volumeList.Volumes = append(volumeList.Volumes, models.Volume{
						DockerResource: models.DockerResource{ID: 0, Name: name, CreatedAt: time.Now()}, // Use embedded DockerResource with CreatedAt
						VolumeID:       "vol_" + name,                                                   // Use VolumeID
						Driver:         "local",
						Mountpoint:     "/var/lib/docker_test/volumes/" + name,
					})
				}
			}
		} else {
			// Return default volumes using correct fields
			volumeList.Volumes = []models.Volume{
				{
					DockerResource: models.DockerResource{ID: 1, Name: "volume1", CreatedAt: time.Now()}, // Use embedded DockerResource with CreatedAt
					VolumeID:       "vol1",                                                               // Use VolumeID
					Driver:         "local",
					Mountpoint:     "/var/lib/docker_test/volumes/volume1",
				},
				{
					DockerResource: models.DockerResource{ID: 2, Name: "volume2", CreatedAt: time.Now().Add(-24 * time.Hour)}, // Use embedded DockerResource with CreatedAt
					VolumeID:       "vol2",                                                                                    // Use VolumeID
					Driver:         "local",
					Mountpoint:     "/var/lib/docker_test/volumes/volume2",
				},
			}
		}

		// Write response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(volumeList)
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test listing all volumes
	volumes, err := client.ListVolumes(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, volumes, 2)
	assert.Equal(t, "volume1", volumes[0].DockerResource.Name) // Access Name via DockerResource
	assert.Equal(t, "volume2", volumes[1].DockerResource.Name) // Access Name via DockerResource

	// Test with name filter
	filters := map[string]string{
		"name": "filtered_volume",
	}

	volumes, err = client.ListVolumes(context.Background(), filters)
	require.NoError(t, err)
	assert.Len(t, volumes, 1)
	assert.Equal(t, "filtered_volume", volumes[0].DockerResource.Name) // Access Name via DockerResource
}

// TestGetVolume tests getting volume details
func TestGetVolume(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path matches expected pattern
		if strings.HasPrefix(r.URL.Path, "/api/v1/volumes/") && r.Method == http.MethodGet {
			// Extract volume name from URL
			parts := strings.Split(r.URL.Path, "/")
			volumeName := parts[len(parts)-1]

			if volumeName == "validvolume" {
				// Return volume details using correct fields
				volume := models.Volume{
					DockerResource: models.DockerResource{ // Use embedded DockerResource
						ID:   1,
						Name: volumeName,
						Labels: models.JSONMap{ // Use JSONMap for Labels
							"com.example.label1": "value1",
							"com.example.label2": "value2",
						},
						CreatedAt: time.Now(), // Use time.Time
					},
					VolumeID:   "vol_" + volumeName, // Use VolumeID
					Driver:     "local",
					Mountpoint: "/var/lib/docker_test/volumes/" + volumeName,
					Scope:      "local",
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(volume)
			} else {
				// Volume not found
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Volume not found"}`))
			}
		} else {
			// Invalid path
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test getting a valid volume
	volume, err := client.GetVolume(context.Background(), "validvolume")
	require.NoError(t, err)
	assert.Equal(t, "validvolume", volume.DockerResource.Name) // Access Name via DockerResource
	assert.Equal(t, "local", volume.Driver)
	assert.Equal(t, "/var/lib/docker_test/volumes/validvolume", volume.Mountpoint)
	assert.Equal(t, "local", volume.Scope)
	assert.NotNil(t, volume.DockerResource.Labels)                                // Access Labels via DockerResource
	assert.Equal(t, "value1", volume.DockerResource.Labels["com.example.label1"]) // Access Labels via DockerResource

	// Test getting a non-existent volume
	_, err = client.GetVolume(context.Background(), "nonexistentvolume")
	assert.Error(t, err)

	// Test with empty volume name
	_, err = client.GetVolume(context.Background(), "")
	assert.Error(t, err)
}

// TestCreateVolume tests volume creation
func TestCreateVolume(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/volumes", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Parse request body
		var createReq models.VolumeCreateRequest
		err := json.NewDecoder(r.Body).Decode(&createReq)
		require.NoError(t, err)

		// Check required fields
		if createReq.Name == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Volume name cannot be empty"}`))
			return
		}

		// Check for duplicate volume name
		if createReq.Name == "duplicate" {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"error": "Volume already exists"}`))
			return
		}

		// Return created volume using correct fields
		labelsMap := make(models.JSONMap)
		for k, v := range createReq.Labels {
			labelsMap[k] = v
		}
		volume := models.Volume{
			DockerResource: models.DockerResource{ID: 0, Name: createReq.Name, Labels: labelsMap, CreatedAt: time.Now()}, // Use embedded DockerResource with CreatedAt
			VolumeID:       "vol_" + createReq.Name,                                                                      // Use VolumeID
			Driver:         createReq.Driver,
			Mountpoint:     "/var/lib/docker_test/volumes/" + createReq.Name,
		}

		if volume.Driver == "" {
			volume.Driver = "local"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(volume)
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test creating a volume with minimal options
	createReq := &models.VolumeCreateRequest{
		Name: "test_volume",
	}

	volume, err := client.CreateVolume(context.Background(), createReq) // Pass VolumeCreateRequest
	require.NoError(t, err)
	assert.Equal(t, "test_volume", volume.DockerResource.Name) // Access Name via DockerResource
	assert.Equal(t, "local", volume.Driver)
	assert.Equal(t, "/var/lib/docker_test/volumes/test_volume", volume.Mountpoint)

	// Test creating a volume with more options
	createReq = &models.VolumeCreateRequest{
		Name:   "custom_volume",
		Driver: "custom_driver",
		Labels: map[string]string{
			"com.example.label": "value",
		},
		DriverOpts: map[string]string{
			"size": "10G",
		},
	}
	volume, err = client.CreateVolume(context.Background(), createReq) // Pass VolumeCreateRequest
	require.NoError(t, err)
	assert.Equal(t, "custom_volume", volume.DockerResource.Name) // Access Name via DockerResource
	assert.Equal(t, "custom_driver", volume.Driver)
	assert.Equal(t, "/var/lib/docker_test/volumes/custom_volume", volume.Mountpoint)
	assert.Equal(t, "value", volume.DockerResource.Labels["com.example.label"]) // Access Labels via DockerResource

	// Test creating a duplicate volume
	createReq = &models.VolumeCreateRequest{
		Name: "duplicate",
	}

	_, err = client.CreateVolume(context.Background(), createReq) // Pass VolumeCreateRequest
	assert.Error(t, err)

	// Test with empty name
	createReq = &models.VolumeCreateRequest{
		Name: "",
	}

	_, err = client.CreateVolume(context.Background(), createReq) // Pass VolumeCreateRequest
	assert.Error(t, err)
}

// TestRemoveVolume tests volume removal
func TestRemoveVolume(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path matches expected pattern
		if strings.HasPrefix(r.URL.Path, "/api/v1/volumes/") && r.Method == http.MethodDelete {
			// Extract volume name from URL
			parts := strings.Split(r.URL.Path, "/")
			volumeName := parts[len(parts)-1]

			// Parse query parameters
			force := r.URL.Query().Get("force") == "true"

			if volumeName == "nonexistent" {
				// Volume not found
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Volume not found"}`))
			} else if volumeName == "inuse" && !force {
				// Volume in use and not forced
				w.WriteHeader(http.StatusConflict)
				w.Write([]byte(`{"error": "Volume is in use"}`))
			} else {
				// Success response
				w.WriteHeader(http.StatusNoContent)
			}
		} else {
			// Invalid path
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test removing a valid volume
	err = client.RemoveVolume(context.Background(), "validvolume", false)
	require.NoError(t, err)

	// Test removing a volume with force
	err = client.RemoveVolume(context.Background(), "inuse", true)
	require.NoError(t, err)

	// Test removing a volume in use without force
	err = client.RemoveVolume(context.Background(), "inuse", false)
	assert.Error(t, err)

	// Test removing a non-existent volume
	err = client.RemoveVolume(context.Background(), "nonexistent", false)
	assert.Error(t, err)

	// Test with empty volume name
	err = client.RemoveVolume(context.Background(), "", false)
	assert.Error(t, err)
}

// TestPruneVolumes tests volume pruning
func TestPruneVolumes(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/volumes/prune", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Parse query parameters
		query := r.URL.Query()
		filters := query.Get("filters")

		// Response
		pruneResponse := struct {
			VolumesDeleted []string `json:"VolumesDeleted"`
			SpaceReclaimed uint64   `json:"SpaceReclaimed"`
		}{
			VolumesDeleted: []string{"volume1", "volume2"},
			SpaceReclaimed: 1024 * 1024 * 100, // 100MB
		}

		// If filters provided, adjust response
		if filters != "" {
			var filtersMap map[string][]string
			err := json.Unmarshal([]byte(filters), &filtersMap)
			require.NoError(t, err)

			if labels, ok := filtersMap["label"]; ok && len(labels) > 0 {
				// Filtered pruning
				pruneResponse.VolumesDeleted = []string{"volume1"}
				pruneResponse.SpaceReclaimed = 1024 * 1024 * 50 // 50MB
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pruneResponse)
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test pruning all volumes
	spaceReclaimed, err := client.PruneVolumes(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, uint64(1024*1024*100), spaceReclaimed)

	// Test pruning with filters
	filters := map[string]string{
		"label": "test=true",
	}

	spaceReclaimed, err = client.PruneVolumes(context.Background(), filters)
	require.NoError(t, err)
	assert.Equal(t, uint64(1024*1024*50), spaceReclaimed)
}

// TestCloneVolume tests cloning a volume
func TestCloneVolume(t *testing.T) {
	// Create test mux to handle different paths
	mux := http.NewServeMux()

	// GET /volumes/source - Get source volume
	mux.HandleFunc("/api/v1/volumes/source", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Use correct fields for Volume literal
		labelsMap := make(models.JSONMap)
		for k, v := range map[string]string{"com.example.source": "true"} {
			labelsMap[k] = v
		}
		optionsMap := make(models.JSONMap)
		for k, v := range map[string]string{"size": "1G"} {
			optionsMap[k] = v
		}
		volume := models.Volume{
			DockerResource: models.DockerResource{ID: 1, Name: "source", Labels: labelsMap, CreatedAt: time.Now().Add(-24 * time.Hour)}, // Use embedded DockerResource with CreatedAt
			VolumeID:       "vol_source",                                                                                                // Use VolumeID
			Driver:         "local",
			Mountpoint:     "/var/lib/docker_test/volumes/source",
			Options:        optionsMap, // Use JSONMap
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(volume)
	})

	// GET /volumes/nonexistent - 404 Not Found
	mux.HandleFunc("/api/v1/volumes/nonexistent", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Volume not found"}`))
	})

	// POST /volumes - Create volume
	mux.HandleFunc("/api/v1/volumes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var createReq models.VolumeCreateRequest
		err := json.NewDecoder(r.Body).Decode(&createReq)
		require.NoError(t, err)

		// Check required fields
		if createReq.Name == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Volume name cannot be empty"}`))
			return
		}

		// Create and return volume using correct fields
		labelsMap := make(models.JSONMap)
		for k, v := range createReq.Labels {
			labelsMap[k] = v
		}
		optionsMap := make(models.JSONMap)
		for k, v := range createReq.DriverOpts {
			optionsMap[k] = v
		}
		volume := models.Volume{
			DockerResource: models.DockerResource{ID: 0, Name: createReq.Name, Labels: labelsMap, CreatedAt: time.Now()}, // Use embedded DockerResource with CreatedAt
			VolumeID:       "vol_" + createReq.Name,                                                                      // Use VolumeID
			Driver:         createReq.Driver,
			Mountpoint:     "/var/lib/docker_test/volumes/" + createReq.Name,
			Options:        optionsMap, // Use JSONMap
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(volume)
	})

	// Create test server with mux
	server := httptest.NewServer(mux)
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test cloning a volume
	clonedVolume, err := client.CloneVolume(context.Background(), "source", "target", nil)
	require.NoError(t, err)
	assert.Equal(t, "target", clonedVolume.DockerResource.Name) // Access Name via DockerResource
	assert.Equal(t, "local", clonedVolume.Driver)
	assert.Equal(t, "/var/lib/docker_test/volumes/target", clonedVolume.Mountpoint)
	assert.Equal(t, "true", clonedVolume.DockerResource.Labels["com.example.source"])                  // Access Labels via DockerResource
	assert.Equal(t, "source", clonedVolume.DockerResource.Labels["com.docker_test.volume.clone-from"]) // Access Labels via DockerResource
	assert.Equal(t, "1G", clonedVolume.Options["size"])

	// Test cloning a volume with additional labels
	labels := map[string]string{
		"com.example.target": "true",
	}
	clonedVolume, err = client.CloneVolume(context.Background(), "source", "target-with-labels", labels)
	require.NoError(t, err)
	assert.Equal(t, "target-with-labels", clonedVolume.DockerResource.Name)                            // Access Name via DockerResource
	assert.Equal(t, "true", clonedVolume.DockerResource.Labels["com.example.source"])                  // Access Labels via DockerResource
	assert.Equal(t, "true", clonedVolume.DockerResource.Labels["com.example.target"])                  // Access Labels via DockerResource
	assert.Equal(t, "source", clonedVolume.DockerResource.Labels["com.docker_test.volume.clone-from"]) // Access Labels via DockerResource

	// Test cloning a non-existent volume
	_, err = client.CloneVolume(context.Background(), "nonexistent", "target", nil)
	assert.Error(t, err)

	// Test with empty source name
	_, err = client.CloneVolume(context.Background(), "", "target", nil)
	assert.Error(t, err)

	// Test with empty target name
	_, err = client.CloneVolume(context.Background(), "source", "", nil)
	assert.Error(t, err)
}
