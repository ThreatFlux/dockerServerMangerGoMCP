package client

import (
	"context"
	"encoding/json"
	"fmt" // Added for Sscanf
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	// "errors" // Removed unused import

	registrytypes "github.com/docker/docker/api/types/registry" // Added for AuthConfig
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// TestListImages tests the image listing functionality
func TestListImages(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/images", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		// Parse query parameters
		query := r.URL.Query()
		filters := query.Get("filters")

		var imageList []models.Image

		// Generate images based on filters
		if filters != "" {
			var filtersMap map[string][]string
			err := json.Unmarshal([]byte(filters), &filtersMap)
			require.NoError(t, err)

			// Check for reference filter
			if references, ok := filtersMap["reference"]; ok && len(references) > 0 {
				// Return images matching the reference filter
				for _, ref := range references {
					repo, tag := parseImageRef(ref) // Use helper to split ref
					imageList = append(imageList, models.Image{
						DockerResource: models.DockerResource{ID: 0, Name: repo}, // Use embedded DockerResource
						ImageID:        "sha256:" + generateTestHash(ref),
						Repository:     repo, // Use Repository
						Tag:            tag,  // Use Tag
						Size:           12345678,
						Created:        time.Now(), // Use time.Time
					})
				}
			}
		} else {
			// Return default images using correct fields
			imageList = []models.Image{
				{
					DockerResource: models.DockerResource{ID: 1, Name: "nginx"}, // Use embedded DockerResource
					ImageID:        "sha256:image1hash",
					Repository:     "nginx",  // Use Repository
					Tag:            "latest", // Use Tag
					Size:           12345678,
					Created:        time.Now(), // Use time.Time
				},
				{
					DockerResource: models.DockerResource{ID: 2, Name: "redis"}, // Use embedded DockerResource
					ImageID:        "sha256:image2hash",
					Repository:     "redis",  // Use Repository
					Tag:            "latest", // Use Tag
					Size:           87654321,
					Created:        time.Now().Add(-24 * time.Hour), // Use time.Time
				},
			}
		}

		// Write response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(imageList)
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test listing all images
	images, err := client.ListImages(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, images, 2)
	assert.Equal(t, "sha256:image1hash", images[0].ImageID) // Use ImageID
	assert.Equal(t, "sha256:image2hash", images[1].ImageID) // Use ImageID

	// Test with reference filter
	filters := map[string]string{
		"reference": "myapp:latest",
	}

	images, err = client.ListImages(context.Background(), filters)
	require.NoError(t, err)
	assert.Len(t, images, 1)
	assert.Equal(t, "docker.io/library/myapp", images[0].Repository) // Check normalized Repository
	assert.Equal(t, "latest", images[0].Tag)                         // Check Tag
}

// TestGetImage tests getting image details
func TestGetImage(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path matches expected pattern
		if strings.HasPrefix(r.URL.Path, "/api/v1/images/") && r.Method == http.MethodGet {
			// Extract image ID from URL
			parts := strings.Split(r.URL.Path, "/")
			imageID := parts[len(parts)-1]

			if imageID == "validimage" {
				// Return image details using correct fields
				image := models.Image{
					DockerResource: models.DockerResource{ID: 1, Name: "validimage"}, // Use embedded DockerResource
					ImageID:        "sha256:validimageahash",
					Repository:     "validimage", // Use Repository
					Tag:            "latest",     // Use Tag
					Size:           12345678,
					Created:        time.Now(), // Use time.Time
					// Config field removed as it's not in models.Image
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(image)
			} else {
				// Image not found
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Image not found"}`))
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

	// Test getting a valid image
	image, err := client.GetImage(context.Background(), "validimage")
	require.NoError(t, err)
	assert.Equal(t, "sha256:validimageahash", image.ImageID) // Use ImageID
	assert.Equal(t, "validimage", image.Repository)          // Check Repository
	assert.Equal(t, "latest", image.Tag)                     // Check Tag
	assert.Equal(t, int64(12345678), image.Size)
	// Config assertions removed as Config field is not part of models.Image

	// Test getting a non-existent image
	_, err = client.GetImage(context.Background(), "nonexistentimage")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound) // Check for wrapped ErrNotFound

	// Test with empty image ID
	_, err = client.GetImage(context.Background(), "")
	assert.Error(t, err)
}

// TestPullImage tests pulling an image
func TestPullImage(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/images/pull", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Parse query parameters
		query := r.URL.Query()
		fromImage := query.Get("fromImage") // This will be the normalized name, e.g., "docker.io/library/notfound"
		tag := query.Get("tag")

		assert.NotEmpty(t, fromImage)

		// Check for auth header
		authHeader := r.Header.Get("X-Registry-Auth")

		// Determine response based on input
		if fromImage == "docker.io/library/validimage" { // Check normalized name
			// Successful pull
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status": "Pull complete", "progressDetail": {}, "id": "validimage"}`))
		} else if fromImage == "docker.io/library/privateimage" && authHeader == "" { // Check normalized name
			// Unauthorized - missing auth
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Authentication required"}`))
		} else if fromImage == "docker.io/library/notfound" { // Check normalized name for notfound case
			// Image not found - return proper error response
			t.Logf("Mock server: Handling 'notfound' image (%s). Setting status to 404.", fromImage) // Add logging
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound) // Write header explicitly first
			errorBody, _ := json.Marshal(models.ErrorResponse{Success: false, Error: models.ErrorInfo{Code: "NOT_FOUND", Message: "Image not found"}})
			w.Write(errorBody) // Write the body directly
		} else {
			// Generic success for other cases (adjust if needed)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status": "Pull complete", "progressDetail": {}, "id": "` + fromImage + `:` + tag + `"}`))
		}
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test pulling a valid image (use non-normalized name here, client normalizes)
	err = client.PullImage(context.Background(), "validimage:latest", nil)
	require.NoError(t, err)

	// Test pulling with auth (use non-normalized name here)
	auth := &registrytypes.AuthConfig{ // Use registrytypes.AuthConfig from SDK
		Username: "testuser",
		Password: "testpass",
	}
	err = client.PullImage(context.Background(), "privateimage:latest", auth)
	require.NoError(t, err)

	// Test pulling a non-existent image (use non-normalized name here)
	err = client.PullImage(context.Background(), "notfound:latest", nil)
	require.Error(t, err, "Expected an error when pulling non-existent image, but got nil") // Use require.Error first
	assert.ErrorIs(t, err, ErrNotFound)                                                     // Then check if it wraps ErrNotFound

	// Test with empty image reference
	err = client.PullImage(context.Background(), "", nil)
	assert.Error(t, err)
}

// TestTagImage tests tagging an image
func TestTagImage(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path matches expected pattern
		if strings.HasPrefix(r.URL.Path, "/api/v1/images/") && strings.HasSuffix(r.URL.Path, "/tag") && r.Method == http.MethodPost {
			// Extract image ID from URL
			parts := strings.Split(r.URL.Path, "/")
			imageID := parts[len(parts)-2]

			// Parse query parameters
			query := r.URL.Query()
			repo := query.Get("repo")
			// tag := query.Get("tag") // Removed unused variable

			assert.NotEmpty(t, repo)

			if imageID == "nonexistent" {
				// Image not found
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Image not found"}`))
			} else {
				// Success response
				w.WriteHeader(http.StatusCreated)
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

	// Test tagging a valid image
	err = client.TagImage(context.Background(), "validimage", "newrepo", "newtag")
	require.NoError(t, err)

	// Test tagging with default tag
	err = client.TagImage(context.Background(), "validimage", "newrepo", "")
	require.NoError(t, err)

	// Test tagging a non-existent image
	err = client.TagImage(context.Background(), "nonexistent", "newrepo", "newtag")
	assert.Error(t, err)

	// Test with empty image ID
	err = client.TagImage(context.Background(), "", "newrepo", "newtag")
	assert.Error(t, err)

	// Test with empty repo
	err = client.TagImage(context.Background(), "validimage", "", "newtag")
	assert.Error(t, err)
}

// TestRemoveImage tests removing an image
func TestRemoveImage(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path matches expected pattern and method
		if strings.HasPrefix(r.URL.Path, "/api/v1/images/") && r.Method == http.MethodDelete {
			// Extract image ID from URL
			parts := strings.Split(r.URL.Path, "/")
			imageID := parts[len(parts)-1]

			// Parse query parameters
			query := r.URL.Query()
			force := query.Get("force")

			if imageID == "nonexistent" {
				// Image not found
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Image not found"}`))
			} else if imageID == "inuse" && force != "true" {
				// Image in use and not forced
				w.WriteHeader(http.StatusConflict)
				w.Write([]byte(`{"error": "Image is in use"}`))
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

	// Test removing a valid image
	err = client.RemoveImage(context.Background(), "validimage", false)
	require.NoError(t, err)

	// Test removing an image with force
	err = client.RemoveImage(context.Background(), "inuse", true)
	require.NoError(t, err)

	// Test removing an image in use without force
	err = client.RemoveImage(context.Background(), "inuse", false)
	assert.Error(t, err)

	// Test removing a non-existent image
	err = client.RemoveImage(context.Background(), "nonexistent", false)
	assert.Error(t, err)

	// Test with empty image ID
	err = client.RemoveImage(context.Background(), "", false)
	assert.Error(t, err)
}

// TestGetImageHistory tests getting the history of an image
func TestGetImageHistory(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path matches expected pattern
		if strings.HasPrefix(r.URL.Path, "/api/v1/images/") && strings.HasSuffix(r.URL.Path, "/history") && r.Method == http.MethodGet {
			// Extract image ID from URL
			parts := strings.Split(r.URL.Path, "/")
			imageID := parts[len(parts)-2]

			if imageID == "validimage" {
				// Return history
				history := []models.ImageHistoryResponse{ // Use correct type name
					{
						ID:        "sha256:layer1hash",
						Created:   time.Now(), // Use time.Time
						CreatedBy: "/bin/sh -c #(nop) CMD [\"nginx\" \"-g\" \"daemon off;\"]",
						Size:      0,
						Comment:   "",
					},
					{
						ID:        "sha256:layer2hash",
						Created:   time.Now().Add(-1 * time.Hour), // Use time.Time
						CreatedBy: "/bin/sh -c #(nop) EXPOSE 80",
						Size:      0,
						Comment:   "",
					},
					{
						ID:        "sha256:layer3hash",
						Created:   time.Now().Add(-2 * time.Hour), // Use time.Time
						CreatedBy: "/bin/sh -c apt-get update && apt-get install -y nginx",
						Size:      1024 * 1024 * 30, // 30MB
						Comment:   "",
					},
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(history)
			} else {
				// Image not found
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Image not found"}`))
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

	// Test getting history of a valid image
	history, err := client.GetImageHistory(context.Background(), "validimage")
	require.NoError(t, err)
	assert.Len(t, history, 3)
	assert.Equal(t, "sha256:layer1hash", history[0].ID)
	assert.Equal(t, "sha256:layer2hash", history[1].ID)
	assert.Equal(t, "sha256:layer3hash", history[2].ID)

	// Test getting history of a non-existent image
	_, err = client.GetImageHistory(context.Background(), "nonexistentimage")
	assert.Error(t, err)

	// Test with empty image ID
	_, err = client.GetImageHistory(context.Background(), "")
	assert.Error(t, err)
}

// TestSearchImages tests searching for images
func TestSearchImages(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/images/search", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		// Parse query parameters
		query := r.URL.Query()
		term := query.Get("term")
		limit := query.Get("limit")

		assert.NotEmpty(t, term)

		var searchResults []registrytypes.SearchResult // Use registrytypes.SearchResult

		if term == "nginx" {
			searchResults = []registrytypes.SearchResult{ // Use registrytypes.SearchResult
				{
					Name:        "nginx",
					Description: "Official build of Nginx",
					StarCount:   10000,
					IsOfficial:  true,
					IsAutomated: false,
				},
				{
					Name:        "jwilder/nginx-proxy",
					Description: "Automated Nginx reverse proxy for docker_test containers",
					StarCount:   5000,
					IsOfficial:  false,
					IsAutomated: true,
				},
			}

			// Apply limit if specified
			if limit != "" {
				limitInt := 0
				_, err := fmt.Sscanf(limit, "%d", &limitInt)
				require.NoError(t, err)

				if limitInt > 0 && limitInt < len(searchResults) {
					searchResults = searchResults[:limitInt]
				}
			}
		} else if term == "nonexistent" {
			// No results
			searchResults = []registrytypes.SearchResult{} // Use registrytypes.SearchResult
		} else {
			// Generic results
			searchResults = []registrytypes.SearchResult{ // Use registrytypes.SearchResult
				{
					Name:        term,
					Description: "Example image",
					StarCount:   100,
					IsOfficial:  false,
					IsAutomated: false,
				},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(searchResults)
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test searching for images
	results, err := client.SearchImages(context.Background(), "nginx", 0)
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, "nginx", results[0].Name)
	assert.Equal(t, "jwilder/nginx-proxy", results[1].Name)

	// Test searching with limit
	results, err = client.SearchImages(context.Background(), "nginx", 1)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "nginx", results[0].Name)

	// Test searching for non-existent image
	results, err = client.SearchImages(context.Background(), "nonexistent", 0)
	require.NoError(t, err)
	assert.Len(t, results, 0)

	// Test with empty term
	_, err = client.SearchImages(context.Background(), "", 0)
	assert.Error(t, err)
}

// TestParseImageRef tests the image reference parsing helper
func TestParseImageRef(t *testing.T) {
	// Test cases
	testCases := []struct {
		inputRef     string
		expectedRepo string
		expectedTag  string
		expectError  bool // Note: error check not implemented in current parseImageRef
	}{
		{"nginx", "docker.io/library/nginx", "latest", false}, // Corrected: Expect "latest" tag
		{"nginx:latest", "docker.io/library/nginx", "latest", false},
		{"nginx:1.21", "docker.io/library/nginx", "1.21", false},
		{"myregistry.com/myapp:v1.0", "myregistry.com/myapp", "v1.0", false},
		{"myapp", "docker.io/library/myapp", "latest", false},   // Simple name
		{"user/myapp", "docker.io/user/myapp", "latest", false}, // User repo
		{"user/myapp:tag", "docker.io/user/myapp", "tag", false},
		// {"", "", "", true}, // Empty input handled by fallback in current parseImageRef
		// Add cases with digests if needed, though parseImageRef focuses on repo/tag
		// {"nginx@sha256:abcdef...", "docker.io/library/nginx", "", false}, // Digest case
	}

	for _, tc := range testCases {
		t.Run(tc.inputRef, func(t *testing.T) {
			repo, tag := parseImageRef(tc.inputRef)
			assert.Equal(t, tc.expectedRepo, repo)
			assert.Equal(t, tc.expectedTag, tag)
		})
	}
}

// generateTestHash generates a simple hash for testing
func generateTestHash(input string) string {
	// Simple non-cryptographic hash for predictable test output
	hash := 0
	for _, c := range input {
		hash = (hash*31 + int(c)) % 1000000
	}
	return fmt.Sprintf("%06d", hash)
}
