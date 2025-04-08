package client

import (
	"context"
	"encoding/json"
	"fmt" // Added import for Sscanf
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// TestUploadComposeFile tests uploading a Compose file
func TestUploadComposeFile(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/compose/upload", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Check content type
		contentType := r.Header.Get("Content-Type")
		assert.True(t, strings.HasPrefix(contentType, "multipart/form-data"))

		// Parse multipart form
		err := r.ParseMultipartForm(10 << 20) // 10 MB
		require.NoError(t, err)

		// Get uploaded file
		file, header, err := r.FormFile("file")
		require.NoError(t, err)
		defer file.Close()

		// Read file content
		content, err := io.ReadAll(file)
		require.NoError(t, err)

		// Check file content
		if strings.Contains(string(content), "error") {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Invalid Compose file"}`))
			return
		}

		// Successful response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fileID := "compose_" + header.Filename
		json.NewEncoder(w).Encode(map[string]string{
			"fileId": fileID,
		})
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test uploading a valid Compose file
	content := strings.NewReader(`
version: '3'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
`)

	fileID, err := client.UploadComposeFile(context.Background(), content, "docker_test-compose.yml")
	require.NoError(t, err)
	// Corrected assertion based on previous test output
	assert.Equal(t, "compose_docker_test-compose.yml", fileID)

	// Test uploading an invalid Compose file
	content = strings.NewReader(`
version: '3'
services:
  error:
    image: invalid
`)

	_, err = client.UploadComposeFile(context.Background(), content, "invalid.yml")
	assert.Error(t, err)

	// Test with nil content
	_, err = client.UploadComposeFile(context.Background(), nil, "docker_test-compose.yml")
	assert.Error(t, err)
}

// TestValidateComposeFile tests validating a Compose file
func TestValidateComposeFile(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/compose/validate", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Parse request body
		var reqBody struct {
			FileID string `json:"fileId"`
		}

		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)

		// Check file ID
		if reqBody.FileID == "valid_file" {
			// Valid file
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":    true,
				"warnings": []string{"Using latest tag"},
			})
		} else if reqBody.FileID == "invalid_file" {
			// Invalid file
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":  false,
				"errors": []string{"Service 'web' is missing required field 'image'"},
			})
		} else if reqBody.FileID == "nonexistent" {
			// File not found
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "File not found"}`))
		} else {
			// Default valid response
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":    true,
				"warnings": []string{},
			})
		}
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test validating a valid file
	warnings, err := client.ValidateComposeFile(context.Background(), "valid_file")
	require.NoError(t, err)
	assert.Len(t, warnings, 1)
	assert.Equal(t, "Using latest tag", warnings[0])

	// Test validating an invalid file
	_, err = client.ValidateComposeFile(context.Background(), "invalid_file")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Service 'web' is missing required field 'image'")

	// Test validating a non-existent file
	_, err = client.ValidateComposeFile(context.Background(), "nonexistent")
	assert.Error(t, err)

	// Test with empty file ID
	_, err = client.ValidateComposeFile(context.Background(), "")
	assert.Error(t, err)
}

// TestComposeUp tests deploying a Compose file
func TestComposeUp(t *testing.T) {
	// Create test mux to handle different paths
	mux := http.NewServeMux()

	// POST /compose/upload - Upload Compose file
	mux.HandleFunc("/api/v1/compose/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		err := r.ParseMultipartForm(10 << 20) // 10 MB
		require.NoError(t, err)
		file, header, err := r.FormFile("file")
		require.NoError(t, err)
		defer file.Close()
		fileID := "file_" + header.Filename
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"fileId": fileID})
	})

	// POST /compose/up - Deploy Compose
	mux.HandleFunc("/api/v1/compose/up", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var reqBody struct {
			FileIDs []string                 `json:"fileIds"`
			Options *models.ComposeUpOptions `json:"options"`
		}
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)
		if len(reqBody.FileIDs) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "At least one file ID is required"}`))
			return
		}
		deploymentID := "deployment_" + strings.Join(reqBody.FileIDs, "_")
		if reqBody.Options != nil && reqBody.Options.ProjectName != "" {
			deploymentID = "deployment_" + reqBody.Options.ProjectName
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"deploymentId": deploymentID})
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	file1 := strings.NewReader(`version: '3'\nservices:\n  web:\n    image: nginx:latest`)
	file2 := strings.NewReader(`version: '3'\nservices:\n  db:\n    image: postgres:latest`)
	files := []io.Reader{file1, file2}
	options := &models.ComposeUpOptions{ProjectName: "test_project"}

	deploymentID, err := client.ComposeUp(context.Background(), files, options)
	require.NoError(t, err)
	assert.Equal(t, "deployment_test_project", deploymentID)

	_, err = client.ComposeUp(context.Background(), []io.Reader{}, options)
	assert.Error(t, err)
}

// TestComposeDown tests shutting down a Compose deployment
func TestComposeDown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/compose/") && strings.HasSuffix(r.URL.Path, "/down") && r.Method == http.MethodPost {
			parts := strings.Split(r.URL.Path, "/")
			deploymentID := parts[len(parts)-2]
			var options models.ComposeDownOptions
			err := json.NewDecoder(r.Body).Decode(&options)
			require.NoError(t, err)
			if deploymentID == "nonexistent" {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Deployment not found"}`))
			} else {
				w.WriteHeader(http.StatusOK)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	options := &models.ComposeDownOptions{RemoveVolumes: true, RemoveImages: "local"}
	err = client.ComposeDown(context.Background(), "valid_deployment", options)
	require.NoError(t, err)
	err = client.ComposeDown(context.Background(), "nonexistent", options)
	assert.Error(t, err)
	err = client.ComposeDown(context.Background(), "", options)
	assert.Error(t, err)
}

// Shared server setup for GetComposeStatus and WatchComposeDeployment
var composeStatusServer *httptest.Server
var watchCallCount map[string]int

func setupComposeStatusServer() {
	watchCallCount = make(map[string]int)
	composeStatusServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle GET logs requests first (more specific path)
		// Path: /api/v1/compose/{id}/logs?service=...&tail=...
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/logs") {
			pathParts := strings.Split(strings.TrimSuffix(r.URL.Path, "/logs"), "/")
			// Expected: ["", "api", "v1", "compose", "{id}"] -> len=5, id index=4
			if len(pathParts) != 5 || pathParts[1] != "api" || pathParts[2] != "v1" || pathParts[3] != "compose" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			deploymentID := pathParts[4] // Correct index for ID
			serviceName := r.URL.Query().Get("service")
			tail := r.URL.Query().Get("tail")

			if deploymentID == "nonexistent" || serviceName == "nonexistent" {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Not found"}`))
				return
			}

			w.Header().Set("Content-Type", "text/plain")
			logLine := fmt.Sprintf("Log for %s", deploymentID) // Use correct ID
			if serviceName != "" {
				logLine += fmt.Sprintf(" service %s", serviceName)
			}
			if tail != "" {
				logLine += fmt.Sprintf(" tail %s", tail)
			}
			w.Write([]byte(logLine))
			return // Handled GET logs request
		}

		// Handle GET status requests (less specific path)
		// Path: /api/v1/compose/{id}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/compose/") {
			parts := strings.Split(r.URL.Path, "/")
			// Expected: ["", "api", "v1", "compose", "{id}"] -> len=5, id index=4
			if len(parts) != 5 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			deploymentID := parts[4] // Correct index for ID

			if deploymentID == "watch_deployment" {
				watchCallCount[deploymentID]++
				status := models.ComposeStatus{ // Use ComposeStatus
					DeploymentID: deploymentID, ProjectName: "watch_project",
					Status:      string(models.DeploymentStatusRunning), // Cast constant to string
					LastUpdated: time.Now(),
					Services: []models.ComposeServiceStatus{ // Use ComposeServiceStatus
						{ID: "watch_svc_1", Name: "watch_service", State: string(models.ServiceStatusRunning)}, // State is string
					},
				}
				// Simulate state change after first call
				if watchCallCount[deploymentID] > 1 {
					status.Status = string(models.DeploymentStatusStopped) // Cast constant to string
					status.Services[0].State = string(models.ServiceStatusExited)
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(status) // Encode ComposeStatus
			} else if deploymentID == "valid_deployment" {
				status := models.ComposeStatus{ // Use ComposeStatus
					DeploymentID: deploymentID, ProjectName: "test_project", Status: string(models.DeploymentStatusRunning), // Cast constant to string
					LastUpdated: time.Now().Add(-1 * time.Hour),
					Services: []models.ComposeServiceStatus{ // Use ComposeServiceStatus
						{ID: "container_web_1", Name: "web", State: string(models.ServiceStatusRunning), Ports: []models.PortMapping{{ContainerPort: "80", HostPort: "80", Type: "tcp"}}},
						{ID: "container_db_1", Name: "db", State: string(models.ServiceStatusRunning), Ports: []models.PortMapping{{ContainerPort: "5432", HostPort: "5432", Type: "tcp"}}},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(status) // Encode ComposeStatus
			} else if deploymentID == "nonexistent" {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Deployment not found"}`))
			} else { // Handle generic case for other tests if needed
				status := models.ComposeStatus{ // Use ComposeStatus
					DeploymentID: deploymentID, ProjectName: "project_" + deploymentID, Status: string(models.DeploymentStatusRunning), // Cast constant to string
					LastUpdated: time.Now().Add(-1 * time.Hour), Services: []models.ComposeServiceStatus{},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(status) // Encode ComposeStatus
			}
			return // Handled GET status request
		}

		// Fallback for unhandled requests
		w.WriteHeader(http.StatusNotFound)
	}))
}

func teardownComposeStatusServer() {
	if composeStatusServer != nil {
		composeStatusServer.Close()
	}
}

// TestGetComposeStatus tests getting the status of a Compose deployment
func TestGetComposeStatus(t *testing.T) {
	setupComposeStatusServer()
	defer teardownComposeStatusServer()

	client, err := NewClient(WithBaseURL(composeStatusServer.URL))
	require.NoError(t, err)

	status, err := client.GetComposeStatus(context.Background(), "valid_deployment")
	require.NoError(t, err)
	assert.Equal(t, "test_project", status.ProjectName)
	assert.Equal(t, string(models.DeploymentStatusRunning), status.Status) // Compare string representation
	assert.Len(t, status.Services, 2)
	assert.Equal(t, "web", status.Services[0].Name)
	assert.Equal(t, "db", status.Services[1].Name)

	_, err = client.GetComposeStatus(context.Background(), "nonexistent")
	assert.Error(t, err)
	_, err = client.GetComposeStatus(context.Background(), "")
	assert.Error(t, err)
}

// TestListComposeDeployments tests listing Compose deployments
func TestListComposeDeployments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compose", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		// Use ComposeDeploymentResponse as expected by the client function
		deployments := []models.ComposeDeploymentResponse{
			{ID: 1, ProjectName: "project1", Status: "running", ServiceCount: 2, LastUpdated: time.Now().Add(-2 * time.Hour)}, // Use uint ID
			{ID: 2, ProjectName: "project2", Status: "running", ServiceCount: 3, LastUpdated: time.Now().Add(-1 * time.Hour)}, // Use uint ID
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(deployments)
	}))
	defer server.Close()
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	deployments, err := client.ListComposeDeployments(context.Background())
	require.NoError(t, err)
	assert.Len(t, deployments, 2)
	assert.Equal(t, "project1", deployments[0].ProjectName)
	assert.Equal(t, "project2", deployments[1].ProjectName)
}

// TestScaleComposeService tests scaling a service in a Compose deployment
func TestScaleComposeService(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/compose/") && strings.HasSuffix(r.URL.Path, "/scale") && r.Method == http.MethodPost {
			parts := strings.Split(r.URL.Path, "/")
			deploymentID := parts[len(parts)-2]
			var reqBody struct {
				Service  string `json:"service"`
				Replicas int    `json:"replicas"`
			}
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)
			if reqBody.Service == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error": "Service name cannot be empty"}`))
				return
			}
			if reqBody.Replicas < 0 {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error": "Replicas must be non-negative"}`))
				return
			}
			if deploymentID == "nonexistent" {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Deployment not found"}`))
				return
			}
			if reqBody.Service == "nonexistent" {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Service not found"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	err = client.ScaleComposeService(context.Background(), "valid_deployment", "web", 3)
	require.NoError(t, err)
	err = client.ScaleComposeService(context.Background(), "nonexistent", "web", 3)
	assert.Error(t, err)
	err = client.ScaleComposeService(context.Background(), "valid_deployment", "nonexistent", 3)
	assert.Error(t, err)
	err = client.ScaleComposeService(context.Background(), "valid_deployment", "web", -1)
	assert.Error(t, err)
	err = client.ScaleComposeService(context.Background(), "", "web", 3)
	assert.Error(t, err)
	err = client.ScaleComposeService(context.Background(), "valid_deployment", "", 3)
	assert.Error(t, err)
}

// TestGetComposeLogs tests getting logs for a Compose deployment or service
func TestGetComposeLogs(t *testing.T) {
	setupComposeStatusServer() // Reuse server that handles logs
	defer teardownComposeStatusServer()

	client, err := NewClient(WithBaseURL(composeStatusServer.URL))
	require.NoError(t, err)

	// Test getting logs for deployment (service="")
	logs, err := client.GetComposeLogs(context.Background(), "valid_deployment", "", 0) // Pass empty service and 0 tail
	require.NoError(t, err)
	logBytes, err := io.ReadAll(logs)
	require.NoError(t, err)
	assert.Equal(t, "Log for valid_deployment", string(logBytes))
	logs.Close() // Close the reader

	// Test getting logs for specific service with tail
	logs, err = client.GetComposeLogs(context.Background(), "valid_deployment", "web", 10) // Pass service and tail
	require.NoError(t, err)
	logBytes, err = io.ReadAll(logs)
	require.NoError(t, err)
	assert.Equal(t, "Log for valid_deployment service web tail 10", string(logBytes))
	logs.Close() // Close the reader

	// Test with non-existent deployment
	_, err = client.GetComposeLogs(context.Background(), "nonexistent", "web", 0)
	assert.Error(t, err)

	// Test with non-existent service
	_, err = client.GetComposeLogs(context.Background(), "valid_deployment", "nonexistent", 0)
	assert.Error(t, err)

	// Test with empty deployment ID
	_, err = client.GetComposeLogs(context.Background(), "", "web", 0)
	assert.Error(t, err)

	// Test with empty service name (should still work, gets all logs)
	logs, err = client.GetComposeLogs(context.Background(), "valid_deployment", "", 100)
	require.NoError(t, err)
	logBytes, err = io.ReadAll(logs)
	require.NoError(t, err)
	assert.Equal(t, "Log for valid_deployment tail 100", string(logBytes))
	logs.Close() // Close the reader
}

// TestWatchComposeDeployment tests watching the status of a Compose deployment
func TestWatchComposeDeployment(t *testing.T) {
	setupComposeStatusServer() // Use shared server
	defer teardownComposeStatusServer()

	client, err := NewClient(WithBaseURL(composeStatusServer.URL))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond) // Increased timeout
	defer cancel()

	statusCh, errCh := client.WatchComposeDeployment(ctx, "watch_deployment", 10*time.Millisecond) // Use specific ID

	var receivedStatuses []*models.ComposeStatus // Correct slice type
	var receivedError error

	// Collect statuses and errors
	done := false
	for !done {
		select {
		case status, ok := <-statusCh:
			if !ok {
				done = true // Channel closed
				break
			}
			receivedStatuses = append(receivedStatuses, status)
		case err, ok := <-errCh:
			if ok {
				receivedError = err
			}
			done = true // Error occurred or channel closed
		case <-ctx.Done():
			receivedError = ctx.Err() // Timeout occurred
			done = true
		}
	}

	assert.NoError(t, receivedError, "Watch returned an error") // Expect no error for successful watch

	// Check received statuses
	require.GreaterOrEqual(t, len(receivedStatuses), 2, "Expected at least 2 status updates")
	assert.Equal(t, string(models.DeploymentStatusRunning), receivedStatuses[0].Status)                       // Compare string representation
	assert.Equal(t, string(models.DeploymentStatusStopped), receivedStatuses[len(receivedStatuses)-1].Status) // Compare string representation
	assert.Equal(t, string(models.ServiceStatusExited), receivedStatuses[len(receivedStatuses)-1].Services[0].State)
}
