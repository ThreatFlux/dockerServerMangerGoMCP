package client

import (
	"archive/tar" // Added for tar operations
	"bytes"       // Added for in-memory buffer
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// TestListContainers tests the container listing functionality
func TestListContainers(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/containers", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		// Parse query parameters
		query := r.URL.Query()
		filters := query.Get("filters")

		var containerList []models.Container

		// Generate containers based on filters
		if filters != "" {
			var filtersMap map[string][]string
			err := json.Unmarshal([]byte(filters), &filtersMap)
			require.NoError(t, err)

			// Check for name filter
			if names, ok := filtersMap["name"]; ok && len(names) > 0 {
				// Return containers matching the name filter
				for _, name := range names {
					containerList = append(containerList, models.Container{
						DockerResource: models.DockerResource{ID: 0, Name: name}, // Use embedded DockerResource, ID is uint
						ContainerID:    "container_" + name,                      // Use ContainerID
					})
				}
			}
		} else {
			// Return default containers using correct fields
			containerList = []models.Container{
				{
					DockerResource: models.DockerResource{ID: 1, Name: "test_container_1"}, // Use embedded DockerResource
					ContainerID:    "container1",                                           // Use ContainerID
					Image:          "nginx:latest",
					State:          "running",
				},
				{
					DockerResource: models.DockerResource{ID: 2, Name: "test_container_2"}, // Use embedded DockerResource
					ContainerID:    "container2",                                           // Use ContainerID
					Image:          "redis:latest",
					State:          "exited",
				},
			}
		}

		// Write response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(containerList)
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test listing all containers
	containers, err := client.ListContainers(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, containers, 2)
	assert.Equal(t, "container1", containers[0].ContainerID) // Use ContainerID
	assert.Equal(t, "container2", containers[1].ContainerID) // Use ContainerID

	// Test with name filter
	filters := map[string]string{
		"name": "filtered_container",
	}

	containers, err = client.ListContainers(context.Background(), filters)
	require.NoError(t, err)
	assert.Len(t, containers, 1)
	assert.Equal(t, "container_filtered_container", containers[0].ContainerID) // Use ContainerID
	assert.Equal(t, "filtered_container", containers[0].DockerResource.Name)   // Access Name via DockerResource
}

// TestGetContainer tests getting container details
func TestGetContainer(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path matches expected pattern
		// Path: /api/v1/containers/{id}
		if strings.HasPrefix(r.URL.Path, "/api/v1/containers/") && r.Method == http.MethodGet && len(strings.Split(strings.Trim(r.URL.Path, "/"), "/")) == 4 {
			parts := strings.Split(r.URL.Path, "/")
			containerID := parts[len(parts)-1]

			if containerID == "validcontainer" {
				// Return container details using correct fields
				container := models.Container{
					DockerResource: models.DockerResource{ID: 1, Name: "test_container", CreatedAt: time.Now().Add(-24 * time.Hour)}, // Use embedded DockerResource
					ContainerID:    containerID,
					Image:          "nginx:latest",
					State:          "running",
					Ports: models.JSONMap{ // Use JSONMap for Ports
						"80/tcp": []map[string]string{ // Key is containerPort/protocol
							{"HostIp": "0.0.0.0", "HostPort": "8080"},
						},
					},
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(container)
			} else {
				// Container not found
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Container not found"}`))
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

	// Test getting a valid container
	container, err := client.GetContainer(context.Background(), "validcontainer")
	require.NoError(t, err)
	assert.Equal(t, "validcontainer", container.ContainerID)         // Use ContainerID
	assert.Equal(t, "test_container", container.DockerResource.Name) // Access Name via DockerResource
	assert.Equal(t, "nginx:latest", container.Image)
	assert.Equal(t, "running", container.State)
	assert.Len(t, container.Ports, 1)
	// Access ports map correctly
	portBindings, ok := container.Ports["80/tcp"].([]interface{})
	require.True(t, ok, "Port 80/tcp should exist and be a slice")
	require.Len(t, portBindings, 1, "Port 80/tcp should have one binding")
	binding, ok := portBindings[0].(map[string]interface{})
	require.True(t, ok, "Binding should be a map")
	assert.Equal(t, "8080", binding["HostPort"])

	// Test getting a non-existent container
	_, err = client.GetContainer(context.Background(), "nonexistentcontainer")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound) // Check for wrapped error

	// Test with empty container ID
	_, err = client.GetContainer(context.Background(), "")
	assert.Error(t, err)
}

// TestCreateContainer tests container creation
func TestCreateContainer(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		assert.Equal(t, "/api/v1/containers", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Parse request body
		var createReq models.ContainerCreateRequest // Use correct type name
		err := json.NewDecoder(r.Body).Decode(&createReq)
		require.NoError(t, err)

		// Check required fields
		if createReq.Image == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Image name cannot be empty"}`))
			return
		}

		// Generate container ID
		containerID := "container_" + createReq.Name
		if containerID == "container_" {
			containerID = "container_" + strconv.FormatInt(time.Now().Unix(), 10)
		}

		// Return created container using correct fields
		container := models.Container{
			DockerResource: models.DockerResource{ID: 0, Name: createReq.Name, CreatedAt: time.Now()}, // Use embedded DockerResource
			ContainerID:    containerID,
			Image:          createReq.Image,
			Command:        strings.Join(createReq.Command, " "), // Use correct field name 'Command' and join slice
			State:          "created",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(container)
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test creating a container with minimal options
	createReq := &models.ContainerCreateRequest{ // Use correct type name
		Image: "nginx:latest",
		Name:  "test_container",
	}
	container, err := client.CreateContainer(context.Background(), createReq)
	require.NoError(t, err)
	assert.Equal(t, "container_test_container", container.ContainerID) // Use ContainerID
	assert.Equal(t, "test_container", container.DockerResource.Name)   // Access Name via DockerResource
	assert.Equal(t, "nginx:latest", container.Image)
	assert.Equal(t, "created", container.State)

	// Test with invalid request (missing image)
	createReq = &models.ContainerCreateRequest{ // Use correct type name
		Name: "invalid_container",
	}

	_, err = client.CreateContainer(context.Background(), createReq)
	assert.Error(t, err)

	// Test with nil request
	_, err = client.CreateContainer(context.Background(), nil)
	assert.Error(t, err)
}

// TestContainerLifecycle tests container lifecycle operations (start, stop, pause, etc.)
func TestContainerLifecycle(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		// Expected path: api/v1/containers/{id} (DELETE) or api/v1/containers/{id}/{operation} (POST)
		if len(parts) < 4 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "containers" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Invalid base path"}`))
			return
		}
		containerID := parts[3]

		// Handle DELETE
		if r.Method == http.MethodDelete {
			if len(parts) != 4 { // Path should be exactly /api/v1/containers/{id}
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Invalid delete path"}`))
				return
			}
			if containerID == "nonexistent" {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Container not found"}`))
			} else if containerID == "testcontainer" {
				force := r.URL.Query().Get("force")
				assert.Equal(t, "true", force, "Force parameter should be true for delete")
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Container not found for delete"}`))
			}
			return
		}

		// Handle POST lifecycle operations
		if r.Method == http.MethodPost {
			// Path should be /api/v1/containers/{id}/{operation} -> len=5
			if len(parts) != 5 {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Invalid lifecycle path structure"}`))
				return
			}
			operation := parts[4]
			if containerID == "nonexistent" {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Container not found"}`))
			} else if containerID == "testcontainer" {
				switch operation {
				case "start", "restart", "pause", "unpause":
					w.WriteHeader(http.StatusNoContent)
				case "stop":
					timeout := r.URL.Query().Get("t")
					assert.NotEmpty(t, timeout, "Timeout parameter should be provided for stop")
					w.WriteHeader(http.StatusNoContent)
				default:
					w.WriteHeader(http.StatusNotFound) // Unknown operation
					w.Write([]byte(`{"error": "Unknown lifecycle operation"}`))
				}
			} else {
				// If ID is not "testcontainer" or "nonexistent", return 404
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error": "Container not found for lifecycle op"}`))
			}
			return
		}

		// Fallback for other methods or invalid paths
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error": "Method not allowed or invalid path"}`))
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test container operations
	containerID := "testcontainer"

	// Start container
	err = client.StartContainer(context.Background(), containerID)
	require.NoError(t, err)

	// Stop container with timeout
	timeout := 10
	err = client.StopContainer(context.Background(), containerID, &timeout)
	require.NoError(t, err)

	// Restart container
	err = client.RestartContainer(context.Background(), containerID, &timeout)
	require.NoError(t, err)

	// Pause container
	err = client.PauseContainer(context.Background(), containerID)
	require.NoError(t, err)

	// Unpause container
	err = client.UnpauseContainer(context.Background(), containerID)
	require.NoError(t, err)

	// Remove container
	err = client.RemoveContainer(context.Background(), containerID, true)
	require.NoError(t, err)

	// Test operations with non-existent container
	err = client.StartContainer(context.Background(), "nonexistent") // Use StartContainer for check
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound) // Check wrapped error

	// Test with empty container ID
	err = client.StartContainer(context.Background(), "")
	assert.Error(t, err)
}

// TestGetContainerLogs tests getting container logs
func TestGetContainerLogs(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		if !strings.HasPrefix(r.URL.Path, "/api/v1/containers/") || !strings.HasSuffix(r.URL.Path, "/logs") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		assert.Equal(t, http.MethodGet, r.Method)

		// Extract container ID from URL
		parts := strings.Split(r.URL.Path, "/")
		containerID := parts[len(parts)-2]

		if containerID == "nonexistent" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Container not found"}`))
			return
		}

		// Check query parameters
		query := r.URL.Query()
		stdout := query.Get("stdout")
		stderr := query.Get("stderr")
		timestamps := query.Get("timestamps")

		assert.Equal(t, "true", stdout)
		assert.Equal(t, "true", stderr)

		// Generate log content based on parameters
		logContent := "Container log line 1\nContainer log line 2\n"
		if timestamps == "true" {
			now := time.Now()
			logContent = now.Format(time.RFC3339) + " Container log line 1\n" +
				now.Add(time.Second).Format(time.RFC3339) + " Container log line 2\n"
		}

		// Write log content
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(logContent))
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test getting logs
	options := map[string]string{
		"stdout":     "true",
		"stderr":     "true",
		"timestamps": "true",
	}

	logReader, err := client.GetContainerLogs(context.Background(), "testcontainer", options)
	require.NoError(t, err)
	defer logReader.Close()

	// Read log content
	logContent, err := io.ReadAll(logReader)
	require.NoError(t, err)
	assert.Contains(t, string(logContent), "Container log line")

	// Test with invalid container ID
	_, err = client.GetContainerLogs(context.Background(), "nonexistent", options)
	assert.Error(t, err)

	// Test with empty container ID
	_, err = client.GetContainerLogs(context.Background(), "", options)
	assert.Error(t, err)
}

// TestGetContainerStats tests getting container stats
func TestGetContainerStats(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		if !strings.HasPrefix(r.URL.Path, "/api/v1/containers/") || !strings.HasSuffix(r.URL.Path, "/stats") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		assert.Equal(t, http.MethodGet, r.Method)

		// Extract container ID from URL
		parts := strings.Split(r.URL.Path, "/")
		containerID := parts[len(parts)-2]

		if containerID == "nonexistent" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Container not found"}`))
			return
		}

		// Check stream parameter
		stream := r.URL.Query().Get("stream")
		assert.Equal(t, "false", stream)

		// Return stats using correct ContainerStats fields
		stats := models.ContainerStats{
			Time:             time.Now(),
			CPUPercentage:    10.5,
			CPUUsage:         1000000,
			SystemCPUUsage:   10000000,
			OnlineCPUs:       4,
			MemoryUsage:      104857600,  // 100MB
			MemoryMaxUsage:   209715200,  // 200MB
			MemoryLimit:      1073741824, // 1GB
			MemoryPercentage: 9.77,
			NetworkRx:        1024,
			NetworkTx:        2048,
			BlockRead:        4096,
			BlockWrite:       8192,
			PIDs:             15,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test getting stats
	stats, err := client.GetContainerStats(context.Background(), "testcontainer")
	require.NoError(t, err)
	assert.Equal(t, uint64(1000000), stats.CPUUsage)      // Use direct field CPUUsage
	assert.Equal(t, uint64(104857600), stats.MemoryUsage) // Use direct field MemoryUsage
	assert.Equal(t, int64(1024), stats.NetworkRx)         // Use direct field NetworkRx
	assert.Equal(t, int64(2048), stats.NetworkTx)         // Use direct field NetworkTx

	// Test with invalid container ID
	_, err = client.GetContainerStats(context.Background(), "nonexistent")
	assert.Error(t, err)

	// Test with empty container ID
	_, err = client.GetContainerStats(context.Background(), "")
	assert.Error(t, err)
}

// TestExecCreate tests creating an exec instance
func TestExecCreate(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path and method
		if !strings.HasPrefix(r.URL.Path, "/api/v1/containers/") || !strings.HasSuffix(r.URL.Path, "/exec") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		assert.Equal(t, http.MethodPost, r.Method)

		// Extract container ID from URL
		parts := strings.Split(r.URL.Path, "/")
		containerID := parts[len(parts)-2]

		if containerID == "nonexistent" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Container not found"}`))
			return
		}

		// Parse request body
		var execConfig models.ContainerExecCreateRequest // Use correct type name
		err := json.NewDecoder(r.Body).Decode(&execConfig)
		require.NoError(t, err)
		// Check command
		assert.NotEmpty(t, execConfig.Command) // Use correct field name 'Command'

		// Return exec ID
		response := struct {
			ID string `json:"Id"`
		}{
			ID: "exec_" + containerID,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test creating exec instance using models.ContainerExecCreateRequest
	execConfig := &models.ContainerExecCreateRequest{ // Use internal model type
		Command:      []string{"ls", "-la"}, // Use Command field
		AttachStdin:  false,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
	}

	execID, err := client.ExecCreate(context.Background(), "testcontainer", execConfig) // Pass internal model type
	require.NoError(t, err)
	assert.Equal(t, "exec_testcontainer", execID)

	// Test with invalid container ID
	_, err = client.ExecCreate(context.Background(), "nonexistent", execConfig) // Pass internal model type
	assert.Error(t, err)

	// Test with nil config
	_, err = client.ExecCreate(context.Background(), "testcontainer", nil)
	assert.Error(t, err)

	// Test with empty command
	_, err = client.ExecCreate(context.Background(), "testcontainer", &models.ContainerExecCreateRequest{}) // Use internal model type
	assert.Error(t, err)
}

// TestContainerFileOperations tests file operations for containers
func TestContainerFileOperations(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request path prefix and suffix
		// Path: /api/v1/containers/{id}/archive
		if !strings.HasPrefix(r.URL.Path, "/api/v1/containers/") || !strings.HasSuffix(r.URL.Path, "/archive") {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Invalid archive path"}`))
			return
		}

		// Extract container ID from URL
		trimmedPath := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/containers/"), "/archive")
		containerID := trimmedPath

		if containerID == "nonexistent" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Container not found"}`))
			return
		}
		if containerID != "testcontainer" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Container not found for file ops"}`))
			return
		}

		// Check query parameter 'path'
		path := r.URL.Query().Get("path")
		assert.NotEmpty(t, path)

		if r.Method == http.MethodGet {
			// Handle CopyFromContainer
			assert.Equal(t, "/path/to/source", path)
			w.Header().Set("Content-Type", "application/x-tar")
			// Create a simple tar archive for the response (write to buffer first)
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			fileContent := []byte("mock tar data")
			hdr := &tar.Header{
				Name: "source_file.txt", // Example filename in archive
				Mode: 0600,
				Size: int64(len(fileContent)),
			}
			err := tw.WriteHeader(hdr)
			require.NoError(t, err, "Mock server failed to write tar header")
			_, err = tw.Write(fileContent)
			require.NoError(t, err, "Mock server failed to write tar data")
			err = tw.Close() // Close the writer to finalize the archive
			require.NoError(t, err, "Mock server failed to close tar writer")

			// Ensure buffer has data before writing
			require.Greater(t, buf.Len(), 0, "Tar buffer should not be empty")
			w.Header().Set("Content-Length", strconv.Itoa(buf.Len())) // Set Content-Length
			w.Write(buf.Bytes())
			// Try flushing if available (e.g., for chunked responses)
			if f, ok := w.(http.Flusher); ok {
				f.Flush() // Flush after writing
			}
		} else if r.Method == http.MethodPut {
			// Handle CopyToContainer - Read and verify the uploaded tar stream
			assert.Equal(t, "/path/to/destination", path)
			assert.Equal(t, "application/x-tar", r.Header.Get("Content-Type"))
			tr := tar.NewReader(r.Body)
			hdr, err := tr.Next() // Use := here as hdr and err are new in this scope
			require.NoError(t, err, "Failed to read tar header")
			assert.Equal(t, "dest_file.txt", hdr.Name)

			contentBytes := new(bytes.Buffer)
			_, err = io.Copy(contentBytes, tr) // Use = for err as it's already declared
			require.NoError(t, err, "Failed to read tar content")
			assert.Equal(t, "test file content", contentBytes.String())

			// Ensure no more files in archive
			_, err = tr.Next() // Use = for err
			assert.Equal(t, io.EOF, err, "Expected end of tar archive")

			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	// Create client
	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	// Test copying to container - Create a tar stream
	var copyToBuf bytes.Buffer
	twCopyTo := tar.NewWriter(&copyToBuf)
	contentBytes := []byte("test file content")
	hdrCopyTo := &tar.Header{
		Name: "dest_file.txt", // Filename inside the tar
		Mode: 0600,
		Size: int64(len(contentBytes)),
	}
	require.NoError(t, twCopyTo.WriteHeader(hdrCopyTo))
	_, err = twCopyTo.Write(contentBytes)
	require.NoError(t, err)
	require.NoError(t, twCopyTo.Close()) // Close finishes the tar archive

	err = client.CopyToContainer(context.Background(), "testcontainer", "/path/to/destination", &copyToBuf) // Pass the buffer containing the tar stream
	require.NoError(t, err)

	// Test copying from container
	reader, err := client.CopyFromContainer(context.Background(), "testcontainer", "/path/to/source")
	require.NoError(t, err)
	defer reader.Close()

	// Verify the content extracted from the tar stream
	// Revert to reading directly from the reader
	tr := tar.NewReader(reader) // Create reader directly from the response body
	hdr, err := tr.Next()       // Read the first header
	require.NoError(t, err, "Failed to read tar header from response")
	assert.Equal(t, "source_file.txt", hdr.Name) // Check filename

	extractedContent := new(bytes.Buffer)
	_, err = io.Copy(extractedContent, tr) // Read the file content from the tar reader
	require.NoError(t, err, "Failed to copy content from tar response")
	assert.Equal(t, "mock tar data", extractedContent.String()) // Check content

	_, err = tr.Next()                                                                       // Try to read the next header
	assert.Equal(t, io.EOF, err, "Expected EOF after reading single file from tar response") // Expect EOF

	// Test CopyToContainer with invalid container ID
	var errBufCopyTo bytes.Buffer
	twErrCopyTo := tar.NewWriter(&errBufCopyTo)
	hdrErrCopyTo := &tar.Header{Name: "err_file.txt", Mode: 0600, Size: 0}
	require.NoError(t, twErrCopyTo.WriteHeader(hdrErrCopyTo))
	require.NoError(t, twErrCopyTo.Close())
	err = client.CopyToContainer(context.Background(), "nonexistent", "/path/to/destination", &errBufCopyTo)
	assert.Error(t, err)

	// Test CopyFromContainer with invalid container ID
	_, err = client.CopyFromContainer(context.Background(), "nonexistent", "/path/to/source")
	assert.Error(t, err)

	// Test CopyToContainer with empty container ID
	var emptyBufCopyTo bytes.Buffer
	twEmptyCopyTo := tar.NewWriter(&emptyBufCopyTo)
	hdrEmptyCopyTo := &tar.Header{Name: "empty_file.txt", Mode: 0600, Size: 0}
	require.NoError(t, twEmptyCopyTo.WriteHeader(hdrEmptyCopyTo))
	require.NoError(t, twEmptyCopyTo.Close())
	err = client.CopyToContainer(context.Background(), "", "/path/to/destination", &emptyBufCopyTo)
	assert.Error(t, err)

	// Test CopyFromContainer with empty path
	_, err = client.CopyFromContainer(context.Background(), "testcontainer", "")
	assert.Error(t, err)
}
