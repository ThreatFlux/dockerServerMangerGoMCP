package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	docker_internal "github.com/threatflux/dockerServerMangerGoMCP/internal/docker"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Added for ComposeUpRequest
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"  // Added for utils.Response
)

// Helper function to get Docker client from manager
func getDockerClient(t *testing.T, manager docker_internal.Manager) *client.Client { // Return *client.Client
	c, err := manager.GetClient() // GetClient returns *client.Client
	require.NoError(t, err, "Failed to get Docker client from manager")
	return c
}

// Helper function to cleanup compose resources
func cleanupComposeStack(t *testing.T, manager docker_internal.Manager, deploymentID string) {
	t.Helper()
	// Use a background context with a timeout for cleanup operations
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := getDockerClient(t, manager) // Use cli variable name

	// Use deploymentID as the compose project name label
	projectLabel := fmt.Sprintf("com.docker.compose.project=%s", deploymentID)
	t.Logf("Starting cleanup for deployment: %s (label: %s)", deploymentID, projectLabel)

	// Remove containers
	containers, err := cli.ContainerList(ctx, container.ListOptions{ // Use container.ListOptions
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("label", projectLabel),
		),
	})
	if err != nil {
		// Log error but continue cleanup
		t.Logf("Warning: Failed to list containers for cleanup (deployment: %s): %v", deploymentID, err)
	} else {
		t.Logf("Found %d container(s) for cleanup (deployment: %s)", len(containers), deploymentID)
		for _, cont := range containers { // Use cont variable name
			t.Logf("Attempting to remove container %s (deployment: %s)", cont.ID[:12], deploymentID)
			err := cli.ContainerRemove(ctx, cont.ID, container.RemoveOptions{ // Use container.RemoveOptions
				Force:         true,
				RemoveVolumes: true, // Also remove anonymous volumes associated with the container
			})
			if err != nil {
				// Check if container is already gone (common during cleanup races)
				if !client.IsErrNotFound(err) {
					t.Logf("Warning: Failed to remove container %s for cleanup (deployment: %s): %v", cont.ID[:12], deploymentID, err)
				} else {
					t.Logf("Container %s already removed (deployment: %s)", cont.ID[:12], deploymentID)
				}
			} else {
				t.Logf("Successfully removed container %s (deployment: %s)", cont.ID[:12], deploymentID)
			}
		}
	}

	// Remove networks
	networks, err := cli.NetworkList(ctx, network.ListOptions{ // Use network.ListOptions
		Filters: filters.NewArgs(
			filters.Arg("label", projectLabel),
		),
	})
	if err != nil {
		t.Logf("Warning: Failed to list networks for cleanup (deployment: %s): %v", deploymentID, err)
	} else {
		t.Logf("Found %d network(s) for cleanup (deployment: %s)", len(networks), deploymentID)
		for _, net := range networks { // Use net variable name
			// Avoid removing default networks if they somehow get labeled
			if net.Name == "bridge" || net.Name == "host" || net.Name == "none" {
				continue
			}
			t.Logf("Attempting to remove network %s (%s) (deployment: %s)", net.Name, net.ID[:12], deploymentID)
			err := cli.NetworkRemove(ctx, net.ID)
			if err != nil {
				if !client.IsErrNotFound(err) { // Check if already gone
					t.Logf("Warning: Failed to remove network %s for cleanup (deployment: %s): %v", net.Name, deploymentID, err)
				} else {
					t.Logf("Network %s already removed (deployment: %s)", net.Name, deploymentID)
				}
			} else {
				t.Logf("Successfully removed network %s (deployment: %s)", net.Name, deploymentID)
			}
		}
	}

	// Remove volumes (only those explicitly labeled by compose)
	volumes, err := cli.VolumeList(ctx, volume.ListOptions{ // Use volume.ListOptions
		Filters: filters.NewArgs(
			filters.Arg("label", projectLabel),
		),
	})
	if err != nil {
		t.Logf("Warning: Failed to list volumes for cleanup (deployment: %s): %v", deploymentID, err)
	} else {
		t.Logf("Found %d volume(s) for cleanup (deployment: %s)", len(volumes.Volumes), deploymentID)
		for _, vol := range volumes.Volumes { // Use vol variable name
			t.Logf("Attempting to remove volume %s (deployment: %s)", vol.Name, deploymentID)
			err := cli.VolumeRemove(ctx, vol.Name, true) // Force remove
			if err != nil {
				if !client.IsErrNotFound(err) { // Check if already gone
					t.Logf("Warning: Failed to remove volume %s for cleanup (deployment: %s): %v", vol.Name, deploymentID, err)
				} else {
					t.Logf("Volume %s already removed (deployment: %s)", vol.Name, deploymentID)
				}
			} else {
				t.Logf("Successfully removed volume %s (deployment: %s)", vol.Name, deploymentID)
			}
		}
	}
	t.Logf("Finished cleanup for deployment: %s", deploymentID)
}

// Helper function to check container status
func assertContainerCountAndStatus(t *testing.T, manager docker_internal.Manager, deploymentID string, expectedCount int, expectedStatus string) {
	t.Helper()
	ctx := context.Background()
	cli := getDockerClient(t, manager) // Use cli variable name
	projectLabel := fmt.Sprintf("com.docker.compose.project=%s", deploymentID)

	// Retry mechanism for eventual consistency
	var containers []types.Container // Use types.Container
	var err error
	// Increased retries and timeout for potentially slow CI environments
	for i := 0; i < 15; i++ { // Retry up to 15 times (e.g., 15 seconds total)
		containers, err = cli.ContainerList(ctx, container.ListOptions{ // Use container.ListOptions
			All: true, // Include stopped containers if expectedStatus is "exited" or similar
			Filters: filters.NewArgs(
				filters.Arg("label", projectLabel),
			),
		})
		require.NoError(t, err, "Failed to list containers for assertion")

		// Filter containers by expected status if provided
		actualMatchingStatusCount := 0
		for _, c := range containers {
			// Docker state can be complex (e.g., "running", "exited (0)", "restarting")
			// Use Contains for broader matching, especially for "running" or "exited"
			if expectedStatus != "" && strings.Contains(strings.ToLower(c.State), strings.ToLower(expectedStatus)) {
				actualMatchingStatusCount++
			}
		}

		countToCheck := len(containers)
		if expectedStatus != "" {
			countToCheck = actualMatchingStatusCount
		}

		if countToCheck == expectedCount {
			// If count matches, verify status if needed
			if expectedStatus != "" {
				for _, c := range containers {
					assert.Contains(t, strings.ToLower(c.State), strings.ToLower(expectedStatus), "Container %s has unexpected state %s (expected to contain %s)", c.Names[0], c.State, expectedStatus)
				}
			}
			return // Success
		}

		t.Logf("Container count/status mismatch for %s. Expected %d (%s), got %d total, %d matching status. Retrying...", deploymentID, expectedCount, expectedStatus, len(containers), actualMatchingStatusCount)
		time.Sleep(1 * time.Second)
	}

	// If loop finishes without success, fail the test
	// Log final container states for debugging
	finalStates := []string{}
	for _, c := range containers {
		finalStates = append(finalStates, fmt.Sprintf("%s: %s", c.Names[0], c.State))
	}
	t.Logf("Final container states for %s: %v", deploymentID, finalStates)

	finalMatchingCount := 0
	if expectedStatus != "" {
		for _, c := range containers {
			if strings.Contains(strings.ToLower(c.State), strings.ToLower(expectedStatus)) {
				finalMatchingCount++
			}
		}
		require.Equal(t, expectedCount, finalMatchingCount, "Unexpected number of containers in state '%s' for deployment %s after retries", expectedStatus, deploymentID)
	} else {
		// If no specific status expected, just check the total count
		require.Len(t, containers, expectedCount, "Unexpected number of containers found for deployment %s after retries", deploymentID)
	}

	// Final assertion on state for clarity if expectedStatus was provided
	if expectedStatus != "" {
		for _, c := range containers {
			assert.Contains(t, strings.ToLower(c.State), strings.ToLower(expectedStatus), "Container %s has unexpected state %s (expected to contain %s)", c.Names[0], c.State, expectedStatus)
		}
	}
}

// sendComposeUpRequest sends a JSON request to the /compose/up endpoint
func sendComposeUpRequest(t *testing.T, ts *testServer, token, projectName, composeContent string) (*http.Response, string) {
	t.Helper()

	// Create request body
	upReq := models.ComposeUpRequest{
		ProjectName:        projectName,
		ComposeFileContent: composeContent,
		// Add other options if needed, e.g., ForceRecreate: true
	}
	bodyBytes, err := json.Marshal(upReq)
	require.NoError(t, err)
	body := bytes.NewBuffer(bodyBytes)

	// Create request
	req, err := http.NewRequest("POST", ts.HttpServer.URL+"/api/v1/compose/up", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json") // Set correct Content-Type
	req.Header.Set("Authorization", "Bearer "+token)

	// Send request
	httpClient := &http.Client{
		Timeout: 60 * time.Second, // Increased timeout
	}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)

	// Read body to allow reuse and check response structure
	respBodyBytes, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	resp.Body.Close()                                        // Close original body
	resp.Body = io.NopCloser(bytes.NewBuffer(respBodyBytes)) // Replace body for further reading

	// The /up endpoint returns 202 Accepted with a simple message in the 'data' field.
	// The actual deployment ID is the project name we sent.
	if resp.StatusCode == http.StatusAccepted {
		var respData utils.Response // Use the standard utils.Response struct
		err = json.Unmarshal(respBodyBytes, &respData)
		if err != nil {
			t.Logf("Could not unmarshal StatusAccepted response for /up: %v", err)
		} else {
			// Optionally check the message if needed
			if msgData, ok := respData.Data.(map[string]interface{}); ok {
				t.Logf("Received message from /up: %v", msgData["message"])
			}
		}
		// Return the projectName as the effective deployment ID
		return resp, projectName
	}

	// Handle other status codes or errors
	t.Logf("API request to /up failed with status %d. Response: %s", resp.StatusCode, string(respBodyBytes))
	// Return empty string for deploymentID on failure
	return resp, ""
}
