package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	networktypes "github.com/docker/docker/api/types/network"       // Added for EndpointSettings
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Keep internal import
)

// NetworkListOptions represents options for listing networks
type NetworkListOptions struct {
	Filters map[string][]string
}

// buildQueryParams converts network list options to URL query parameters
func buildNetworkListQueryParams(options *NetworkListOptions) url.Values {
	query := url.Values{}

	if options == nil {
		return query
	}

	if len(options.Filters) > 0 {
		filters, err := json.Marshal(options.Filters)
		if err == nil {
			query.Set("filters", string(filters))
		}
	}

	return query
}

// ListNetworks lists networks with optional filters
func (c *APIClient) ListNetworks(ctx context.Context, filters map[string]string) ([]models.Network, error) { // Already using models.Network
	// Convert simple filters map to the expected format
	options := &NetworkListOptions{}
	if len(filters) > 0 {
		options.Filters = make(map[string][]string)
		for k, v := range filters {
			options.Filters[k] = []string{v}
		}
	}

	// Build query params
	query := buildNetworkListQueryParams(options)
	url := c.buildURL(APIPathNetworks)
	if len(query) > 0 {
		url += "?" + query.Encode()
	}

	// Create request
	req, err := c.newRequest(ctx, http.MethodGet, APIPathNetworks, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create list networks request: %w", err)
	}

	// Add query parameters
	req.URL.RawQuery = query.Encode()

	// Execute request
	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list networks request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var networks []models.Network // Already using models.Network
	if err := c.handleResponse(resp, &networks); err != nil {
		return nil, fmt.Errorf("failed to parse networks response: %w", err)
	}

	return networks, nil
}

// GetNetwork gets detailed information about a network
func (c *APIClient) GetNetwork(ctx context.Context, id string) (*models.Network, error) { // Already using models.Network
	if id == "" {
		return nil, fmt.Errorf("network ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s", APIPathNetworks, id)

	var network models.Network // Already using models.Network
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &network); err != nil {
		return nil, fmt.Errorf("failed to get network: %w", err)
	}

	return &network, nil
}

// CreateNetwork creates a new network
func (c *APIClient) CreateNetwork(ctx context.Context, options *models.NetworkCreateRequest) (*models.Network, error) { // Use models.NetworkCreateRequest
	if options == nil {
		return nil, fmt.Errorf("network create options cannot be nil")
	}

	// Validate options
	if options.Name == "" {
		return nil, fmt.Errorf("network name cannot be empty")
	}

	var network models.Network // Already using models.Network
	if err := c.doRequest(ctx, http.MethodPost, APIPathNetworks, options, &network); err != nil {
		return nil, fmt.Errorf("failed to create network: %w", err)
	}

	return &network, nil
}

// RemoveNetwork removes a network
func (c *APIClient) RemoveNetwork(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("network ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s", APIPathNetworks, id)

	if err := c.doRequest(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return fmt.Errorf("failed to remove network: %w", err)
	}

	return nil
}

// ConnectContainerToNetwork connects a container to a network
func (c *APIClient) ConnectContainerToNetwork(ctx context.Context, networkID, containerID string, config *networktypes.EndpointSettings) error { // Use SDK type
	if networkID == "" {
		return fmt.Errorf("network ID cannot be empty")
	}

	if containerID == "" {
		return fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/connect", APIPathNetworks, networkID)

	// Create request body using SDK type
	connectConfig := struct {
		Container      string                         `json:"Container"`
		EndpointConfig *networktypes.EndpointSettings `json:"EndpointConfig,omitempty"` // Use SDK type
	}{
		Container:      containerID,
		EndpointConfig: config,
	}

	if err := c.doRequest(ctx, http.MethodPost, path, connectConfig, nil); err != nil {
		return fmt.Errorf("failed to connect container to network: %w", err)
	}

	return nil
}

// DisconnectContainerFromNetwork disconnects a container from a network
func (c *APIClient) DisconnectContainerFromNetwork(ctx context.Context, networkID, containerID string, force bool) error {
	if networkID == "" {
		return fmt.Errorf("network ID cannot be empty")
	}

	if containerID == "" {
		return fmt.Errorf("container ID cannot be empty")
	}

	path := fmt.Sprintf("%s/%s/disconnect", APIPathNetworks, networkID)

	// Create request body
	disconnectConfig := struct {
		Container string `json:"Container"`
		Force     bool   `json:"Force"`
	}{
		Container: containerID,
		Force:     force,
	}

	if err := c.doRequest(ctx, http.MethodPost, path, disconnectConfig, nil); err != nil {
		return fmt.Errorf("failed to disconnect container from network: %w", err)
	}

	return nil
}

// PruneNetworks removes unused networks
func (c *APIClient) PruneNetworks(ctx context.Context, filters map[string]string) (uint64, error) {
	path := fmt.Sprintf("%s/prune", APIPathNetworks)

	// Convert simple filters map to the expected format
	if len(filters) > 0 {
		filtersMap := make(map[string][]string)
		for k, v := range filters {
			filtersMap[k] = []string{v}
		}

		filtersJSON, err := json.Marshal(filtersMap)
		if err == nil {
			query := url.Values{}
			query.Set("filters", string(filtersJSON))
			path += "?" + query.Encode()
		}
	}

	// Send request
	var pruneResponse struct {
		NetworksDeleted []string `json:"NetworksDeleted"`
	}

	if err := c.doRequest(ctx, http.MethodPost, path, nil, &pruneResponse); err != nil {
		return 0, fmt.Errorf("failed to prune networks: %w", err)
	}

	return uint64(len(pruneResponse.NetworksDeleted)), nil
}

// InspectNetwork gets detailed information about a network
// This is an alias for GetNetwork for Docker CLI compatibility
func (c *APIClient) InspectNetwork(ctx context.Context, id string) (*models.Network, error) { // Already using models.Network
	return c.GetNetwork(ctx, id)
}

// GetContainerNetworks gets all networks a container is connected to
func (c *APIClient) GetContainerNetworks(ctx context.Context, containerID string) ([]models.Network, error) { // Already using models.Network
	if containerID == "" {
		return nil, fmt.Errorf("container ID cannot be empty")
	}

	// Get container details (Assuming GetContainer returns *models.DockerContainer or similar with NetworkSettings)
	// If GetContainer returns models.Container, this needs adjustment based on models.Container structure
	containerDetails, err := c.GetContainer(ctx, containerID) // Use a different var name to avoid confusion if GetContainer returns models.Container
	if err != nil {
		return nil, fmt.Errorf("failed to get container details: %w", err)
	}
	if containerDetails == nil {
		return nil, fmt.Errorf("container details not found for ID: %s", containerID)
	}

	// Extract network IDs from the Networks field (JSONMap)
	var networkIDs []string
	// Check if Networks map exists before ranging (using models.Container now)
	if containerDetails.Networks != nil { // Assuming models.Container has Networks field
		for networkName := range containerDetails.Networks { // Iterate over the Networks JSONMap
			networkIDs = append(networkIDs, networkName)
		}
	} else {
		// Handle case where network settings are not available
		// Depending on requirements, return empty list or an error
		return []models.Network{}, nil // Return empty list if no networks found (Already using models.Network)
	}

	// Get details for each network
	var networks []models.Network // Already using models.Network
	for _, networkID := range networkIDs {
		network, err := c.GetNetwork(ctx, networkID)
		if err != nil {
			// Log error but continue
			fmt.Printf("Failed to get network %s: %v\n", networkID, err)
			continue
		}
		networks = append(networks, *network)
	}

	return networks, nil
}

// UpdateNetwork updates a network's configuration
func (c *APIClient) UpdateNetwork(ctx context.Context, id string, options *models.NetworkUpdateOptions) error { // Already using models.NetworkUpdateOptions
	if id == "" {
		return fmt.Errorf("network ID cannot be empty")
	}

	if options == nil {
		return fmt.Errorf("network update options cannot be nil")
	}

	path := fmt.Sprintf("%s/%s", APIPathNetworks, id)

	if err := c.doRequest(ctx, http.MethodPut, path, options, nil); err != nil {
		return fmt.Errorf("failed to update network: %w", err)
	}

	return nil
}

// CreateMacvlan creates a new Macvlan network
func (c *APIClient) CreateMacvlan(ctx context.Context, name, parent string, subnet, gateway string) (*models.Network, error) { // Already using models.Network
	if name == "" {
		return nil, fmt.Errorf("network name cannot be empty")
	}

	if parent == "" {
		return nil, fmt.Errorf("parent interface cannot be empty")
	}

	// Create network options using models.NetworkCreateRequest
	options := &models.NetworkCreateRequest{
		Name:   name,
		Driver: "macvlan",
		IPAM: &models.IPAMCreateRequest{ // Use IPAMCreateRequest
			Driver: "default",
		},
		Options: map[string]string{
			"parent": parent,
		},
	}

	// Add subnet and gateway if provided
	if subnet != "" {
		config := models.IPAMConfigRequest{ // Use IPAMConfigRequest
			Subnet: subnet,
		}

		if gateway != "" {
			config.Gateway = gateway
		}

		options.IPAM.Config = []models.IPAMConfigRequest{config} // Use IPAMConfigRequest
	}

	return c.CreateNetwork(ctx, options)
}

// CreateOverlay creates a new overlay network
func (c *APIClient) CreateOverlay(ctx context.Context, name string, attachable bool, subnet, gateway string) (*models.Network, error) { // Already using models.Network
	if name == "" {
		return nil, fmt.Errorf("network name cannot be empty")
	}

	// Create network options using models.NetworkCreateRequest
	options := &models.NetworkCreateRequest{
		Name:       name,
		Driver:     "overlay",
		Attachable: attachable,
		IPAM: &models.IPAMCreateRequest{ // Use IPAMCreateRequest
			Driver: "default",
		},
	}

	// Add subnet and gateway if provided
	if subnet != "" {
		config := models.IPAMConfigRequest{ // Use IPAMConfigRequest
			Subnet: subnet,
		}

		if gateway != "" {
			config.Gateway = gateway
		}

		options.IPAM.Config = []models.IPAMConfigRequest{config} // Use IPAMConfigRequest
	}

	return c.CreateNetwork(ctx, options)
}

// IsNetworkExist checks if a network with the given ID or name exists
func (c *APIClient) IsNetworkExist(ctx context.Context, idOrName string) (bool, error) {
	if idOrName == "" {
		return false, fmt.Errorf("network ID or name cannot be empty")
	}

	// Try to get network directly
	_, err := c.GetNetwork(ctx, idOrName)
	if err == nil {
		return true, nil
	}

	// If error is not "not found", return the error
	if !strings.Contains(err.Error(), "not found") {
		return false, err
	}

	// If network wasn't found by ID, try to find by name
	networks, err := c.ListNetworks(ctx, map[string]string{
		"name": idOrName,
	})
	if err != nil {
		return false, err
	}

	return len(networks) > 0, nil
}
