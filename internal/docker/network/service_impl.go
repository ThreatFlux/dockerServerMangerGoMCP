package network

import (
	"context"
	"fmt"

	networktypes "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/errdefs" // Import errdefs for IsNotFound
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Added for toNetworkModel
)

// serviceImpl implements the network.Service interface
type serviceImpl struct {
	dockerManager docker.Manager
	logger        *logrus.Logger
}

// NewService creates a new network service implementation
func NewService(dockerManager docker.Manager, logger *logrus.Logger) Service {
	if logger == nil {
		logger = logrus.New()
	}
	return &serviceImpl{
		dockerManager: dockerManager,
		logger:        logger,
	}
}

// Get gets a network by ID or name
// TODO: Implement Get
func (s *serviceImpl) Get(ctx context.Context, idOrName string, options GetOptions) (*models.Network, error) {
	s.logger.WithField("idOrName", idOrName).Warn("Get network not implemented")
	// Implementation idea:
	// 1. Call InspectRaw to get the raw details.
	// 2. Convert the raw details using toNetworkModel.
	// 3. Handle errors (e.g., not found).
	rawNet, err := s.InspectRaw(ctx, idOrName) // Reuse InspectRaw
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("%w: network %s", ErrNetworkNotFound, idOrName) // Wrap specific error
		}
		return nil, fmt.Errorf("failed to inspect network %s: %w", idOrName, err) // General inspect error
	}
	return toNetworkModel(rawNet), nil
	// return nil, fmt.Errorf("Get network not implemented") // Keep stub for now
}

// List returns a list of Docker networks
func (s *serviceImpl) List(ctx context.Context, options ListOptions) ([]*models.Network, error) { // Changed return type
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err) // Return nil for slice
	}

	listOpts := networktypes.ListOptions{Filters: options.Filters}

	s.logger.WithField("filters", listOpts.Filters).Debug("Listing networks")
	networks, err := cli.NetworkList(ctx, listOpts)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list networks from Docker API")
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	s.logger.WithField("count", len(networks)).Debug("Successfully listed networks")

	// Convert summaries to models (requires inspecting each network)
	// This might be inefficient; consider if the interface should return summaries
	// or if the controller should handle inspection based on summaries.
	// For now, let's inspect each one to fulfill the interface contract.
	modelNetworks := make([]*models.Network, 0, len(networks))
	for _, netSummary := range networks {
		inspectedNet, inspectErr := s.Inspect(ctx, netSummary.ID)
		if inspectErr != nil {
			s.logger.WithError(inspectErr).WithField("networkID", netSummary.ID).Warn("Failed to inspect network during list conversion")
			continue // Skip this network if inspection fails
		}
		modelNetworks = append(modelNetworks, toNetworkModel(inspectedNet))
	}

	return modelNetworks, nil
}

// Inspect returns detailed information about a network
func (s *serviceImpl) Inspect(ctx context.Context, networkID string) (networktypes.Inspect, error) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return networktypes.Inspect{}, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	inspectOpts := networktypes.InspectOptions{Verbose: true} // Get detailed info

	s.logger.WithField("networkID", networkID).Debug("Inspecting network")
	network, err := cli.NetworkInspect(ctx, networkID, inspectOpts)
	if err != nil {
		s.logger.WithError(err).WithField("networkID", networkID).Error("Failed to inspect network")
		// TODO: Wrap common errors like not found
		return networktypes.Inspect{}, fmt.Errorf("failed to inspect network %s: %w", networkID, err)
	}

	s.logger.WithField("networkID", networkID).Debug("Network inspected successfully")
	return network, nil
}

// Create creates a new Docker network
func (s *serviceImpl) Create(ctx context.Context, name string, options CreateOptions) (*models.Network, error) { // Updated signature
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker_test client: %w", err) // Return nil for pointer
	}

	createOpts := networktypes.CreateOptions{
		// Name field removed as it's passed separately
		Driver:     options.Driver,
		Internal:   options.Internal,
		Attachable: options.Attachable,
		Ingress:    options.Ingress,
		EnableIPv6: &options.EnableIPv6, // Pass pointer
		IPAM:       options.IPAM,
		Options:    options.Options,
		Labels:     options.Labels,
	}

	s.logger.WithFields(logrus.Fields{
		"name":   name, // Use name argument
		"driver": options.Driver,
	}).Info("Creating network")

	response, err := cli.NetworkCreate(ctx, name, createOpts) // Use name argument
	if err != nil {
		s.logger.WithError(err).WithField("name", name).Error("Failed to create network") // Use name argument
		return nil, fmt.Errorf("failed to create network %s: %w", name, err)              // Return nil for pointer
	}

	s.logger.WithField("name", name).WithField("id", response.ID).Info("Network created successfully") // Use name argument

	// Inspect the created network to get full details for the model
	networkDetails, inspectErr := s.Inspect(ctx, response.ID)
	if inspectErr != nil {
		// Log the error but still return a basic model if creation succeeded
		s.logger.WithError(inspectErr).WithField("networkID", response.ID).Warn("Failed to inspect network after creation")
		// Create a minimal model based on creation response
		return &models.Network{
			DockerResource: models.DockerResource{Name: name},
			NetworkID:      response.ID,
			Driver:         options.Driver, // Use driver from options
			// Other fields will be zero/default
		}, nil
	}

	// Convert the inspected details to the model
	return toNetworkModel(networkDetails), nil
}

// Remove removes a Docker network
func (s *serviceImpl) Remove(ctx context.Context, networkID string, options RemoveOptions) error { // Added options parameter
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	s.logger.WithField("networkID", networkID).Info("Removing network")
	err = cli.NetworkRemove(ctx, networkID)
	if err != nil {
		s.logger.WithError(err).WithField("networkID", networkID).Error("Failed to remove network")
		// TODO: Wrap common errors like not found or in use
		return fmt.Errorf("failed to remove network %s: %w", networkID, err)
	}

	s.logger.WithField("networkID", networkID).Info("Network removed successfully")
	return nil
}

// Connect connects a container to a network
func (s *serviceImpl) Connect(ctx context.Context, networkID, containerID string, options ConnectOptions) error {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	// Use EndpointConfig directly from options if provided
	endpointSettings := options.EndpointConfig
	if endpointSettings == nil {
		// Create a default if not provided (or handle error if required)
		endpointSettings = &networktypes.EndpointSettings{}
	}

	s.logger.WithFields(logrus.Fields{
		"networkID":   networkID,
		"containerID": containerID,
	}).Info("Connecting container to network")

	err = cli.NetworkConnect(ctx, networkID, containerID, endpointSettings)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"networkID":   networkID,
			"containerID": containerID,
		}).Error("Failed to connect container to network")
		// TODO: Wrap specific errors
		return fmt.Errorf("failed to connect container %s to network %s: %w", containerID, networkID, err)
	}

	s.logger.WithFields(logrus.Fields{
		"networkID":   networkID,
		"containerID": containerID,
	}).Info("Container connected to network successfully")
	return nil
}

// Disconnect disconnects a container from a network
func (s *serviceImpl) Disconnect(ctx context.Context, networkID, containerID string, options DisconnectOptions) error { // Updated signature
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return fmt.Errorf("failed to get docker_test client: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"networkID":   networkID,
		"containerID": containerID,
		"force":       options.Force, // Use Force from options
	}).Info("Disconnecting container from network")

	err = cli.NetworkDisconnect(ctx, networkID, containerID, options.Force) // Use options.Force
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"networkID":   networkID,
			"containerID": containerID,
		}).Error("Failed to disconnect container from network")
		// TODO: Wrap specific errors
		return fmt.Errorf("failed to disconnect container %s from network %s: %w", containerID, networkID, err)
	}

	s.logger.WithFields(logrus.Fields{
		"networkID":   networkID,
		"containerID": containerID,
	}).Info("Container disconnected from network successfully")
	return nil
}

// Prune removes unused Docker networks
func (s *serviceImpl) Prune(ctx context.Context, options PruneOptions) (networktypes.PruneReport, error) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return networktypes.PruneReport{}, fmt.Errorf("failed to get docker_test client: %w", err)
	}

	s.logger.WithField("filters", options.Filters).Info("Pruning networks")
	report, err := cli.NetworksPrune(ctx, options.Filters)
	if err != nil {
		s.logger.WithError(err).Error("Failed to prune networks")
		return networktypes.PruneReport{}, fmt.Errorf("failed to prune networks: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"networks_deleted": len(report.NetworksDeleted),
	}).Info("Networks pruned successfully")
	return report, nil // Return the actual report on success
}

// InspectRaw gets the raw information about a network
func (s *serviceImpl) InspectRaw(ctx context.Context, idOrName string) (networktypes.Inspect, error) {
	cli, err := s.dockerManager.GetClient()
	if err != nil {
		return networktypes.Inspect{}, fmt.Errorf("failed to get docker_test client: %w", err)
	}
	return cli.NetworkInspect(ctx, idOrName, networktypes.InspectOptions{Verbose: true})
}

// GetNetworkDrivers returns the list of available network drivers
// TODO: Implement GetNetworkDrivers if needed, or remove from interface if unused
func (s *serviceImpl) GetNetworkDrivers(ctx context.Context) ([]string, error) {
	// Placeholder implementation
	s.logger.Warn("GetNetworkDrivers not fully implemented")
	// Example: Return common drivers or fetch dynamically if possible
	// This might require a different Docker API call or configuration inspection.
	return []string{"bridge", "host", "overlay", "macvlan", "none"}, fmt.Errorf("GetNetworkDrivers not implemented")
}

// FindNetworkByContainer finds networks connected to a container
// TODO: Implement FindNetworkByContainer
func (s *serviceImpl) FindNetworkByContainer(ctx context.Context, containerIDOrName string, options ListOptions) ([]*models.Network, error) {
	s.logger.WithField("containerID", containerIDOrName).Warn("FindNetworkByContainer not implemented")
	// Implementation idea:
	// 1. Inspect the container to get its NetworkSettings.Networks map.
	// 2. Iterate through the map keys (network IDs).
	// 3. For each network ID, inspect the network.
	// 4. Convert inspected networks to models.Network.
	// 5. Apply filters from ListOptions if necessary.
	return nil, fmt.Errorf("FindNetworkByContainer not implemented")
}

// FindNetworkByName finds networks by name pattern
// TODO: Implement FindNetworkByName
func (s *serviceImpl) FindNetworkByName(ctx context.Context, pattern string, options ListOptions) ([]*models.Network, error) {
	s.logger.WithField("pattern", pattern).Warn("FindNetworkByName not implemented")
	// Implementation idea:
	// 1. Add a 'name' filter with the pattern to options.Filters.
	// 2. Call the existing List method with the modified options.
	options.Filters.Add("name", pattern)
	return s.List(ctx, options) // Reuse List logic
	// return nil, fmt.Errorf("FindNetworkByName not implemented") // Keep stub for now
}

// FindNetworkBySubnet finds networks by subnet
// TODO: Implement FindNetworkBySubnet
func (s *serviceImpl) FindNetworkBySubnet(ctx context.Context, subnet string, options ListOptions) ([]*models.Network, error) {
	s.logger.WithField("subnet", subnet).Warn("FindNetworkBySubnet not implemented")
	// Implementation idea:
	// 1. List all networks (or use filters if possible, though direct subnet filter isn't standard).
	// 2. Inspect each network.
	// 3. Check if any IPAMConfig.Subnet matches the provided subnet.
	// 4. Collect matching networks.
	// 5. Apply other filters from ListOptions.
	return nil, fmt.Errorf("FindNetworkBySubnet not implemented")
}

// --- Helper Functions ---

// toNetworkModel converts Docker network inspect details to our internal model
func toNetworkModel(net networktypes.Inspect) *models.Network {
	createdAtTime := net.Created // Use directly

	// Convert IPAM config
	var ipamConfig []models.IPAMConfig
	if net.IPAM.Config != nil {
		ipamConfig = make([]models.IPAMConfig, len(net.IPAM.Config))
		for i, cfg := range net.IPAM.Config {
			ipamConfig[i] = models.IPAMConfig{
				Subnet:  cfg.Subnet,
				IPRange: cfg.IPRange,
				Gateway: cfg.Gateway,
				// AuxAddress field does not exist in source type
			}
		}
	}

	// Convert Containers map
	containersMap := make(models.JSONMap)
	if net.Containers != nil {
		for id, endpoint := range net.Containers {
			containersMap[id] = map[string]interface{}{
				"Name":        endpoint.Name,
				"EndpointID":  endpoint.EndpointID,
				"MacAddress":  endpoint.MacAddress,
				"IPv4Address": endpoint.IPv4Address,
				"IPv6Address": endpoint.IPv6Address,
			}
		}
	}

	// Convert Options map
	optionsMap := make(models.JSONMap)
	if net.Options != nil {
		for k, v := range net.Options {
			optionsMap[k] = v
		}
	}

	// Convert Labels map
	labelsMap := make(models.JSONMap)
	if net.Labels != nil {
		for k, v := range net.Labels {
			labelsMap[k] = v
		}
	}

	// Convert IPAM Options map
	ipamOptionsMap := make(models.JSONMap)
	if net.IPAM.Options != nil {
		for k, v := range net.IPAM.Options {
			ipamOptionsMap[k] = v
		}
	}

	return &models.Network{
		DockerResource: models.DockerResource{
			Name:   net.Name,
			Labels: labelsMap,
			// UserID needs to be set elsewhere if tracking ownership
		},
		NetworkID:   net.ID,
		Driver:      net.Driver,
		Scope:       net.Scope,
		Created:     createdAtTime,
		Internal:    net.Internal,
		EnableIPv6:  net.EnableIPv6,
		Attachable:  net.Attachable,
		Ingress:     net.Ingress,
		ConfigOnly:  net.ConfigOnly,
		Containers:  containersMap,
		Options:     optionsMap,
		IPAMOptions: ipamOptionsMap, // Assign converted IPAM options map
		// Also store IPAM driver and config within the map if needed, or adjust model
		// Example: ipamOptionsMap["Driver"] = net.IPAM.Driver
		// Example: ipamOptionsMap["Config"] = ipamConfig
		// IPAMOptions, Security, ConfigFrom might need specific handling if used
	}
}

// Helper function to convert map[string]string to models.JSONMap
func convertStringMapToJSONMap(input map[string]string) models.JSONMap {
	if input == nil {
		return nil
	}
	output := make(models.JSONMap, len(input))
	for k, v := range input {
		output[k] = v // JSONMap is map[string]interface{}, string is compatible
	}
	return output
}
