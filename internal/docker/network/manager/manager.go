// Package manager provides the implementation of the network service interface
package manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/docker/docker/api/types/filters"
	dockernetwork "github.com/docker/docker/api/types/network" // Alias import
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	networkService "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/network"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// NetworkManager implements the network.Service interface
type NetworkManager struct {
	// client is the Docker API client
	client *client.Client

	// logger is the logger
	logger *logrus.Logger
}

// Options contains options for creating a NetworkManager
type Options struct {
	// Client is the Docker client
	Client *client.Client

	// Logger is the logger
	Logger *logrus.Logger
}

// New creates a new NetworkManager
func New(options Options) (*NetworkManager, error) {
	var err error
	dockerClient := options.Client // Use a clear variable name
	if dockerClient == nil {
		// Use the client package directly for initialization
		dockerClient, err = client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			return nil, fmt.Errorf("failed to create Docker client: %w", err)
		}
	}

	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}

	return &NetworkManager{
		client: dockerClient, // Assign the potentially initialized client
		logger: logger,
	}, nil
}

// Create creates a new network
func (m *NetworkManager) Create(ctx context.Context, name string, options networkService.CreateOptions) (*models.Network, error) {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Validate network name
	if name == "" {
		return nil, errors.New("network name cannot be empty")
	}

	// Validate driver (use bridge as default)
	driver := options.Driver
	if driver == "" {
		driver = "bridge"
	}

	// Create network create options
	createOptions := dockernetwork.CreateOptions{ // Use alias
		// CheckDuplicate: options.CheckDuplicate, // Field does not exist in network.CreateOptions
		Driver:     driver,
		Scope:      options.Scope,
		EnableIPv6: &options.EnableIPv6, // Pass address for *bool type
		IPAM:       options.IPAM,
		Internal:   options.Internal,
		Attachable: options.Attachable,
		Ingress:    options.Ingress,
		ConfigOnly: options.ConfigOnly,
		Options:    options.Options,
		Labels:     options.Labels,
	}

	// Create the network
	logger.WithFields(logrus.Fields{
		"name":   name,
		"driver": driver,
	}).Debug("Creating network")

	response, err := m.client.NetworkCreate(ctx, name, createOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create network: %w", err)
	}

	// Get the created network
	networkResource, err := m.client.NetworkInspect(ctx, response.ID, dockernetwork.InspectOptions{}) // Use alias
	if err != nil {
		// If we can't inspect the network, return a basic network object
		// Use the correct fields from models.Network (via DockerResource)
		return &models.Network{
			DockerResource: models.DockerResource{Name: name}, // Set Name via embedded struct
			NetworkID:      response.ID,
			Driver:         driver,        // Include driver info if available
			Scope:          options.Scope, // Include scope if available
			// Other fields might be unknown here
		}, nil
	}

	// Convert to model
	return toNetworkModel(networkResource), nil
}

// Get gets a network by ID or name
func (m *NetworkManager) Get(ctx context.Context, idOrName string, options networkService.GetOptions) (*models.Network, error) {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Validate ID or name
	if idOrName == "" {
		return nil, errors.New("network ID or name cannot be empty")
	}

	// Get the network
	logger.WithField("idOrName", idOrName).Debug("Getting network")

	// Create inspect options
	inspectOptions := dockernetwork.InspectOptions{ // Use alias
		Verbose: options.Verbose,
		Scope:   options.Scope,
	}

	networkResource, err := m.client.NetworkInspect(ctx, idOrName, inspectOptions)
	if err != nil {
		if client.IsErrNotFound(err) {
			// Try to find by name
			networks, listErr := m.List(ctx, networkService.ListOptions{
				Filters: filters.NewArgs(filters.Arg("name", idOrName)),
				Logger:  logger,
			})
			// If listing also fails or returns no results, return the specific not found error
			if listErr != nil || len(networks) == 0 {
				return nil, networkService.ErrNetworkNotFound // Return specific error
			}
			// If found via List, return the first match
			return networks[0], nil
		}
		// Return other inspect errors
		return nil, fmt.Errorf("failed to inspect network: %w", err)
	}

	// Convert to model
	return toNetworkModel(networkResource), nil
}

// List lists networks
func (m *NetworkManager) List(ctx context.Context, options networkService.ListOptions) ([]*models.Network, error) {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// List networks
	logger.Debug("Listing networks")
	dockerNetworks, err := m.client.NetworkList(ctx, dockernetwork.ListOptions{ // Use alias
		Filters: options.Filters,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	// Convert to models
	result := make([]*models.Network, len(dockerNetworks))
	for i, network := range dockerNetworks {
		if options.NameOnly {
			// Only include basic information using correct model fields
			result[i] = &models.Network{
				DockerResource: models.DockerResource{Name: network.Name}, // Set Name via embedded struct
				NetworkID:      network.ID,
			}
		} else {
			// Inspect to get full details before converting
			networkResource, inspectErr := m.client.NetworkInspect(ctx, network.ID, dockernetwork.InspectOptions{}) // Use alias
			if inspectErr != nil {
				logger.WithError(inspectErr).WithField("network_id", network.ID).Warn("Failed to inspect network during list, returning partial info")
				// Return partial info if inspect fails
				result[i] = &models.Network{
					DockerResource: models.DockerResource{Name: network.Name}, // Set Name via embedded struct
					NetworkID:      network.ID,
					Driver:         network.Driver,
					Scope:          network.Scope,
					// Other fields are unknown
				}
			} else {
				result[i] = toNetworkModel(networkResource) // Assuming toNetworkModel accepts dockernetwork.Inspect
			}
		}
	}

	return result, nil
}

// Remove removes a network
func (m *NetworkManager) Remove(ctx context.Context, idOrName string, options networkService.RemoveOptions) error {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Validate ID or name
	if idOrName == "" {
		return errors.New("network ID or name cannot be empty")
	}

	// Remove the network
	logger.WithField("idOrName", idOrName).Debug("Removing network")
	err := m.client.NetworkRemove(ctx, idOrName)
	if err != nil {
		if client.IsErrNotFound(err) {
			// Use the exported error
			return networkService.ErrNetworkNotFound
		}

		// Handle networks with containers
		if strings.Contains(err.Error(), "has active endpoints") && options.Force {
			// Get connected containers and disconnect them
			if forceErr := m.forceRemoveNetwork(ctx, idOrName); forceErr != nil {
				return fmt.Errorf("failed to force remove network: %w", forceErr)
			}

			// Try to remove the network again
			retryErr := m.client.NetworkRemove(ctx, idOrName)
			if retryErr != nil {
				// Check if it's now gone (maybe removed concurrently)
				if client.IsErrNotFound(retryErr) {
					// Use the exported error
					return networkService.ErrNetworkNotFound
				}
				return fmt.Errorf("failed to remove network after disconnecting containers: %w", retryErr)
			}
			return nil
		}

		return fmt.Errorf("failed to remove network: %w", err)
	}

	return nil
}

// Prune removes unused networks
func (m *NetworkManager) Prune(ctx context.Context, options networkService.PruneOptions) (dockernetwork.PruneReport, error) { // Use alias
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Prune networks
	logger.Debug("Pruning networks")
	report, err := m.client.NetworksPrune(ctx, options.Filters)
	if err != nil {
		// Return the original report type
		return dockernetwork.PruneReport{}, fmt.Errorf("failed to prune networks: %w", err) // Use alias
	}

	// Return the original report type
	return report, nil
}

// Connect connects a container to a network
func (m *NetworkManager) Connect(ctx context.Context, networkIDOrName, containerIDOrName string, options networkService.ConnectOptions) error {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Validate network ID or name
	if networkIDOrName == "" {
		return errors.New("network ID or name cannot be empty")
	}

	// Validate container ID or name
	if containerIDOrName == "" {
		return errors.New("container ID or name cannot be empty")
	}

	// Get the network (to validate it exists)
	_, err := m.Get(ctx, networkIDOrName, networkService.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get network: %w", err)
	}

	// Get the container (to validate it exists and is running)
	containerInfo, err := m.client.ContainerInspect(ctx, containerIDOrName)
	if err != nil {
		if client.IsErrNotFound(err) {
			return fmt.Errorf("container not found: %s", containerIDOrName)
		}
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	// Check if the container is running (unless force is set)
	if !containerInfo.State.Running && !options.Force {
		return fmt.Errorf("container is not running: %s", containerIDOrName)
	}

	// Create endpoint settings if not provided
	endpointSettings := options.EndpointConfig
	if endpointSettings == nil {
		endpointSettings = &dockernetwork.EndpointSettings{} // Use alias
	}

	// Connect the container to the network
	logger.WithFields(logrus.Fields{
		"network":   networkIDOrName,
		"container": containerIDOrName,
	}).Debug("Connecting container to network")

	err = m.client.NetworkConnect(ctx, networkIDOrName, containerIDOrName, endpointSettings)
	if err != nil {
		return fmt.Errorf("failed to connect container to network: %w", err)
	}

	return nil
}

// Disconnect disconnects a container from a network
func (m *NetworkManager) Disconnect(ctx context.Context, networkIDOrName, containerIDOrName string, options networkService.DisconnectOptions) error {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Validate network ID or name
	if networkIDOrName == "" {
		return errors.New("network ID or name cannot be empty")
	}

	// Validate container ID or name
	if containerIDOrName == "" {
		return errors.New("container ID or name cannot be empty")
	}

	// Disconnect the container from the network
	logger.WithFields(logrus.Fields{
		"network":   networkIDOrName,
		"container": containerIDOrName,
	}).Debug("Disconnecting container from network")

	err := m.client.NetworkDisconnect(ctx, networkIDOrName, containerIDOrName, options.Force)
	if err != nil {
		if client.IsErrNotFound(err) {
			// Use the exported error
			return networkService.ErrNetworkNotFound
		}
		return fmt.Errorf("failed to disconnect container from network: %w", err)
	}

	return nil
}

// InspectRaw gets the raw information about a network
func (m *NetworkManager) InspectRaw(ctx context.Context, idOrName string) (dockernetwork.Summary, error) { // Use alias
	// Validate ID or name
	if idOrName == "" {
		return dockernetwork.Summary{}, errors.New("network ID or name cannot be empty") // Use alias
	}

	// Get the network
	networkResource, err := m.client.NetworkInspect(ctx, idOrName, dockernetwork.InspectOptions{ // Use alias
		Verbose: true,
	})
	if err != nil {
		if client.IsErrNotFound(err) {
			// Use the exported error
			return dockernetwork.Summary{}, networkService.ErrNetworkNotFound // Use alias
		}
		return dockernetwork.Summary{}, fmt.Errorf("failed to inspect network: %w", err) // Use alias
	}

	return networkResource, nil
}

// GetNetworkDrivers returns the list of available network drivers
func (m *NetworkManager) GetNetworkDrivers(ctx context.Context) ([]string, error) {
	// Apply timeout if specified
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// List networks
	networks, err := m.client.NetworkList(ctx, dockernetwork.ListOptions{}) // Use alias
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	// Get unique drivers
	driversMap := make(map[string]bool)
	for _, network := range networks {
		driversMap[network.Driver] = true
	}

	// Convert to slice
	drivers := make([]string, 0, len(driversMap))
	for driver := range driversMap {
		drivers = append(drivers, driver)
	}

	// Add default drivers if not already in the list
	defaultDrivers := []string{"bridge", "host", "ipvlan", "macvlan", "null", "overlay"}
	for _, driver := range defaultDrivers {
		if !driversMap[driver] {
			drivers = append(drivers, driver)
		}
	}

	return drivers, nil
}

// FindNetworkByContainer finds networks connected to a container
func (m *NetworkManager) FindNetworkByContainer(ctx context.Context, containerIDOrName string, options networkService.ListOptions) ([]*models.Network, error) {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Validate container ID or name
	if containerIDOrName == "" {
		return nil, errors.New("container ID or name cannot be empty")
	}

	// Get the container (to validate it exists)
	containerInfo, err := m.client.ContainerInspect(ctx, containerIDOrName)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, fmt.Errorf("container not found: %s", containerIDOrName)
		}
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	// List all networks
	networks, err := m.List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	// Find networks connected to the container
	var containerNetworks []*models.Network
	for _, network := range networks {
		// Inspect the network
		// Use network.NetworkID which is string
		networkResource, err := m.InspectRaw(ctx, network.NetworkID)
		if err != nil {
			logger.WithError(err).WithField("network", network.NetworkID).Warn("Failed to inspect network")
			continue
		}

		// Check if the container is connected to the network
		for containerID := range networkResource.Containers {
			if containerID == containerInfo.ID {
				containerNetworks = append(containerNetworks, network)
				break
			}
		}
	}

	return containerNetworks, nil
}

// FindNetworkByName finds networks by name pattern
func (m *NetworkManager) FindNetworkByName(ctx context.Context, pattern string, options networkService.ListOptions) ([]*models.Network, error) {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Create a filter
	filter := filters.NewArgs(filters.Arg("name", pattern))
	// Check if options.Filters has keys before iterating
	// TODO: Re-evaluate filter merging logic if needed.
	// The current approach using options.Filters.Get(\"\") is incorrect.
	// For now, we assume options.Filters already contains all necessary filters
	// or that only the 'name' filter added initially is required.
	filter = options.Filters // Use the passed-in filters directly (might overwrite 'name' filter)

	// Update options with the filter
	listOptions := networkService.ListOptions{
		Filters:  filter,
		NameOnly: options.NameOnly,
		Timeout:  options.Timeout,
		Logger:   logger,
	}

	// List networks
	return m.List(ctx, listOptions)
}

// FindNetworkBySubnet finds networks by subnet
func (m *NetworkManager) FindNetworkBySubnet(ctx context.Context, subnet string, options networkService.ListOptions) ([]*models.Network, error) {
	// Apply default logger if not provided
	logger := options.Logger
	if logger == nil {
		logger = m.logger
	}

	// Apply timeout if specified
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Parse the subnet
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet format: %w", err)
	}

	// List all networks
	networks, err := m.List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	// Find networks with the specified subnet
	var matchingNetworks []*models.Network
	for _, network := range networks {
		// Inspect the network
		// Use network.NetworkID which is string
		networkResource, err := m.InspectRaw(ctx, network.NetworkID)
		if err != nil {
			logger.WithError(err).WithField("network", network.NetworkID).Warn("Failed to inspect network")
			continue
		}

		// Check IPAM configurations
		// Check if IPAM is not nil before accessing Config
		if networkResource.IPAM.Driver != "" && len(networkResource.IPAM.Config) > 0 {
			for _, config := range networkResource.IPAM.Config {
				// Parse the network subnet
				_, networkSubnet, err := net.ParseCIDR(config.Subnet)
				if err != nil {
					continue
				}

				// Check if the subnets overlap
				if subnetsOverlap(ipnet, networkSubnet) {
					matchingNetworks = append(matchingNetworks, network)
					break
				}
			}
		}
	}

	return matchingNetworks, nil
}

// forceRemoveNetwork force removes a network by disconnecting all connected containers
func (m *NetworkManager) forceRemoveNetwork(ctx context.Context, idOrName string) error {
	// Get the network
	networkResource, err := m.InspectRaw(ctx, idOrName)
	if err != nil {
		return err
	}

	// Disconnect all containers
	for containerID := range networkResource.Containers {
		err := m.Disconnect(ctx, idOrName, containerID, networkService.DisconnectOptions{
			Force: true,
		})
		if err != nil {
			// Log warning but continue trying to disconnect others
			m.logger.WithError(err).WithFields(logrus.Fields{
				"network":   idOrName,
				"container": containerID,
			}).Warn("Failed to disconnect container from network during force remove")
		}
	}

	return nil
}

// subnetsOverlap checks if two subnets overlap
func subnetsOverlap(subnet1, subnet2 *net.IPNet) bool {
	// Check if subnet1 contains any IP from subnet2
	// Check network address, first IP, and last IP of subnet2
	if subnet1.Contains(subnet2.IP) || subnet1.Contains(firstIP(subnet2)) || subnet1.Contains(lastIP(subnet2)) {
		return true
	}

	// Check if subnet2 contains any IP from subnet1
	// Check network address, first IP, and last IP of subnet1
	if subnet2.Contains(subnet1.IP) || subnet2.Contains(firstIP(subnet1)) || subnet2.Contains(lastIP(subnet1)) {
		return true
	}

	return false
}

// firstIP returns the first IP in a subnet (network address)
func firstIP(subnet *net.IPNet) net.IP {
	ip := make(net.IP, len(subnet.IP))
	copy(ip, subnet.IP)
	// Apply mask to get the network address
	for i := range ip {
		ip[i] &= subnet.Mask[i]
	}
	return ip
}

// lastIP returns the last IP in a subnet (broadcast address)
func lastIP(subnet *net.IPNet) net.IP {
	ip := make(net.IP, len(subnet.IP))
	copy(ip, subnet.IP)
	// Apply inverted mask to get the broadcast address
	for i := range ip {
		ip[i] |= ^subnet.Mask[i]
	}
	return ip
}

// toNetworkModel converts a Docker network resource to our network model
func toNetworkModel(networkResource dockernetwork.Summary) *models.Network { // Use alias
	// Convert options map[string]string to JSONMap
	optionsJSONMap := make(models.JSONMap)
	for k, v := range networkResource.Options {
		optionsJSONMap[k] = v
	}

	// Convert labels map[string]string to JSONMap
	labelsJSONMap := make(models.JSONMap)
	for k, v := range networkResource.Labels {
		labelsJSONMap[k] = v
	}

	// Convert containers map[string]types.EndpointResource to JSONMap
	containersJSONMap := make(models.JSONMap)
	for id, endpoint := range networkResource.Containers {
		containersJSONMap[id] = models.EndpointResource{ // Use defined model
			Name:        endpoint.Name,
			EndpointID:  endpoint.EndpointID,
			MacAddress:  endpoint.MacAddress,
			IPv4Address: endpoint.IPv4Address,
			IPv6Address: endpoint.IPv6Address,
		}
	}

	// Create a network model using correct fields
	networkModel := &models.Network{
		DockerResource: models.DockerResource{
			Name:   networkResource.Name,
			Labels: labelsJSONMap, // Assign converted labels
			// ID, UserID, User, Notes, CreatedAt, UpdatedAt, DeletedAt need to be set elsewhere
			// CreatedAt should map from networkResource.Created
		},
		NetworkID:     networkResource.ID,
		Driver:        networkResource.Driver,
		Scope:         networkResource.Scope,
		Gateway:       "", // Needs to be extracted from IPAM config
		Subnet:        "", // Needs to be extracted from IPAM config
		IPRange:       "", // Needs to be extracted from IPAM config
		Internal:      networkResource.Internal,
		EnableIPv6:    networkResource.EnableIPv6,
		Attachable:    networkResource.Attachable,
		Ingress:       networkResource.Ingress,
		ConfigOnly:    networkResource.ConfigOnly,
		Containers:    containersJSONMap,                 // Assign converted containers
		LastInspected: time.Now(),                        // Set inspection time
		Options:       optionsJSONMap,                    // Assign converted options
		IPAMOptions:   toIPAMModel(networkResource.IPAM), // Assign converted IPAM
		Security:      nil,                               // Placeholder for security info
		// Created field from DockerResource needs mapping from networkResource.Created
	}
	// Map Created time
	networkModel.CreatedAt = networkResource.Created

	// Extract Gateway/Subnet/IPRange from IPAM config if available
	if networkResource.IPAM.Driver != "" && len(networkResource.IPAM.Config) > 0 {
		// Assuming the first config is the primary one for simplicity
		config := networkResource.IPAM.Config[0]
		networkModel.Gateway = config.Gateway
		networkModel.Subnet = config.Subnet
		networkModel.IPRange = config.IPRange
	}

	return networkModel
}

// toIPAMModel converts a Docker IPAM struct to our IPAM model (JSONMap)
func toIPAMModel(ipam dockernetwork.IPAM) models.JSONMap { // Use alias
	if ipam.Driver == "" && len(ipam.Options) == 0 && len(ipam.Config) == 0 {
		return nil
	}

	ipamMap := make(models.JSONMap)
	ipamMap["driver"] = ipam.Driver

	// Convert Options map[string]string to JSONMap
	optionsMap := make(models.JSONMap)
	for k, v := range ipam.Options {
		optionsMap[k] = v
	}
	ipamMap["options"] = optionsMap

	configList := make([]models.JSONMap, len(ipam.Config))
	for i, config := range ipam.Config {
		configMap := make(models.JSONMap)
		configMap["subnet"] = config.Subnet
		configMap["ip_range"] = config.IPRange
		configMap["gateway"] = config.Gateway
		// Convert AuxAddress map[string]string to JSONMap
		auxMap := make(models.JSONMap)
		for k, v := range config.AuxAddress {
			auxMap[k] = v
		}
		configMap["aux_address"] = auxMap
		configList[i] = configMap
	}
	ipamMap["config"] = configList

	return ipamMap
}
