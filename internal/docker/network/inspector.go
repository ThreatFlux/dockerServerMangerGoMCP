// Package network provides functionality for Docker network management
package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/docker/docker/api/types/filters"              // Standard alias 'filters'
	networktypes "github.com/docker/docker/api/types/network" // Changed alias to networktypes
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// Inspector provides functionality for listing and inspecting networks
type Inspector struct {
	client   client.APIClient
	logger   *logrus.Logger
	throttle *utils.Throttle
}

// NewInspector creates a new network inspector
func NewInspector(client client.APIClient, logger *logrus.Logger) *Inspector {
	if logger == nil {
		logger = logrus.New()
	}

	return &Inspector{
		client:   client,
		logger:   logger,
		throttle: utils.NewThrottle(100, time.Second), // Rate limit to 100 operations per second
	}
}

// InspectionOptions defines options for listing and inspecting networks
type InspectionOptions struct {
	IncludeAll            bool              `json:"include_all"`
	IncludeDriver         string            `json:"include_driver"`
	IncludeSystemNetworks bool              `json:"include_system_networks"`
	IncludeDetailed       bool              `json:"include_detailed"`
	FilterLabels          map[string]string `json:"filter_labels"`
	FilterNames           []string          `json:"filter_names"`
	FilterIDs             []string          `json:"filter_ids"`
	FilterContainers      []string          `json:"filter_containers"`
	FilterScope           string            `json:"filter_scope"`
	FilterSubnet          string            `json:"filter_subnet"`
	FilterIPv6            bool              `json:"filter_ipv6"`
	FilterInternal        bool              `json:"filter_internal"`
	FilterBuiltin         bool              `json:"filter_builtin"`
	Limit                 int               `json:"limit"`
	Offset                int               `json:"offset"`
	SortBy                string            `json:"sort_by"`
	SortDescending        bool              `json:"sort_descending"`
	Timeout               int               `json:"timeout"`
}

// GetNetworks lists networks with filtering options
func (i *Inspector) GetNetworks(ctx context.Context, opts InspectionOptions) ([]*models.Network, error) {
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.Timeout)*time.Second)
		defer cancel()
	}

	filterArgs := i.createFilterArgs(opts) // Uses filters alias internally

	if err := i.throttle.Wait(ctx); err != nil {
		return nil, fmt.Errorf("throttle error: %w", err)
	}

	// Use networktypes.ListOptions
	networkList, err := i.client.NetworkList(ctx, networktypes.ListOptions{ // Use new alias
		Filters: filterArgs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	if !opts.IncludeSystemNetworks {
		networkList = i.filterSystemNetworks(networkList)
	}

	if opts.FilterSubnet != "" {
		networkList, err = i.filterBySubnet(ctx, networkList, opts.FilterSubnet)
		if err != nil {
			return nil, fmt.Errorf("failed to filter networks by subnet: %w", err)
		}
	}

	if len(opts.FilterNames) > 0 && !i.hasFilterArg(filterArgs, "name") {
		networkList = i.filterByNameRegex(networkList, opts.FilterNames)
	}

	// Apply pagination (after filtering, before detailed inspection)
	totalItems := len(networkList)
	start := opts.Offset
	end := totalItems
	if start < 0 {
		start = 0
	}
	if start > totalItems {
		start = totalItems
	}
	if opts.Limit > 0 {
		end = start + opts.Limit
		if end > totalItems {
			end = totalItems
		}
	}
	// Ensure start and end are within bounds after calculation
	if start > end {
		start = end
	}
	paginatedList := networkList[start:end]

	var networks []*models.Network
	for _, n := range paginatedList { // Iterate over paginated list
		if opts.IncludeDetailed {
			detailedNetwork, err := i.GetNetwork(ctx, n.ID, opts)
			if err != nil {
				i.logger.WithFields(logrus.Fields{
					"network_id": n.ID,
					"error":      err.Error(),
				}).Warning("Failed to get detailed network info")
				continue
			}
			networks = append(networks, detailedNetwork)
		} else {
			network := i.convertListItemToModel(n)
			networks = append(networks, network)
		}
	}

	if opts.SortBy != "" {
		networks = i.sortNetworks(networks, opts.SortBy, opts.SortDescending)
	}

	return networks, nil
}

// GetNetwork gets detailed information about a specific network
func (i *Inspector) GetNetwork(ctx context.Context, networkID string, opts InspectionOptions) (*models.Network, error) {
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.Timeout)*time.Second)
		defer cancel()
	}

	if err := i.throttle.Wait(ctx); err != nil {
		return nil, fmt.Errorf("throttle error: %w", err)
	}

	// Use networktypes.InspectOptions
	inspectOptions := networktypes.InspectOptions{ // Use new alias
		Verbose: true,
	}

	networkResource, err := i.client.NetworkInspect(ctx, networkID, inspectOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect network: %w", err)
	}

	network := i.convertInspectToModel(networkResource)
	return network, nil
}

// GetNetworkContainers gets containers connected to a specific network
func (i *Inspector) GetNetworkContainers(ctx context.Context, networkID string) (map[string]models.EndpointResource, error) {
	// Use networktypes.InspectOptions
	inspectOptions := networktypes.InspectOptions{ // Use new alias
		Verbose: true,
	}

	networkResource, err := i.client.NetworkInspect(ctx, networkID, inspectOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect network: %w", err)
	}

	containers := make(map[string]models.EndpointResource)
	for id, endpoint := range networkResource.Containers {
		containers[id] = models.EndpointResource{
			Name:        endpoint.Name,
			EndpointID:  endpoint.EndpointID,
			MacAddress:  endpoint.MacAddress,
			IPv4Address: endpoint.IPv4Address,
			IPv6Address: endpoint.IPv6Address,
		}
	}
	return containers, nil
}

// FindNetworkByName finds a network by its exact name
func (i *Inspector) FindNetworkByName(ctx context.Context, name string) (*models.Network, error) {
	filterArgs := filters.NewArgs() // Use standard 'filters' alias
	filterArgs.Add("name", name)

	// Use networktypes.ListOptions
	networks, err := i.client.NetworkList(ctx, networktypes.ListOptions{ // Use new alias
		Filters: filterArgs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	for _, n := range networks {
		if n.Name == name {
			return i.GetNetwork(ctx, n.ID, InspectionOptions{})
		}
	}
	return nil, errors.New("network not found")
}

// FindNetworksBySubnet finds networks by subnet
func (i *Inspector) FindNetworksBySubnet(ctx context.Context, subnet string) ([]*models.Network, error) {
	// Use networktypes.ListOptions
	networks, err := i.client.NetworkList(ctx, networktypes.ListOptions{}) // Use new alias
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	filteredNetworks, err := i.filterBySubnet(ctx, networks, subnet)
	if err != nil {
		return nil, fmt.Errorf("failed to filter networks by subnet: %w", err)
	}

	var result []*models.Network
	for _, n := range filteredNetworks {
		detailedNetwork, err := i.GetNetwork(ctx, n.ID, InspectionOptions{})
		if err != nil {
			i.logger.WithFields(logrus.Fields{
				"network_id": n.ID,
				"error":      err.Error(),
			}).Warning("Failed to get detailed network info")
			continue
		}
		result = append(result, detailedNetwork)
	}
	return result, nil
}

// FindNetworksByContainer finds networks connected to a specific container
func (i *Inspector) FindNetworksByContainer(ctx context.Context, containerIDOrName string) ([]*models.Network, error) {
	containerID, err := i.resolveContainerID(ctx, containerIDOrName)
	if err != nil {
		return nil, err
	}

	filterArgs := filters.NewArgs() // Use standard 'filters' alias
	filterArgs.Add("container", containerID)

	// Use networktypes.ListOptions
	networks, err := i.client.NetworkList(ctx, networktypes.ListOptions{ // Use new alias
		Filters: filterArgs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	var result []*models.Network
	for _, n := range networks {
		detailedNetwork, err := i.GetNetwork(ctx, n.ID, InspectionOptions{})
		if err != nil {
			i.logger.WithFields(logrus.Fields{
				"network_id": n.ID,
				"error":      err.Error(),
			}).Warning("Failed to get detailed network info")
			continue
		}
		result = append(result, detailedNetwork)
	}
	return result, nil
}

// CountNetworks counts networks matching the specified filters
func (i *Inspector) CountNetworks(ctx context.Context, opts InspectionOptions) (int, error) {
	filterArgs := i.createFilterArgs(opts)
	// Use networktypes.ListOptions
	networks, err := i.client.NetworkList(ctx, networktypes.ListOptions{ // Use new alias
		Filters: filterArgs,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to list networks: %w", err)
	}

	if !opts.IncludeSystemNetworks {
		networks = i.filterSystemNetworks(networks)
	}

	if opts.FilterSubnet != "" {
		networks, err = i.filterBySubnet(ctx, networks, opts.FilterSubnet)
		if err != nil {
			return 0, fmt.Errorf("failed to filter networks by subnet: %w", err)
		}
	}

	if len(opts.FilterNames) > 0 && !i.hasFilterArg(filterArgs, "name") {
		networks = i.filterByNameRegex(networks, opts.FilterNames)
	}

	return len(networks), nil
}

// resolveContainerID resolves a container name to its ID
func (i *Inspector) resolveContainerID(ctx context.Context, containerIDOrName string) (string, error) {
	if len(containerIDOrName) == 64 {
		// Basic check if it looks like an ID
		_, err := i.client.ContainerInspect(ctx, containerIDOrName)
		if err == nil {
			return containerIDOrName, nil
		}
	}

	container, err := i.client.ContainerInspect(ctx, containerIDOrName)
	if err != nil {
		return "", fmt.Errorf("failed to find container '%s': %w", containerIDOrName, err)
	}
	return container.ID, nil
}

// createFilterArgs creates filter arguments based on options
func (i *Inspector) createFilterArgs(opts InspectionOptions) filters.Args { // Use standard 'filters' alias
	filterArgs := filters.NewArgs() // Use standard 'filters' alias
	for key, value := range opts.FilterLabels {
		filterArgs.Add("label", fmt.Sprintf("%s=%s", key, value))
	}
	for _, name := range opts.FilterNames {
		if !strings.ContainsAny(name, "*?[]") { // Only add non-regex names to Docker filter
			filterArgs.Add("name", name)
		}
	}
	for _, id := range opts.FilterIDs {
		filterArgs.Add("id", id)
	}
	if opts.IncludeDriver != "" {
		filterArgs.Add("driver", opts.IncludeDriver)
	}
	if opts.FilterScope != "" {
		filterArgs.Add("scope", opts.FilterScope)
	}
	for _, container := range opts.FilterContainers {
		filterArgs.Add("container", container)
	}
	if opts.FilterIPv6 {
		filterArgs.Add("enable_ipv6", "true") // Note: API filter might be enableIPv6
	}
	if opts.FilterInternal {
		filterArgs.Add("internal", "true")
	}
	if opts.FilterBuiltin {
		filterArgs.Add("builtin", "true")
	}
	return filterArgs
}

// filterSystemNetworks filters out system networks
func (i *Inspector) filterSystemNetworks(networks []networktypes.Inspect) []networktypes.Inspect { // Use new alias
	systemNetworks := map[string]bool{"none": true, "host": true, "bridge": true}
	var filtered []networktypes.Inspect // Use new alias
	for _, network := range networks {
		if !systemNetworks[network.Name] {
			filtered = append(filtered, network)
		}
	}
	return filtered
}

// filterByNameRegex filters networks by name regex
func (i *Inspector) filterByNameRegex(networks []networktypes.Inspect, patterns []string) []networktypes.Inspect { // Use new alias
	if len(patterns) == 0 {
		return networks
	}
	var regexes []*regexp.Regexp
	for _, pattern := range patterns {
		regexPattern := "^" + strings.ReplaceAll(strings.ReplaceAll(pattern, "*", ".*"), "?", ".") + "$"
		regex, err := regexp.Compile(regexPattern)
		if err == nil {
			regexes = append(regexes, regex)
		} else {
			i.logger.Warnf("Invalid regex pattern '%s': %v", pattern, err)
		}
	}
	if len(regexes) == 0 {
		return networks // No valid regexes compiled
	}
	var filtered []networktypes.Inspect // Use new alias
	for _, n := range networks {
		for _, regex := range regexes {
			if regex.MatchString(n.Name) {
				filtered = append(filtered, n)
				break
			}
		}
	}
	return filtered
}

// filterBySubnet filters networks by subnet
func (i *Inspector) filterBySubnet(ctx context.Context, networks []networktypes.Inspect, subnetStr string) ([]networktypes.Inspect, error) { // Use new alias
	_, inputSubnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet format: %w", err)
	}

	var filtered []networktypes.Inspect // Use new alias
	for _, network := range networks {
		// Inspect network to get IPAM details
		inspectOptions := networktypes.InspectOptions{Verbose: true} // Use new alias
		networkResource, err := i.client.NetworkInspect(ctx, network.ID, inspectOptions)
		if err != nil {
			i.logger.WithFields(logrus.Fields{"network_id": network.ID, "error": err}).Warning("Failed to inspect network during subnet filter")
			continue
		}

		// Check if the network has IPAM configurations
		// Use length check instead of nil comparison for struct
		if len(networkResource.IPAM.Config) == 0 {
			continue
		}

		// Check each IPAM configuration
		for _, config := range networkResource.IPAM.Config {
			if config.Subnet == "" {
				continue
			}
			_, networkSubnet, err := net.ParseCIDR(config.Subnet)
			if err != nil {
				i.logger.WithFields(logrus.Fields{"network_id": network.ID, "subnet": config.Subnet, "error": err}).Warning("Failed to parse network subnet")
				continue
			}
			if subnetsOverlap(inputSubnet, networkSubnet) {
				filtered = append(filtered, network)
				break
			}
		}
	}
	return filtered, nil
}

// subnetsOverlap checks if two subnets overlap
func subnetsOverlap(subnet1, subnet2 *net.IPNet) bool {
	return subnet1.Contains(subnet2.IP) || subnet2.Contains(subnet1.IP)
}

// equalIPs checks if two IP addresses are equal (Helper, might not be needed if Contains works)
// func equalIPs(ip1, ip2 net.IP) bool { ... }

// hasFilterArg checks if a filter argument exists
func (i *Inspector) hasFilterArg(filterArgs filters.Args, key string) bool { // Use standard 'filters' alias
	// Use the Get method provided by filters.Args
	return len(filterArgs.Get(key)) > 0
}

// sortNetworks sorts networks by the specified field
func (i *Inspector) sortNetworks(networks []*models.Network, sortBy string, descending bool) []*models.Network {
	var less func(i, j int) bool
	switch strings.ToLower(sortBy) {
	case "name":
		less = func(i, j int) bool { return networks[i].Name < networks[j].Name }
	case "id":
		less = func(i, j int) bool { return networks[i].NetworkID < networks[j].NetworkID } // Use NetworkID
	case "driver":
		less = func(i, j int) bool { return networks[i].Driver < networks[j].Driver }
	case "scope":
		less = func(i, j int) bool { return networks[i].Scope < networks[j].Scope }
	case "created":
		less = func(i, j int) bool { return networks[i].Created.Before(networks[j].Created) } // Use direct time comparison
	default:
		return networks
	}
	sort.Slice(networks, func(i, j int) bool {
		if descending {
			return !less(i, j)
		}
		return less(i, j)
	})
	return networks
}

// convertListItemToModel converts a Docker network list item to our model
func (i *Inspector) convertListItemToModel(n networktypes.Inspect) *models.Network { // Use new alias
	// Convert map[string]string to models.JSONMap
	optionsMap := make(models.JSONMap)
	for k, v := range n.Options {
		optionsMap[k] = v
	}
	labelsMap := make(models.JSONMap)
	for k, v := range n.Labels {
		labelsMap[k] = v
	}

	networkModel := &models.Network{
		DockerResource: models.DockerResource{ // Populate base resource
			Name:   n.Name,
			Labels: labelsMap, // Assign converted labels
		},
		NetworkID:  n.ID, // Use NetworkID field in model
		Driver:     n.Driver,
		Scope:      n.Scope,
		Created:    n.Created, // Assign time.Time directly
		EnableIPv6: n.EnableIPv6,
		Internal:   n.Internal,
		Attachable: n.Attachable,
		Ingress:    n.Ingress,
		ConfigOnly: n.ConfigOnly,
		Options:    optionsMap, // Assign converted options
		// IPAMOptions:   ?, // Populate if needed from n.IPAM.Options
		// Containers:    ?, // Populate if needed from n.Containers
	}

	// Extract IPAM configuration
	// Use length check instead of nil comparison for struct
	if len(n.IPAM.Config) > 0 {
		ipam := &models.IPAM{
			Driver:  n.IPAM.Driver,
			Options: make(models.JSONMap), // Convert IPAM options
		}
		for k, v := range n.IPAM.Options {
			ipam.Options[k] = v
		}

		ipam.Config = make([]models.IPAMConfig, len(n.IPAM.Config))
		for idx, config := range n.IPAM.Config {
			auxAddrMap := make(models.JSONMap)
			for k, v := range config.AuxAddress {
				auxAddrMap[k] = v
			}
			ipam.Config[idx] = models.IPAMConfig{
				Subnet:     config.Subnet,
				IPRange:    config.IPRange,
				Gateway:    config.Gateway,
				AuxAddress: auxAddrMap,
			}
		}
		// Assign IPAM to model (assuming models.Network has an IPAM field)
		// networkModel.IPAM = ipam // Uncomment if models.Network has IPAM field
		// If IPAMOptions is used instead:
		ipamOptionsMap := make(models.JSONMap)
		if ipam != nil {
			ipamOptionsMap["Driver"] = ipam.Driver
			ipamOptionsMap["Options"] = ipam.Options
			ipamOptionsMap["Config"] = ipam.Config // Store config as part of JSON
		}
		networkModel.IPAMOptions = ipamOptionsMap

	}

	// Extract container endpoints
	containersMap := make(models.JSONMap)
	for id, endpoint := range n.Containers {
		containersMap[id] = models.EndpointResource{
			Name:        endpoint.Name,
			EndpointID:  endpoint.EndpointID,
			MacAddress:  endpoint.MacAddress,
			IPv4Address: endpoint.IPv4Address,
			IPv6Address: endpoint.IPv6Address,
		}
	}
	networkModel.Containers = containersMap

	return networkModel
}

// convertInspectToModel converts a Docker network inspect result to our model
func (i *Inspector) convertInspectToModel(n networktypes.Inspect) *models.Network { // Use new alias
	// Convert the full NetworkResource (from inspect) to the Summary-like structure needed by convertListItemToModel
	summary := networktypes.Summary{ // Use new alias
		ID:         n.ID,
		Name:       n.Name,
		Created:    n.Created,
		Scope:      n.Scope,
		Driver:     n.Driver,
		EnableIPv6: n.EnableIPv6,
		IPAM:       n.IPAM,
		Internal:   n.Internal,
		Attachable: n.Attachable,
		Ingress:    n.Ingress,
		ConfigFrom: n.ConfigFrom,
		ConfigOnly: n.ConfigOnly,
		Options:    n.Options,
		Labels:     n.Labels,
		Containers: n.Containers, // Include containers if needed by convertListItemToModel
		// Peers:      n.Peers, // Include if needed
	}
	network := i.convertListItemToModel(summary) // Pass the converted summary
	// Populate additional fields from the detailed inspection if needed
	// network.ConfigFrom = n.ConfigFrom // Assuming ConfigFrom exists in models.Network
	return network
}

// GetAvailableDrivers gets the list of available network drivers
func (i *Inspector) GetAvailableDrivers(ctx context.Context) ([]string, error) {
	if err := i.throttle.Wait(ctx); err != nil {
		return nil, fmt.Errorf("throttle error: %w", err)
	}
	// Use networktypes.ListOptions
	networks, err := i.client.NetworkList(ctx, networktypes.ListOptions{}) // Use new alias
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}
	driversMap := make(map[string]bool)
	for _, network := range networks {
		driversMap[network.Driver] = true
	}
	commonDrivers := []string{"bridge", "host", "none", "overlay", "macvlan", "ipvlan"}
	for _, driver := range commonDrivers {
		driversMap[driver] = true
	}
	drivers := make([]string, 0, len(driversMap))
	for driver := range driversMap {
		drivers = append(drivers, driver)
	}
	sort.Strings(drivers)
	return drivers, nil
}

// GetIPAMDrivers gets the list of available IPAM drivers
func (i *Inspector) GetIPAMDrivers(ctx context.Context) ([]string, error) {
	if err := i.throttle.Wait(ctx); err != nil {
		return nil, fmt.Errorf("throttle error: %w", err)
	}
	// Use networktypes.ListOptions
	networks, err := i.client.NetworkList(ctx, networktypes.ListOptions{}) // Use new alias
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}
	driversMap := make(map[string]bool)
	for _, network := range networks {
		// Use length check instead of nil comparison for struct
		if len(network.IPAM.Config) > 0 && network.IPAM.Driver != "" {
			driversMap[network.IPAM.Driver] = true
		}
	}
	commonDrivers := []string{"default", "host-local", "dhcp", "null"}
	for _, driver := range commonDrivers {
		driversMap[driver] = true
	}
	drivers := make([]string, 0, len(driversMap))
	for driver := range driversMap {
		drivers = append(drivers, driver)
	}
	sort.Strings(drivers)
	return drivers, nil
}
