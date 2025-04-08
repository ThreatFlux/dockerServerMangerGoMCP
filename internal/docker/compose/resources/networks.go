// Package resources provides functionality for managing Docker Compose resources
package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types/filters"
	networkSvc "github.com/threatflux/dockerServerMangerGoMCP/internal/docker/network"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// createComposeNetworks creates the networks for a Docker Compose file
func (m *Manager) createComposeNetworks(ctx context.Context, composeFile *models.ComposeFile, options CreateResourcesOptions) error {
	// Skip if no networks are defined
	if len(composeFile.Networks) == 0 {
		m.logger.Info("No networks defined in Docker Compose file")
		return nil
	}

	// Keep track of created networks for cleanup in case of error
	createdNetworks := make([]string, 0)

	// Create each network
	for networkName, networkConfig := range composeFile.Networks {
		// Skip if external
		if isExternalResource(networkConfig.External) {
			m.logger.WithField("network", networkName).Info("Skipping external network")
			continue
		}

		// Generate network name with prefix if provided
		fullNetworkName := getResourceName(options.ProjectName, options.NamePrefix, networkName)

		// Check if network already exists
		exists, err := m.networkExists(ctx, fullNetworkName)
		if err != nil {
			m.logger.WithError(err).WithField("network", fullNetworkName).Error("Failed to check if network exists")
			return fmt.Errorf("failed to check if network %s exists: %w", fullNetworkName, err)
		}

		// Skip if network exists and we're configured to skip
		if exists && options.SkipExistingNetworks {
			m.logger.WithField("network", fullNetworkName).Info("Network already exists, skipping")
			continue
		}

		// Return error if network exists and we're not configured to skip
		if exists && !options.SkipExistingNetworks {
			m.logger.WithField("network", fullNetworkName).Error("Network already exists")
			return fmt.Errorf("network %s already exists", fullNetworkName)
		}

		// Prepare labels
		labels := make(map[string]string)
		// Add project label
		labels["com.docker_test.compose.project"] = options.ProjectName
		// Add network label
		labels["com.docker_test.compose.network"] = networkName
		// Add additional labels
		for k, v := range options.Labels {
			labels[k] = v
		}

		// Convert compose network config to network create options
		createOpts := m.convertNetworkConfig(networkConfig, labels)

		// Create the network
		m.logger.WithField("network", fullNetworkName).Info("Creating network")
		_, err = m.networkService.Create(ctx, fullNetworkName, createOpts)
		if err != nil {
			m.logger.WithError(err).WithField("network", fullNetworkName).Error("Failed to create network")

			// Attempt to cleanup already created networks
			m.cleanupNetworks(ctx, createdNetworks)

			return fmt.Errorf("failed to create network %s: %w", fullNetworkName, err)
		}

		// Add to list of created networks
		createdNetworks = append(createdNetworks, fullNetworkName)
	}

	return nil
}

// removeComposeNetworks removes the networks for a Docker Compose file
func (m *Manager) removeComposeNetworks(ctx context.Context, composeFile *models.ComposeFile, options RemoveResourcesOptions) error {
	// Skip if no networks are defined
	if len(composeFile.Networks) == 0 {
		m.logger.Info("No networks defined in Docker Compose file")
		return nil
	}

	// Track errors to remove as many networks as possible even if some fail
	var errs []error

	// Remove each network
	for networkName, networkConfig := range composeFile.Networks {
		// Skip if external and not configured to remove external resources
		if isExternalResource(networkConfig.External) && !options.RemoveExternalResources {
			m.logger.WithField("network", networkName).Info("Skipping external network")
			continue
		}

		// Generate network name with prefix if provided
		fullNetworkName := getResourceName(options.ProjectName, options.NamePrefix, networkName)

		// Check if network exists
		exists, err := m.networkExists(ctx, fullNetworkName)
		if err != nil {
			m.logger.WithError(err).WithField("network", fullNetworkName).Error("Failed to check if network exists")
			errs = append(errs, fmt.Errorf("failed to check if network %s exists: %w", fullNetworkName, err))
			continue
		}

		// Skip if network doesn't exist
		if !exists {
			m.logger.WithField("network", fullNetworkName).Info("Network doesn't exist, skipping")
			continue
		}

		// Remove the network
		m.logger.WithField("network", fullNetworkName).Info("Removing network")
		removeOpts := networkSvc.RemoveOptions{
			Force:   options.Force,
			Timeout: options.Timeout,
			Logger:  options.Logger,
		}
		err = m.networkService.Remove(ctx, fullNetworkName, removeOpts)
		if err != nil {
			m.logger.WithError(err).WithField("network", fullNetworkName).Error("Failed to remove network")
			errs = append(errs, fmt.Errorf("failed to remove network %s: %w", fullNetworkName, err))
			continue
		}
	}

	// Return combined error if any occurred
	if len(errs) > 0 {
		// Combine error messages
		errMsgs := make([]string, len(errs))
		for i, err := range errs {
			errMsgs[i] = err.Error()
		}
		return fmt.Errorf("failed to remove networks: %s", strings.Join(errMsgs, "; "))
	}

	return nil
}

// listComposeNetworks lists the networks for a Docker Compose file
func (m *Manager) listComposeNetworks(ctx context.Context, composeFile *models.ComposeFile, options ListResourcesOptions) ([]*models.Network, error) {
	// Skip if no networks are defined
	if len(composeFile.Networks) == 0 {
		m.logger.Info("No networks defined in Docker Compose file")
		return []*models.Network{}, nil
	}

	// Create a filter for the project
	filterArgs := filters.NewArgs()
	filterArgs.Add("label", fmt.Sprintf("com.docker_test.compose.project=%s", options.ProjectName))

	// List all networks for the project
	listOpts := networkSvc.ListOptions{
		Filters: filterArgs,
		Timeout: options.Timeout,
		Logger:  options.Logger,
	}
	networks, err := m.networkService.List(ctx, listOpts)
	if err != nil {
		m.logger.WithError(err).Error("Failed to list networks")
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	// Filter networks to only those in the compose file
	result := make([]*models.Network, 0)
	for _, network := range networks {
		// Extract network name from labels
		networkNameLabel, ok := network.Labels["com.docker_test.compose.network"]
		if !ok {
			// Skip networks without the network label
			continue
		}

		// Check if the network is defined in the compose file
		// We need to iterate because composeFile.Networks is map[string]models.NetworkConfig
		// and we only have the label value.
		found := false
		for nameInCompose := range composeFile.Networks {
			if nameInCompose == networkNameLabel {
				found = true
				break
			}
		}
		if found {
			result = append(result, network)
		}
	}

	// Add external networks if requested
	if options.IncludeExternalResources {
		for networkName, networkConfig := range composeFile.Networks {
			// Skip if not external
			if !isExternalResource(networkConfig.External) {
				continue
			}

			// Get external network name
			externalName := getExternalResourceName(networkConfig.External, networkName)

			// Try to get the network
			getOpts := networkSvc.GetOptions{
				Timeout: options.Timeout,
				Logger:  options.Logger,
			}
			network, err := m.networkService.Get(ctx, externalName, getOpts)
			if err != nil {
				// Skip if network not found
				// TODO: Maybe log this?
				continue
			}

			// Add the network to the result
			result = append(result, network)
		}
	}

	return result, nil
}

// convertNetworkConfig converts a compose network config to network create options
func (m *Manager) convertNetworkConfig(networkConfig models.NetworkConfig, labels map[string]string) networkSvc.CreateOptions {
	// Create options
	opts := networkSvc.CreateOptions{
		Driver: networkConfig.Driver,
		// EnableIPv6:   networkConfig.EnableIPv6, // Field doesn't exist in models.NetworkConfig
		Internal:       networkConfig.Internal,
		Attachable:     networkConfig.Attachable,
		Labels:         labels,
		Options:        networkConfig.DriverOpts, // Use DriverOpts directly
		CheckDuplicate: true,
	}

	// Convert IPAM configuration if present
	if networkConfig.IPAM != nil {
		// Log a warning as detailed IPAM conversion is not implemented
		m.logger.Warn("Detailed IPAM configuration conversion from compose file is not fully implemented yet.")
		// We can still create a basic IPAM config if needed, but without details from the interface{}
		// For now, we skip setting opts.IPAM
		/*
			ipamConfig := &network.IPAM{
				// Driver:  // Need to parse Driver from IPAM map
				Options: map[string]string{},
				Config:  []network.IPAMConfig{},
			}
			// TODO: Implement proper parsing of networkConfig.IPAM based on its structure
			// Example parsing (adjust based on actual structure of networkConfig.IPAM)
			if ipamMap, ok := networkConfig.IPAM.(map[string]interface{}); ok {
				if driver, ok := ipamMap["driver"].(string); ok {
					ipamConfig.Driver = driver
				}
				if configList, ok := ipamMap["config"].([]interface{}); ok {
					for _, cfgItem := range configList {
						if cfgMap, ok := cfgItem.(map[string]interface{}); ok {
							config := network.IPAMConfig{}
							if subnet, ok := cfgMap["subnet"].(string); ok {
								config.Subnet = subnet
							}
							// Add parsing for IPRange, Gateway, AuxAddress similarly
							ipamConfig.Config = append(ipamConfig.Config, config)
						}
					}
				}
				// Add parsing for IPAM options similarly
			}
			opts.IPAM = ipamConfig
		*/
	}

	return opts
}

// cleanupNetworks removes networks in case of error during creation
func (m *Manager) cleanupNetworks(ctx context.Context, networks []string) {
	for _, network := range networks {
		m.logger.WithField("network", network).Info("Cleaning up network")
		removeOpts := networkSvc.RemoveOptions{
			Force:   true,
			Timeout: 30 * time.Second, // Added time import
			Logger:  m.logger,
		}
		if err := m.networkService.Remove(ctx, network, removeOpts); err != nil {
			m.logger.WithError(err).WithField("network", network).Error("Failed to clean up network")
		}
	}
}

// networkExists checks if a network exists
func (m *Manager) networkExists(ctx context.Context, name string) (bool, error) {
	// Try to get the network
	getOpts := networkSvc.GetOptions{
		Timeout: 10 * time.Second, // Added time import
		Logger:  m.logger,
	}
	_, err := m.networkService.Get(ctx, name, getOpts)
	if err != nil {
		// Check if the error is a not found error using the network service's error type
		if errors.Is(err, networkSvc.ErrNetworkNotFound) { // Use error from networkSvc package
			return false, nil
		}
		// Return other errors
		return false, err
	}
	// Network exists
	return true, nil
}

// Helper functions are now defined in helpers.go
