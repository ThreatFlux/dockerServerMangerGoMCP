// Package container provides functionality for managing Docker containers.
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	dockertypes "github.com/docker/docker/api/types"              // Re-added dockertypes alias
	containertypes "github.com/docker/docker/api/types/container" // Use containertypes alias
	filterstypes "github.com/docker/docker/api/types/filters"     // Use filterstypes alias
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
)

// Inspector provides methods for inspecting containers.
type Inspector struct {
	client   client.APIClient
	logger   *logrus.Logger
	throttle *utils.Throttle
}

// NewInspector creates a new Inspector.
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

// InspectionOptions defines options for listing and inspecting containers.
type InspectionOptions struct {
	All            bool              `json:"all"`
	Limit          int               `json:"limit"`
	Size           bool              `json:"size"`
	Filters        map[string]string `json:"filters"`
	SortBy         string            `json:"sort_by"`
	SortDescending bool              `json:"sort_descending"`
	Offset         int               `json:"offset"`
	Timeout        int               `json:"timeout"`
}

// GetContainers lists containers based on the provided options.
func (i *Inspector) GetContainers(ctx context.Context, opts InspectionOptions) ([]*models.Container, error) {
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.Timeout)*time.Second)
		defer cancel()
	}

	filterArgs := i.createFilterArgs(opts.Filters)

	if err := i.throttle.Wait(ctx); err != nil {
		return nil, fmt.Errorf("throttle error: %w", err)
	}

	listOptions := containertypes.ListOptions{ // Changed types -> containertypes
		All:     opts.All,
		Limit:   opts.Limit,
		Size:    opts.Size,
		Filters: filterArgs,
	}

	containersList, err := i.client.ContainerList(ctx, listOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Apply pagination (after filtering, before detailed inspection)
	totalItems := len(containersList)
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
	paginatedList := containersList[start:end]

	var containers []*models.Container
	for _, c := range paginatedList {
		// Fetch detailed info for each container if needed (or convert directly)
		// For simplicity, converting directly from list item
		containerModel := i.convertListItemToModel(c)
		containers = append(containers, &containerModel)
	}

	if opts.SortBy != "" {
		containers = i.sortContainers(containers, opts.SortBy, opts.SortDescending)
	}

	return containers, nil
}

// GetContainer inspects a single container by ID or name.
func (i *Inspector) GetContainer(ctx context.Context, idOrName string) (*models.Container, error) {
	if err := i.throttle.Wait(ctx); err != nil {
		return nil, fmt.Errorf("throttle error: %w", err)
	}

	containerJSON, err := i.client.ContainerInspect(ctx, idOrName)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, fmt.Errorf("container '%s' not found", idOrName)
		}
		return nil, fmt.Errorf("failed to inspect container '%s': %w", idOrName, err)
	}

	containerModel := i.convertInspectToModel(containerJSON)
	return &containerModel, nil
}

// GetContainerStats retrieves statistics for a container.
// If stream is true, it returns a stream of stats; otherwise, a single stats snapshot.
func (i *Inspector) GetContainerStats(ctx context.Context, idOrName string, stream bool) (io.ReadCloser, error) {
	if err := i.throttle.Wait(ctx); err != nil {
		return nil, fmt.Errorf("throttle error: %w", err)
	}

	stats, err := i.client.ContainerStats(ctx, idOrName, stream)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, fmt.Errorf("container '%s' not found", idOrName)
		}
		return nil, fmt.Errorf("failed to get stats for container '%s': %w", idOrName, err)
	}

	// The body needs to be closed by the caller if stream is true or after reading if stream is false.
	return stats.Body, nil
}

// GetContainerStatsJSON retrieves a single stats snapshot and decodes it into StatsJSON.
func (i *Inspector) GetContainerStatsJSON(ctx context.Context, idOrName string) (*containertypes.StatsResponse, error) { // Changed to containertypes.StatsResponse
	statsReader, err := i.GetContainerStats(ctx, idOrName, false) // Get non-streaming stats
	if err != nil {
		return nil, err
	}
	defer statsReader.Close()

	var stats containertypes.StatsResponse // Changed to containertypes.StatsResponse
	if err := json.NewDecoder(statsReader).Decode(&stats); err != nil {
		// Handle potential EOF for non-streaming stats if the container stops quickly
		if err == io.EOF {
			return &containertypes.StatsResponse{}, nil // Return empty stats on EOF for non-streaming
		}
		return nil, fmt.Errorf("failed to decode container stats: %w", err)
	}

	return &stats, nil
}

// CountContainers counts containers matching the specified filters.
func (i *Inspector) CountContainers(ctx context.Context, opts InspectionOptions) (int, error) {
	filterArgs := i.createFilterArgs(opts.Filters)

	listOptions := containertypes.ListOptions{ // Changed types -> containertypes
		All:     opts.All,
		Filters: filterArgs,
	}

	containersList, err := i.client.ContainerList(ctx, listOptions)
	if err != nil {
		return 0, fmt.Errorf("failed to list containers: %w", err)
	}

	return len(containersList), nil
}

// createFilterArgs converts a map to filters.Args.
func (i *Inspector) createFilterArgs(filters map[string]string) filterstypes.Args { // Use filterstypes alias
	filterArgs := filterstypes.NewArgs() // Use filterstypes alias
	for key, value := range filters {
		filterArgs.Add(key, value)
	}
	return filterArgs
}

// sortContainers sorts a slice of containers by the specified field.
func (i *Inspector) sortContainers(containers []*models.Container, sortBy string, descending bool) []*models.Container {
	var less func(i, j int) bool
	switch strings.ToLower(sortBy) {
	case "name":
		less = func(i, j int) bool {
			// Handle potential nil Names slice
			nameA := ""
			if len(containers[i].Names) > 0 {
				nameA = containers[i].Names[0]
			}
			nameB := ""
			if len(containers[j].Names) > 0 {
				nameB = containers[j].Names[0]
			}
			return strings.TrimPrefix(nameA, "/") < strings.TrimPrefix(nameB, "/")
		}
	case "id":
		less = func(i, j int) bool { return containers[i].ContainerID < containers[j].ContainerID } // Use ContainerID
	case "image":
		less = func(i, j int) bool { return containers[i].Image < containers[j].Image }
	case "state":
		less = func(i, j int) bool { return containers[i].State < containers[j].State }
	case "created":
		less = func(i, j int) bool {
			return containers[i].DockerResource.CreatedAt.Before(containers[j].DockerResource.CreatedAt)
		} // Access via embedded DockerResource
	case "sizerw":
		less = func(i, j int) bool { return containers[i].SizeRw < containers[j].SizeRw }
	case "sizerootfs":
		less = func(i, j int) bool { return containers[i].SizeRootFs < containers[j].SizeRootFs }
	default:
		return containers // No sorting if field is unknown
	}

	sort.Slice(containers, func(i, j int) bool {
		if descending {
			return !less(i, j) // Reverse order for descending
		}
		return less(i, j)
	})
	return containers
}

// convertListItemToModel converts a types.Container to models.Container.
func (i *Inspector) convertListItemToModel(c containertypes.Summary) models.Container { // Changed dockertypes.Container -> containertypes.Summary
	// Basic conversion
	containerModel := models.Container{
		DockerResource: models.DockerResource{
			// ID is GORM PK, Name and Labels are here
			Name:      strings.TrimPrefix(c.Names[0], "/"), // Assuming first name is primary
			Labels:    convertStringMapToJSONMap(c.Labels), // Use helper function
			CreatedAt: time.Unix(c.Created, 0),             // Convert Unix timestamp and assign here
		},
		ContainerID: c.ID, // Assign Docker ID here
		Names:       c.Names,
		Image:       c.Image,
		ImageID:     c.ImageID,
		Command:     c.Command,
		State:       c.State,
		Status:      models.ContainerStatus(c.Status), // Cast to models.ContainerStatus
		// Labels:     models.JSONMap(c.Labels), // Already in DockerResource, explicit conversion needed if assigned here
		SizeRw:     c.SizeRw,
		SizeRootFs: c.SizeRootFs,
		// HostConfig needs more details, maybe nil for list items
		// NetworkSettings needs conversion
		Mounts: []models.MountPoint{}, // Initialize Mounts slice
	}

	// Convert Ports
	portsMap := make(models.JSONMap)
	for _, p := range c.Ports {
		// Store port info in the map; key could be container port/proto
		portKey := fmt.Sprintf("%d/%s", p.PrivatePort, p.Type)
		portsMap[portKey] = models.PortMapping{
			HostIP:        p.IP,
			HostPort:      fmt.Sprintf("%d", p.PublicPort),
			ContainerPort: fmt.Sprintf("%d/%s", p.PrivatePort, p.Type),
			Type:          p.Type,
		}
	}
	containerModel.Ports = portsMap

	// Convert Mounts (Note: types.MountPoint in list is different from inspect)
	for _, m := range c.Mounts {
		containerModel.Mounts = append(containerModel.Mounts, models.MountPoint{
			Type:        string(m.Type),
			Name:        m.Name, // Add Name if available in list item MountPoint
			Source:      m.Source,
			Destination: m.Destination,
			Mode:        m.Mode,
			RW:          m.RW,
			// Propagation is not available in list item MountPoint
		})
	}

	// Convert NetworkSettings
	if c.NetworkSettings != nil && c.NetworkSettings.Networks != nil {
		networksMap := make(models.JSONMap)
		for name, settings := range c.NetworkSettings.Networks {
			networksMap[name] = map[string]interface{}{ // Store as map[string]interface{} for JSONMap
				"NetworkID":           settings.NetworkID, // Use map keys matching models.ContainerNetwork fields if needed elsewhere
				"EndpointID":          settings.EndpointID,
				"Gateway":             settings.Gateway,
				"IPAddress":           settings.IPAddress,
				"IPPrefixLen":         settings.IPPrefixLen,
				"IPv6Gateway":         settings.IPv6Gateway,
				"GlobalIPv6Address":   settings.GlobalIPv6Address,
				"GlobalIPv6PrefixLen": settings.GlobalIPv6PrefixLen,
				"MacAddress":          settings.MacAddress,
				"DriverOpts":          settings.DriverOpts,
				"Links":               settings.Links,
				"Aliases":             settings.Aliases,
			}
		}
		containerModel.Networks = networksMap
	}

	return containerModel
}

// convertInspectToModel converts a types.ContainerJSON to models.Container.
func (i *Inspector) convertInspectToModel(c dockertypes.ContainerJSON) models.Container { // Use dockertypes alias
	// Start with basic info
	createdAt, _ := time.Parse(time.RFC3339Nano, c.Created) // Parse Created string
	labelsMap := make(models.JSONMap)
	if c.Config != nil {
		labelsMap = convertStringMapToJSONMap(c.Config.Labels)
	}

	containerModel := models.Container{
		DockerResource: models.DockerResource{
			// ID is GORM PK, Name and Labels are here
			Name:      strings.TrimPrefix(c.Name, "/"),
			Labels:    labelsMap, // Use converted map
			CreatedAt: createdAt, // Use parsed time
		},
		ContainerID: c.ID, // Assign Docker ID here
		Image:       c.Config.Image,
		ImageID:     c.Image,
		Command:     strings.Join(c.Config.Cmd, " "),
		State:       c.State.Status,                         // Keep raw state string
		Status:      models.ContainerStatus(c.State.Status), // Use State.Status and cast for model status
		// Labels:       c.Config.Labels, // Already in DockerResource
		RestartCount: c.RestartCount,
		// Driver:       c.Driver, // Field removed from model
		Platform: c.Platform,
		// LogPath:      c.LogPath, // Field removed from model
		// HostConfig:   c.HostConfig, // Store relevant parts if needed
		// ExecIDs:      c.ExecIDs, // Field removed from model
		// NetworkSettings needs conversion below
		// Config field removed as most relevant parts are extracted
	}

	// Handle potential nil pointers for SizeRw and SizeRootFs
	if c.SizeRw != nil {
		containerModel.SizeRw = *c.SizeRw
	}
	if c.SizeRootFs != nil {
		containerModel.SizeRootFs = *c.SizeRootFs
	}
	// if c.GraphDriver.Name != "" {
	// containerModel.GraphDriver = c.GraphDriver.Name // GraphDriver field doesn't exist in models.Container
	// }

	// Add health check information if available
	if c.State.Health != nil {
		containerModel.Health = c.State.Health.Status
	}

	// Convert Ports
	portsMap := make(models.JSONMap)
	if c.NetworkSettings != nil && c.NetworkSettings.Ports != nil {
		for port, bindings := range c.NetworkSettings.Ports {
			containerPort := string(port)
			var bindingList []map[string]interface{}
			if len(bindings) == 0 {
				bindingList = append(bindingList, map[string]interface{}{
					"ContainerPort": containerPort,
				})
			} else {
				for _, binding := range bindings {
					bindingList = append(bindingList, map[string]interface{}{
						"HostIP":        binding.HostIP,
						"HostPort":      binding.HostPort,
						"ContainerPort": containerPort,
						// Type might be inferred from port string if needed
					})
				}
			}
			portsMap[containerPort] = bindingList
		}
		containerModel.Ports = portsMap
	}

	// Convert Mounts
	containerModel.Mounts = []models.MountPoint{}
	for _, m := range c.Mounts {
		containerModel.Mounts = append(containerModel.Mounts, models.MountPoint{
			Type:        string(m.Type),
			Source:      m.Source,
			Destination: m.Destination,
			Mode:        m.Mode,
			RW:          m.RW,
			Propagation: string(m.Propagation),
		})
	}

	// Convert NetworkSettings
	if c.NetworkSettings != nil && c.NetworkSettings.Networks != nil {
		networksMap := make(models.JSONMap)
		for name, settings := range c.NetworkSettings.Networks {
			networksMap[name] = map[string]interface{}{ // Store as map[string]interface{} for JSONMap
				"NetworkID":           settings.NetworkID, // Use map keys matching models.ContainerNetwork fields if needed elsewhere
				"EndpointID":          settings.EndpointID,
				"Gateway":             settings.Gateway,
				"IPAddress":           settings.IPAddress,
				"IPPrefixLen":         settings.IPPrefixLen,
				"IPv6Gateway":         settings.IPv6Gateway,
				"GlobalIPv6Address":   settings.GlobalIPv6Address,
				"GlobalIPv6PrefixLen": settings.GlobalIPv6PrefixLen,
				"MacAddress":          settings.MacAddress,
				"DriverOpts":          settings.DriverOpts,
				"Links":               settings.Links,
				"Aliases":             settings.Aliases,
			}
		}
		containerModel.Networks = networksMap
	}

	// Populate other fields from HostConfig if needed
	if c.HostConfig != nil {
		containerModel.RestartPolicy = models.RestartPolicy(c.HostConfig.RestartPolicy.Name)
		if containerModel.RestartPolicy == models.RestartPolicyOnFailure && c.HostConfig.RestartPolicy.MaximumRetryCount > 0 {
			containerModel.RestartPolicy = models.RestartPolicy(fmt.Sprintf("on-failure:%d", c.HostConfig.RestartPolicy.MaximumRetryCount))
		}
		if c.HostConfig.NetworkMode.IsHost() {
			containerModel.NetworkMode = models.NetworkModeHost
		} else if c.HostConfig.NetworkMode.IsNone() {
			containerModel.NetworkMode = models.NetworkModeNone
		} else if c.HostConfig.NetworkMode.IsContainer() {
			containerModel.NetworkMode = models.NetworkMode(fmt.Sprintf("container:%s", c.HostConfig.NetworkMode.ConnectedContainer()))
		} else {
			containerModel.NetworkMode = models.NetworkModeBridge
		} // Default or specific network name

		containerModel.Privileged = c.HostConfig.Privileged
		containerModel.SecurityOptions = models.StringArray(c.HostConfig.SecurityOpt)
		containerModel.AutoRemove = c.HostConfig.AutoRemove
		containerModel.ReadOnly = c.HostConfig.ReadonlyRootfs
		containerModel.HostIPC = c.HostConfig.IpcMode.IsHost()
		containerModel.HostPID = c.HostConfig.PidMode.IsHost()
		containerModel.CapAdd = models.StringArray(c.HostConfig.CapAdd)
		containerModel.CapDrop = models.StringArray(c.HostConfig.CapDrop)
		containerModel.UsernsMode = string(c.HostConfig.UsernsMode)

		resourcesMap := make(models.JSONMap)
		resourcesMap["Memory"] = c.HostConfig.Memory
		resourcesMap["MemoryReservation"] = c.HostConfig.MemoryReservation
		resourcesMap["MemorySwap"] = c.HostConfig.MemorySwap
		resourcesMap["NanoCPUs"] = c.HostConfig.NanoCPUs
		resourcesMap["CPUShares"] = c.HostConfig.CPUShares
		resourcesMap["CPUPeriod"] = c.HostConfig.CPUPeriod
		resourcesMap["CPUQuota"] = c.HostConfig.CPUQuota
		resourcesMap["CpusetCpus"] = c.HostConfig.CpusetCpus
		resourcesMap["CpusetMems"] = c.HostConfig.CpusetMems
		resourcesMap["BlkioWeight"] = c.HostConfig.BlkioWeight
		if c.HostConfig.PidsLimit != nil {
			resourcesMap["PidsLimit"] = *c.HostConfig.PidsLimit
		}
		containerModel.Resources = resourcesMap
	}

	// Populate EnvVars from Config
	if c.Config != nil {
		containerModel.EnvVars = models.StringArray(c.Config.Env)
		containerModel.Entrypoint = c.Config.Entrypoint
		containerModel.WorkingDir = c.Config.WorkingDir
		containerModel.User = c.Config.User
		containerModel.ExposedPorts = make([]string, 0, len(c.Config.ExposedPorts))
		for port := range c.Config.ExposedPorts {
			containerModel.ExposedPorts = append(containerModel.ExposedPorts, string(port))
		}

		healthcheckMap := make(models.JSONMap)
		if c.Config.Healthcheck != nil {
			healthcheckMap["Test"] = c.Config.Healthcheck.Test
			healthcheckMap["Interval"] = c.Config.Healthcheck.Interval.String()
			healthcheckMap["Timeout"] = c.Config.Healthcheck.Timeout.String()
			healthcheckMap["Retries"] = c.Config.Healthcheck.Retries
			healthcheckMap["StartPeriod"] = c.Config.Healthcheck.StartPeriod.String()
		}
		containerModel.Healthcheck = healthcheckMap
	}

	// Populate state details
	if c.State != nil {
		containerModel.Running = c.State.Running
		containerModel.Paused = c.State.Paused
		containerModel.Restarting = c.State.Restarting
		containerModel.OOMKilled = c.State.OOMKilled
		containerModel.Dead = c.State.Dead
		if t, err := time.Parse(time.RFC3339Nano, c.State.StartedAt); err == nil {
			containerModel.StartedAt = t
		}
		if t, err := time.Parse(time.RFC3339Nano, c.State.FinishedAt); err == nil && !t.IsZero() {
			containerModel.FinishedAt = t
		}
		if containerModel.Running && !containerModel.StartedAt.IsZero() {
			containerModel.UpTime = time.Since(containerModel.StartedAt).String()
		}
		if c.State.Health != nil {
			containerModel.Health = c.State.Health.Status
		}
	}

	// Set SecurityProfile based on SecurityOptions
	for _, opt := range containerModel.SecurityOptions {
		if strings.HasPrefix(opt, "seccomp=") {
			containerModel.SecurityProfile = "seccomp:" + strings.TrimPrefix(opt, "seccomp=")
			break
		}
		if strings.HasPrefix(opt, "apparmor=") {
			containerModel.SecurityProfile = "apparmor:" + strings.TrimPrefix(opt, "apparmor=")
			break
		}
	}

	containerModel.SanitizeSecurityFields()
	return containerModel
}

// GetContainerLogs retrieves logs for a container.
func (i *Inspector) GetContainerLogs(ctx context.Context, idOrName string, options containertypes.LogsOptions) (io.ReadCloser, error) { // Changed types -> containertypes
	if err := i.throttle.Wait(ctx); err != nil { // Use containertypes alias
		return nil, fmt.Errorf("throttle error: %w", err)
	}

	logReader, err := i.client.ContainerLogs(ctx, idOrName, options)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, fmt.Errorf("container '%s' not found", idOrName)
		}
		return nil, fmt.Errorf("failed to get logs for container '%s': %w", idOrName, err)
	}

	return logReader, nil
}

// GetContainerProcesses retrieves the list of processes running inside a container.
func (i *Inspector) GetContainerProcesses(ctx context.Context, idOrName string, psArgs string) (containertypes.ContainerTopOKBody, error) { // Correct return type
	if err := i.throttle.Wait(ctx); err != nil {
		return containertypes.ContainerTopOKBody{}, fmt.Errorf("throttle error: %w", err) // Correct return type
	}

	processes, err := i.client.ContainerTop(ctx, idOrName, strings.Fields(psArgs))
	if err != nil {
		if client.IsErrNotFound(err) {
			return containertypes.ContainerTopOKBody{}, fmt.Errorf("container '%s' not found", idOrName) // Correct return type
		}
		return containertypes.ContainerTopOKBody{}, fmt.Errorf("failed to get processes for container '%s': %w", idOrName, err) // Correct return type
	}

	return processes, nil
}

// GetContainerChanges retrieves changes on a container's filesystem.
func (i *Inspector) GetContainerChanges(ctx context.Context, idOrName string) ([]containertypes.FilesystemChange, error) { // Correct return type
	if err := i.throttle.Wait(ctx); err != nil {
		return nil, fmt.Errorf("throttle error: %w", err)
	}

	changes, err := i.client.ContainerDiff(ctx, idOrName)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, fmt.Errorf("container '%s' not found", idOrName)
		}
		return nil, fmt.Errorf("failed to get changes for container '%s': %w", idOrName, err)
	}

	return changes, nil
}

// GetContainerResourceUsage retrieves detailed resource usage statistics.
func (i *Inspector) GetContainerResourceUsage(ctx context.Context, idOrName string) (*containertypes.StatsResponse, error) { // Changed to containertypes.StatsResponse
	return i.GetContainerStatsJSON(ctx, idOrName)
}

// Helper function to convert map[string]string to models.JSONMap
func convertStringMapToJSONMap(input map[string]string) models.JSONMap {
	output := make(models.JSONMap, len(input))
	for k, v := range input {
		output[k] = v
	}
	return output
}
