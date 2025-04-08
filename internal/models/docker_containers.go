package models

import (
	"strconv"
	// "strings" // Removed unused import
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container" // Keep container for State type
	// "github.com/docker_test/docker_test/api/types/mount" // Remove unused mount import
	"github.com/docker/docker/api/types/network" // Re-added import
	"github.com/docker/go-connections/nat"
	specs "github.com/opencontainers/image-spec/specs-go/v1" // Re-added import
)

// DockerContainer represents a Docker container for API operations
// Note: This struct might be redundant or conflict with models.Container
// defined in docker_entities.go. Consider consolidating.
type DockerContainer struct {
	ID              string                    `json:"id"`
	Name            string                    `json:"name"`
	Image           string                    `json:"image"`
	ImageID         string                    `json:"image_id"`
	Command         string                    `json:"command"`
	Created         time.Time                 `json:"created"`
	Started         time.Time                 `json:"started,omitempty"`
	Finished        time.Time                 `json:"finished,omitempty"`
	State           *types.ContainerState     `json:"state,omitempty"` // Use pointer to Docker SDK State struct from types package
	Status          string                    `json:"status"`
	Health          *ContainerHealth          `json:"health,omitempty"` // Assuming this is a custom local type
	ExitCode        int                       `json:"exit_code"`
	Error           string                    `json:"error,omitempty"`
	Ports           []PortMapping             `json:"ports"` // Use PortMapping from docker_entities.go
	Labels          map[string]string         `json:"labels"`
	Mounts          []MountPoint              `json:"mounts"` // Use MountPoint from docker_entities.go
	NetworkSettings NetworkSettings           `json:"network_settings"`
	Config          *container.Config         `json:"config,omitempty"`
	HostConfig      *container.HostConfig     `json:"host_config,omitempty"`
	NetworkConfig   *network.NetworkingConfig `json:"network_config,omitempty"`
	Platform        *specs.Platform           `json:"platform,omitempty"`
	Stats           *ContainerStats           `json:"stats,omitempty"` // Use ContainerStats from docker_entities.go
	LogsSize        int64                     `json:"logs_size,omitempty"`
	SizeRw          int64                     `json:"size_rw,omitempty"`
	SizeRootFs      int64                     `json:"size_root_fs,omitempty"`
	RestartCount    int                       `json:"restart_count"`
	IsManaged       bool                      `json:"is_managed"`
	IsMonitored     bool                      `json:"is_monitored"`
	ComposeProject  string                    `json:"compose_project,omitempty"`
	ComposeService  string                    `json:"compose_service,omitempty"`
}

// ContainerHealth represents the health of a container
type ContainerHealth struct {
	Status        string      `json:"status"`
	FailingStreak int         `json:"failing_streak"`
	Log           []HealthLog `json:"log"`
}

// HealthLog represents a health log
type HealthLog struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	ExitCode int       `json:"exit_code"`
	Output   string    `json:"output"`
}

// NetworkSettings represents network settings
type NetworkSettings struct {
	Networks    map[string]EndpointSettings `json:"networks"`
	IPAddress   string                      `json:"ip_address"`
	IPPrefixLen int                         `json:"ip_prefix_len"`
	Gateway     string                      `json:"gateway"`
	Bridge      string                      `json:"bridge"`
	Ports       nat.PortMap                 `json:"ports"`
	MacAddress  string                      `json:"mac_address"`
	DNS         []string                    `json:"dns"`
	DNSOptions  []string                    `json:"dns_options"`
	DNSSearch   []string                    `json:"dns_search"`
}

// EndpointSettings represents endpoint settings
type EndpointSettings struct {
	IPAddress           string   `json:"ip_address"`
	IPPrefixLen         int      `json:"ip_prefix_len"`
	Gateway             string   `json:"gateway"`
	MacAddress          string   `json:"mac_address"`
	NetworkID           string   `json:"network_id"`
	EndpointID          string   `json:"endpoint_id"`
	GlobalIPv6Address   string   `json:"global_ipv6_address"`
	GlobalIPv6PrefixLen int      `json:"global_ipv6_prefix_len"`
	IPv6Gateway         string   `json:"ipv6_gateway"`
	Links               []string `json:"links"`
	Aliases             []string `json:"aliases"`
}

// FromDockerContainer converts a Docker container list item (types.Container) to a model container (DockerContainer)
// This is likely used by the inspector's list conversion.
func FromDockerContainer(c types.Container) DockerContainer {
	var ports []PortMapping
	for _, p := range c.Ports {
		ports = append(ports, PortMapping{
			HostIP:        p.IP,
			HostPort:      strconv.FormatUint(uint64(p.PublicPort), 10),
			ContainerPort: strconv.FormatUint(uint64(p.PrivatePort), 10),
			Type:          p.Type,
		})
	}

	var mounts []MountPoint
	for _, m := range c.Mounts {
		mounts = append(mounts, MountPoint{
			Type:        string(m.Type), // Convert mount.Type
			Name:        m.Name,
			Source:      m.Source,
			Destination: m.Destination,
			// Driver:      m.Driver, // Field might not exist
			Mode:        m.Mode,
			RW:          m.RW,
			Propagation: string(m.Propagation), // Convert mount.Propagation
		})
	}

	// state := ContainerState(formatContainerStatus(c.State, c.Status)) // Remove: types.Container doesn't have the State struct, only string. formatContainerStatus is available in package.

	// Direct assignment as SizeRw and SizeRootFs are int64, not pointers.
	sizeRw := c.SizeRw
	sizeRootFs := c.SizeRootFs

	container := DockerContainer{
		ID:      c.ID,
		Name:    trimContainerName(c.Names),
		Image:   c.Image,
		ImageID: c.ImageID,
		Command: c.Command,
		Created: time.Unix(c.Created, 0),
		// State:        state, // Remove: Cannot populate *types.ContainerState from types.Container
		Status:      c.Status,
		Ports:       ports,
		Labels:      c.Labels,
		Mounts:      mounts,
		SizeRw:      sizeRw,
		SizeRootFs:  sizeRootFs,
		IsManaged:   false,
		IsMonitored: false,
	}

	if c.NetworkSettings != nil {
		container.NetworkSettings = NetworkSettings{
			Networks: make(map[string]EndpointSettings),
		}
		for name, settings := range c.NetworkSettings.Networks {
			container.NetworkSettings.Networks[name] = EndpointSettings{
				IPAddress:           settings.IPAddress,
				IPPrefixLen:         settings.IPPrefixLen,
				Gateway:             settings.Gateway,
				MacAddress:          settings.MacAddress,
				NetworkID:           settings.NetworkID,
				EndpointID:          settings.EndpointID,
				GlobalIPv6Address:   settings.GlobalIPv6Address,
				GlobalIPv6PrefixLen: settings.GlobalIPv6PrefixLen,
				IPv6Gateway:         settings.IPv6Gateway,
				Links:               settings.Links,
				Aliases:             settings.Aliases,
			}
		}
	}

	if projectName, ok := c.Labels["com.docker_test.compose.project"]; ok {
		container.ComposeProject = projectName
	}
	if serviceName, ok := c.Labels["com.docker_test.compose.service"]; ok {
		container.ComposeService = serviceName
	}

	return container
}

// trimContainerName removes the leading slash from container names
func trimContainerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	name := names[0]
	if len(name) > 0 && name[0] == '/' {
		name = name[1:]
	}
	return name
}

// formatContainerStatus needs to be accessible here (moved to docker_entities.go)
// func formatContainerStatus(state, status string) string { ... }
