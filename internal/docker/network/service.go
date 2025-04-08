// Package network provides functionality for Docker network management
package network

import (
	"context"
	"errors"
	"time"

	// dockertypes "github.com/docker_test/docker_test/api/types" // Removed unused import
	"github.com/docker/docker/api/types/filters"
	networktypes "github.com/docker/docker/api/types/network" // Keep networktypes alias for specific network structs
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// ErrNetworkNotFound indicates that a network was not found
var ErrNetworkNotFound = errors.New("network not found")

// Service defines the interface for Docker network operations
type Service interface {
	// Create creates a new network
	Create(ctx context.Context, name string, options CreateOptions) (*models.Network, error)

	// Get gets a network by ID or name
	Get(ctx context.Context, idOrName string, options GetOptions) (*models.Network, error)

	// List lists networks
	List(ctx context.Context, options ListOptions) ([]*models.Network, error)

	// Remove removes a network
	Remove(ctx context.Context, idOrName string, options RemoveOptions) error

	// Prune removes unused networks
	Prune(ctx context.Context, options PruneOptions) (networktypes.PruneReport, error) // Changed dockertypes.NetworksPruneReport -> networktypes.PruneReport

	// Connect connects a container to a network
	Connect(ctx context.Context, networkIDOrName, containerIDOrName string, options ConnectOptions) error

	// Disconnect disconnects a container from a network
	Disconnect(ctx context.Context, networkIDOrName, containerIDOrName string, options DisconnectOptions) error

	// InspectRaw gets the raw information about a network
	InspectRaw(ctx context.Context, idOrName string) (networktypes.Inspect, error) // Changed networktypes.NetworkResource -> networktypes.Inspect

	// GetNetworkDrivers returns the list of available network drivers
	GetNetworkDrivers(ctx context.Context) ([]string, error)

	// FindNetworkByContainer finds networks connected to a container
	FindNetworkByContainer(ctx context.Context, containerIDOrName string, options ListOptions) ([]*models.Network, error)

	// FindNetworkByName finds networks by name pattern
	FindNetworkByName(ctx context.Context, pattern string, options ListOptions) ([]*models.Network, error)

	// FindNetworkBySubnet finds networks by subnet
	FindNetworkBySubnet(ctx context.Context, subnet string, options ListOptions) ([]*models.Network, error)
}

// CreateOptions defines options for creating a network
type CreateOptions struct {
	// Driver is the network driver name
	Driver string

	// IPAM is the IPAM configuration
	IPAM *networktypes.IPAM // Use networktypes alias

	// Options are driver specific options
	Options map[string]string

	// Labels are labels to set on the network
	Labels map[string]string

	// EnableIPv6 indicates whether to enable IPv6
	EnableIPv6 bool

	// Internal indicates whether the network is internal
	Internal bool

	// Attachable indicates whether containers can be attached to this network
	Attachable bool

	// Ingress indicates whether the network is an ingress network
	Ingress bool

	// ConfigOnly indicates whether the network is a configuration only network
	ConfigOnly bool

	// Scope is the network scope
	Scope string

	// CheckDuplicate checks for networks with same name
	CheckDuplicate bool

	// Timeout is the operation timeout
	Timeout time.Duration

	// Logger is the logger
	Logger *logrus.Logger
}

// GetOptions defines options for getting a network
type GetOptions struct {
	// Verbose indicates whether to include verbose information
	Verbose bool

	// Scope is the network scope
	Scope string

	// Timeout is the operation timeout
	Timeout time.Duration

	// Logger is the logger
	Logger *logrus.Logger
}

// ListOptions defines options for listing networks
type ListOptions struct {
	// Filters are the filters to apply
	Filters filters.Args

	// NameOnly indicates whether to include only the network name
	NameOnly bool

	// Timeout is the operation timeout
	Timeout time.Duration

	// Logger is the logger
	Logger *logrus.Logger
}

// RemoveOptions defines options for removing a network
type RemoveOptions struct {
	// Force indicates whether to force removal
	Force bool

	// Timeout is the operation timeout
	Timeout time.Duration

	// Logger is the logger
	Logger *logrus.Logger
}

// PruneOptions defines options for pruning networks
type PruneOptions struct {
	// Filters are the filters to apply
	Filters filters.Args

	// Timeout is the operation timeout
	Timeout time.Duration

	// Logger is the logger
	Logger *logrus.Logger
}

// ConnectOptions defines options for connecting a container to a network
type ConnectOptions struct {
	// EndpointConfig is the endpoint configuration
	EndpointConfig *networktypes.EndpointSettings // Use networktypes alias

	// Force indicates whether to bypass validation and force connection
	Force bool

	// Timeout is the operation timeout
	Timeout time.Duration

	// Logger is the logger
	Logger *logrus.Logger
}

// DisconnectOptions defines options for disconnecting a container from a network
type DisconnectOptions struct {
	// Force indicates whether to force disconnection
	Force bool

	// Timeout is the operation timeout
	Timeout time.Duration

	// Logger is the logger
	Logger *logrus.Logger
}

// NetworkFilter defines filters for looking up networks
type NetworkFilter struct {
	// Name is the network name filter
	Name string

	// ID is the network ID filter
	ID string

	// Driver is the driver name filter
	Driver string

	// Scope is the scope filter
	Scope string

	// Type is the type filter
	Type string

	// LabelFilter is the label filter
	LabelFilter string

	// Dangling indicates whether to include only dangling networks
	Dangling bool

	// Custom is a map of custom filters
	Custom map[string][]string
}

// ToFilters converts a NetworkFilter to filters.Args
func (f *NetworkFilter) ToFilters() filters.Args {
	// Create a new filter
	filter := filters.NewArgs()

	// Add filters
	if f.Name != "" {
		filter.Add("name", f.Name)
	}
	if f.ID != "" {
		filter.Add("id", f.ID)
	}
	if f.Driver != "" {
		filter.Add("driver", f.Driver)
	}
	if f.Scope != "" {
		filter.Add("scope", f.Scope)
	}
	if f.Type != "" {
		filter.Add("type", f.Type)
	}
	if f.LabelFilter != "" {
		filter.Add("label", f.LabelFilter)
	}
	if f.Dangling {
		filter.Add("dangling", "true")
	}

	// Add custom filters
	for key, values := range f.Custom {
		for _, value := range values {
			filter.Add(key, value)
		}
	}

	return filter
}

// Event types for network events
const (
	// NetworkEventTypeCreate is the event type for network creation
	NetworkEventTypeCreate = "create"

	// NetworkEventTypeConnect is the event type for network connection
	NetworkEventTypeConnect = "connect"

	// NetworkEventTypeDestroy is the event type for network destruction
	NetworkEventTypeDestroy = "destroy"

	// NetworkEventTypeDisconnect is the event type for network disconnection
	NetworkEventTypeDisconnect = "disconnect"

	// NetworkEventTypeRemove is the event type for network removal
	NetworkEventTypeRemove = "remove"
)
