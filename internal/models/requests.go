package models

import (
	"mime/multipart"
	"time"
)

// PaginationRequest represents pagination parameters for API requests
type PaginationRequest struct {
	Page     int `json:"page" form:"page" binding:"gte=1" example:"1"`
	PageSize int `json:"page_size" form:"page_size" binding:"gte=1,lte=100" example:"10"`
}

// SetDefaults sets default values for the pagination request
func (p *PaginationRequest) SetDefaults() {
	if p.Page <= 0 {
		p.Page = 1
	}
	if p.PageSize <= 0 {
		p.PageSize = 10
	} else if p.PageSize > 100 {
		p.PageSize = 100
	}
}

// GetOffset returns the offset for the pagination request
func (p *PaginationRequest) GetOffset() int {
	return (p.Page - 1) * p.PageSize
}

// SortRequest represents sorting parameters for API requests
type SortRequest struct {
	SortBy    string `json:"sort_by" form:"sort_by" example:"name"`
	SortOrder string `json:"sort_order" form:"sort_order" binding:"omitempty,oneof=asc desc" example:"asc"`
}

// SetDefaults sets default values for the sort request
func (s *SortRequest) SetDefaults(defaultSortBy string) {
	if s.SortBy == "" {
		s.SortBy = defaultSortBy
	}
	if s.SortOrder == "" {
		s.SortOrder = "asc"
	}
}

// FilterRequest represents filtering parameters for API requests
type FilterRequest struct {
	Search    string            `json:"search" form:"search" example:"my-app"`
	Filters   map[string]string `json:"filters" form:"filters" example:"label=production,status=running"`
	StartDate *time.Time        `json:"start_date" form:"start_date" format:"date-time" example:"2023-10-26T00:00:00Z"`
	EndDate   *time.Time        `json:"end_date" form:"end_date" format:"date-time" example:"2023-10-27T23:59:59Z"`
}

// -----------------------
// Authentication Requests
// -----------------------

// RegisterRequest represents a user registration request
// @description Data required for registering a new user account.
type RegisterRequest struct {
	// Email is the user's email address, used for login.
	// required: true
	// example: user@example.com
	Email string `json:"email" binding:"required,email" example:"user@example.com"`

	// Password is the user's desired password (min 8 characters).
	// required: true
	// example: StrongP@ssw0rd!
	Password string `json:"password" binding:"required,min=8" example:"StrongP@ssw0rd!"`

	// Name is the user's display name.
	// required: true
	// example: John Doe
	Name string `json:"name" binding:"required" example:"John Doe"`

	// InviteCode is an optional code required for registration if the system is configured for invite-only.
	// example: ABC-123
	InviteCode string `json:"invite_code" example:"ABC-123"` // Optional, depends on system configuration
}

// LoginRequest represents a user login request
// @description Credentials required for user login.
type LoginRequest struct {
	// Email is the user's registered email address.
	// required: true
	// example: user@example.com
	Email string `json:"email" binding:"required,email" example:"user@example.com"`

	// Password is the user's password.
	// required: true
	// example: StrongP@ssw0rd!
	Password string `json:"password" binding:"required" example:"StrongP@ssw0rd!"`
}

// RefreshTokenRequest represents a token refresh request
// @description Contains the refresh token needed to obtain a new access token.
type RefreshTokenRequest struct {
	// RefreshToken is the valid refresh token previously issued to the user.
	// required: true
	// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (long token string)
	RefreshToken string `json:"refresh_token" binding:"required" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// ChangePasswordRequest represents a password change request
// @description Data required for a user to change their own password.
type ChangePasswordRequest struct {
	// CurrentPassword is the user's existing password.
	// required: true
	// example: OldP@ssw0rd!
	CurrentPassword string `json:"current_password" binding:"required" example:"OldP@ssw0rd!"`

	// NewPassword is the desired new password (min 8 characters).
	// required: true
	// example: NewStrongP@ssw0rd!
	NewPassword string `json:"new_password" binding:"required,min=8" example:"NewStrongP@ssw0rd!"`
}

// AdminCreateUserRequest represents a request by an admin to create a new user
// @description Data required for an administrator to create a new user account.
type AdminCreateUserRequest struct {
	// Email is the new user's email address.
	// required: true
	// example: newuser@example.com
	Email string `json:"email" binding:"required,email" example:"newuser@example.com"`

	// Password is the initial password for the new user (min 8 characters).
	// required: true
	// example: InitialP@ssw0rd!
	Password string `json:"password" binding:"required,min=8" example:"InitialP@ssw0rd!"`

	// Name is the new user's display name.
	// required: true
	// example: Jane Smith
	Name string `json:"name" binding:"required" example:"Jane Smith"`

	// Roles is an optional list of roles to assign to the new user.
	// example: ["user", "editor"]
	Roles []string `json:"roles" example:"user,editor"` // Optional: roles to assign (e.g., ["user", "admin"])

	// Active specifies if the new user account should be active immediately. Defaults to true if omitted.
	// example: true
	Active bool `json:"active" example:"true"` // Optional: defaults to true if omitted

	// EmailVerified specifies if the new user's email should be marked as verified. Defaults to false.
	// example: false
	EmailVerified bool `json:"email_verified" example:"false"` // Optional: defaults to false
}

// AdminUpdateUserRequest represents a request by an admin to update a user
// @description Data for an administrator to update an existing user's details. All fields are optional.
type AdminUpdateUserRequest struct {
	// Name is the user's updated display name.
	// example: "Johnathan Doe"
	Name *string `json:"name" example:"Johnathan Doe"` // Optional: Pointer to allow omitting

	// Email is the user's updated email address. If changed, email verification status might be reset.
	// example: "john.doe.updated@example.com"
	Email *string `json:"email" example:"john.doe.updated@example.com"` // Optional: Pointer to allow omitting

	// Roles is the updated list of roles for the user. An empty slice clears existing roles.
	// example: ["user", "admin"]
	Roles *[]string `json:"roles" example:"user,admin"` // Optional: Pointer to allow omitting (empty slice means clear roles)

	// Active specifies whether the user account should be active.
	// example: false
	Active *bool `json:"active" example:"false"` // Optional: Pointer to allow omitting

	// EmailVerified specifies whether the user's email address is verified.
	// example: true
	EmailVerified *bool `json:"email_verified" example:"true"` // Optional: Pointer to allow omitting
}

// -----------------------
// Container Requests
// -----------------------

// ContainerCreateRequest represents a container creation request.
// @description Configuration details for creating a new Docker container.
type ContainerCreateRequest struct {
	// Name is the name to assign to the new container.
	// required: true
	// example: "my-nginx-container"
	Name string `json:"name" binding:"required" example:"my-nginx-container"`

	// Image is the name or ID of the Docker image to use.
	// required: true
	// example: "nginx:latest"
	Image string `json:"image" binding:"required" example:"nginx:latest"`

	// Command is the command to run when the container starts.
	// example: ["nginx", "-g", "daemon off;"]
	Command []string `json:"command" example:"nginx,-g,daemon off;"`

	// Entrypoint overrides the default entrypoint of the image.
	// example: ["/docker-entrypoint.sh"]
	Entrypoint []string `json:"entrypoint" example:"/docker-entrypoint.sh"`

	// Env is a list of environment variables to set in the container (e.g., "VAR=value").
	// example: ["NGINX_HOST=example.com", "NGINX_PORT=80"]
	Env []string `json:"env" example:"NGINX_HOST=example.com,NGINX_PORT=80"`

	// Labels are key-value pairs to apply to the container.
	// example: {"environment": "development", "app": "webserver"}
	Labels map[string]string `json:"labels" example:"environment:development,app:webserver"`

	// Ports specifies the port mappings between the host and the container.
	Ports []PortMapping `json:"ports"`

	// Volumes specifies the volume mappings between the host/named volumes and the container.
	Volumes []VolumeMapping `json:"volumes"`

	// Networks is a list of network names or IDs to connect the container to.
	// example: ["my-app-network"]
	Networks []string `json:"networks" example:"my-app-network"`

	// RestartPolicy defines the container's behavior when it exits.
	// example: "unless-stopped"
	RestartPolicy string `json:"restart_policy" binding:"omitempty,oneof=no on-failure always unless-stopped" example:"unless-stopped"`

	// MemoryLimit is the maximum amount of memory the container can use (in bytes).
	// example: 104857600 (100MB)
	MemoryLimit int64 `json:"memory_limit" example:"104857600"` // 100MB

	// CPULimit specifies the CPU quota for the container (e.g., 1.5 means 1.5 CPU cores). Docker uses NanoCPUs (1e9 per core).
	// example: 1.5
	CPULimit float64 `json:"cpu_limit" example:"1.5"` // 1.5 CPU cores

	// Privileged gives the container extended privileges on the host. Use with caution.
	// example: false
	Privileged bool `json:"privileged" example:"false"`

	// AutoRemove automatically removes the container when it exits.
	// example: false
	AutoRemove bool `json:"auto_remove" example:"false"`

	// Notes are user-defined notes for the container (stored in application DB).
	// example: "Main web server container."
	Notes string `json:"notes" example:"Main web server container."`
}

// ContainerExecStartRequest represents a request to start an exec instance
type ContainerExecStartRequest struct {
	ExecID      string `json:"exec_id" binding:"required" example:"a1b2c3d4e5f6"`
	Tty         bool   `json:"tty" example:"true"`
	DetachKeys  string `json:"detach_keys" example:"ctrl-p,ctrl-q"`
	StdinBase64 string `json:"stdin_base64" example:"aGVsbG8gd29ybGQK"` // Base64 encoded input for non-websocket start
}

// ContainerExecResizeRequest represents a request to resize an exec instance's TTY
type ContainerExecResizeRequest struct {
	ExecID string `json:"exec_id" binding:"required" example:"a1b2c3d4e5f6"`
	Height int    `json:"height" binding:"required,gt=0" example:"24"`
	Width  int    `json:"width" binding:"required,gt=0" example:"80"`
}

// VolumeMapping represents a volume mount configuration for a container.
// @description Defines how a host path or named volume is mounted into a container.
type VolumeMapping struct {
	// Source is the name of the volume or the path on the host machine.
	// required: true
	// example: "my-app-data" or "/path/on/host"
	Source string `json:"source" binding:"required" example:"my-app-data"` // or "/path/on/host"

	// Destination is the absolute path inside the container where the volume is mounted.
	// required: true
	// example: "/var/www/html"
	Destination string `json:"destination" binding:"required" example:"/var/www/html"`

	// ReadOnly specifies whether the mount should be read-only within the container.
	// example: false
	ReadOnly bool `json:"read_only" example:"false"`
}

// ContainerListRequest represents a container list request
type ContainerListRequest struct {
	PaginationRequest
	SortRequest
	FilterRequest
	All       bool   `json:"all" form:"all" example:"false"`
	Status    string `json:"status" form:"status" binding:"omitempty,oneof=running stopped created paused restarting removing exited dead" example:"running"`
	ImageID   string `json:"image_id" form:"image_id" example:"sha256:a1b2c3d4..."`
	NetworkID string `json:"network_id" form:"network_id" example:"net_abc123"`
	VolumeID  string `json:"volume_id" form:"volume_id" example:"vol_def456"`
}

// ContainerStartRequest represents a container start request
type ContainerStartRequest struct {
	CheckpointID string `json:"checkpoint_id" example:"my-checkpoint"`
}

// ContainerStopRequest represents a container stop request
type ContainerStopRequest struct {
	Timeout int `json:"timeout" binding:"omitempty,gte=0" example:"10"` // Seconds
}

// ContainerRenameRequest represents a request to rename a container.
// @description Specifies the new name for an existing container.
type ContainerRenameRequest struct {
	// Name is the new name to assign to the container. Must be unique.
	// required: true
	// example: "my-renamed-nginx"
	Name string `json:"name" binding:"required" example:"my-renamed-nginx"`
}

// ContainerExecCreateRequest represents a container exec creation request
// @description Configuration for creating a new exec instance in a container.
type ContainerExecCreateRequest struct {
	// Command is the command to execute in the container, with arguments.
	// required: true
	// example: ["/bin/bash", "-c", "echo hello"]
	Command []string `json:"command" binding:"required" example:"/bin/bash,-c,echo hello"`

	// AttachStdin specifies whether to attach stdin to the exec command.
	// example: false
	AttachStdin bool `json:"attach_stdin" example:"false"`

	// AttachStdout specifies whether to attach stdout to the exec command.
	// example: true
	AttachStdout bool `json:"attach_stdout" example:"true"`

	// AttachStderr specifies whether to attach stderr to the exec command.
	// example: true
	AttachStderr bool `json:"attach_stderr" example:"true"`

	// DetachKeys specifies the key sequence for detaching from the exec session.
	// example: "ctrl-p,ctrl-q"
	DetachKeys string `json:"detach_keys" example:"ctrl-p,ctrl-q"`

	// Tty specifies whether to allocate a pseudo-TTY for the exec command. Required for interactive sessions.
	// example: false
	Tty bool `json:"tty" example:"false"`

	// Env specifies environment variables to set in the exec command's environment.
	// example: ["VAR1=value1", "VAR2=value2"]
	Env []string `json:"env" example:"VAR1=value1,VAR2=value2"`

	// Privileged specifies whether to run the exec command in privileged mode.
	// example: false
	Privileged bool `json:"privileged" example:"false"`

	// WorkingDir specifies the working directory inside the container for the exec command.
	// example: "/app"
	WorkingDir string `json:"working_dir" example:"/app"`
}

// FileEditRequest represents a request to edit or create a file within a container.
// @description Data required to modify or create a file inside a container.
type FileEditRequest struct {
	// Path is the absolute path to the file inside the container.
	// required: true
	// example: "/app/config.json"
	Path string `json:"path" binding:"required" example:"/app/config.json"`

	// Content is the new content for the file, encoded in Base64.
	// required: true
	// example: "ewogICJhcGlLZXkiOiAiYWJjMTIzIgp9Cg=="
	Content string `json:"content" binding:"required" example:"ewogICJhcGlLZXkiOiAiYWJjMTIzIgp9Cg=="` // Base64 encoded content

	// Create specifies whether to create the file if it doesn't exist. Defaults to false.
	// example: false
	Create bool `json:"create" example:"false"` // Flag to create the file if it doesn't exist
}

// ContainerLogsRequest represents parameters for retrieving container logs.
// @description Query parameters to control log retrieval, including filtering and streaming.
type ContainerLogsRequest struct {
	// Follow streams the logs in real-time.
	// example: false
	Follow bool `json:"follow" form:"follow" example:"false"`

	// Since shows logs since a specific timestamp (RFC3339 or Unix timestamp) or relative duration (e.g., "10m").
	// example: "2023-10-27T10:00:00Z"
	Since time.Time `json:"since" form:"since" time_format:"rfc3339" example:"2023-10-27T10:00:00Z"` // Added time_format

	// Until shows logs before a specific timestamp (RFC3339 or Unix timestamp) or relative duration (e.g., "5m").
	// example: "2023-10-27T11:00:00Z"
	Until time.Time `json:"until" form:"until" time_format:"rfc3339" example:"2023-10-27T11:00:00Z"` // Added time_format

	// Timestamps includes timestamps for each log line.
	// example: true
	Timestamps bool `json:"timestamps" form:"timestamps" example:"true"`

	// Tail specifies the number of lines to show from the end of the logs (e.g., "100" or "all").
	// example: "100"
	Tail string `json:"tail" form:"tail" example:"100"`

	// ShowStdout includes stdout logs. Defaults to true if neither stdout nor stderr is specified.
	// example: true
	ShowStdout bool `json:"stdout" form:"stdout" example:"true"`

	// ShowStderr includes stderr logs. Defaults to true if neither stdout nor stderr is specified.
	// example: true
	ShowStderr bool `json:"stderr" form:"stderr" example:"true"`
}

// -----------------------
// Image Requests
// -----------------------

// ImageListRequest represents an image list request
type ImageListRequest struct {
	PaginationRequest
	SortRequest
	FilterRequest
	All        bool   `json:"all" form:"all" example:"false"`
	Repository string `json:"repository" form:"repository" example:"nginx"`
	Tag        string `json:"tag" form:"tag" example:"latest"`
	Digest     string `json:"digest" form:"digest" example:"sha256:a1b2c3d4..."`
}

// ImagePullRequest represents a request to pull a Docker image from a registry.
// @description Specifies the image to pull and optional credentials for private registries.
type ImagePullRequest struct {
	// Image is the name of the image to pull (e.g., "nginx", "myregistry.com/myapp").
	// required: true
	// example: "nginx"
	Image string `json:"image" binding:"required" example:"nginx"`

	// Tag is the specific tag of the image to pull. Defaults to "latest" if omitted.
	// example: "1.21-alpine"
	Tag string `json:"tag" example:"1.21-alpine"`

	// Credentials contains optional username and password for authenticating with a private registry.
	Credentials struct {
		// Username for the private registry.
		// example: "dockerhub_user"
		Username string `json:"username" example:"dockerhub_user"`
		// Password or access token for the private registry.
		// example: "mysecretpassword"
		Password string `json:"password" example:"mysecretpassword"`
	} `json:"credentials"`
}

// ImageBuildRequest represents an image build request
type ImageBuildRequest struct {
	Repository    string                `json:"repository" binding:"required" example:"my-custom-app"`
	Tag           string                `json:"tag" example:"v1.0"`
	Dockerfile    string                `json:"dockerfile" example:"Dockerfile.prod"`
	Context       string                `json:"context" example:"."`               // Path to build context (directory)
	ContextFile   *multipart.FileHeader `json:"context_file" swaggerignore:"true"` // Use multipart form for context upload
	BuildArgs     map[string]string     `json:"build_args" example:"VERSION=1.0,API_KEY=abcdef"`
	Labels        map[string]string     `json:"labels" example:"maintainer=devteam,project=webapp"`
	NoCache       bool                  `json:"no_cache" example:"false"`
	Pull          bool                  `json:"pull" example:"true"` // Attempt to pull newer image layers
	RemoteContext string                `json:"remote_context" example:"git://github.com/user/repo.git#main:subdir"`
}

// ImageTagRequest represents a request to tag an existing Docker image.
// @description Specifies the source image and the new repository/tag to apply.
type ImageTagRequest struct {
	// SourceImage is the ID or current name:tag of the image to tag.
	// required: true
	// example: "nginx:latest" or "sha256:a1b2c3d4..."
	SourceImage string `json:"source_image" binding:"required" example:"nginx:latest"` // Image ID or Name:Tag to tag

	// Repository is the repository name for the new tag.
	// required: true
	// example: "my-custom-nginx"
	Repository string `json:"repository" binding:"required" example:"my-custom-nginx"`

	// Tag is the tag name for the new tag.
	// required: true
	// example: "v1.0"
	Tag string `json:"tag" binding:"required" example:"v1.0"`
}

// ImageRemoveRequest represents an image remove request
type ImageRemoveRequest struct {
	Force         bool `json:"force" example:"false"`
	PruneChildren bool `json:"prune_children" example:"false"`
}

// -----------------------
// Volume Requests
// -----------------------

// VolumeListRequest represents parameters for listing Docker volumes.
// @description Query parameters for filtering, sorting, and paginating the list of Docker volumes.
type VolumeListRequest struct {
	PaginationRequest // Embeds Page and PageSize
	SortRequest       // Embeds SortBy and SortOrder
	FilterRequest     // Embeds Search, Filters, StartDate, EndDate
	// Driver filters volumes by the specified driver name.
	// example: local
	Driver string `json:"driver" form:"driver" example:"local"`
}

// VolumeCreateRequest represents a volume creation request.
// @description Configuration details for creating a new Docker volume.
type VolumeCreateRequest struct {
	// Name is the name for the new volume.
	// required: true
	// example: my-app-data
	Name string `json:"name" binding:"required" example:"my-app-data"`

	// Driver specifies the volume driver to use. Defaults to "local".
	// example: local
	Driver string `json:"driver" example:"local"`

	// DriverOpts are driver-specific options.
	// example: {"type": "nfs", "o": "addr=192.168.1.1,rw"}
	DriverOpts map[string]string `json:"driver_opts"` // Example removed due to swag parsing issues

	// Labels are key-value pairs to apply to the volume.
	// example: {"environment": "production", "backup": "true"}
	Labels map[string]string `json:"labels" example:"backup=true,environment=production"`

	// Notes are user-defined notes for the volume (stored in the application DB).
	// example: "Persistent data for the main database."
	Notes string `json:"notes" example:"Persistent data for the main application."`
}

// VolumePruneRequest represents parameters for pruning unused Docker volumes.
// @description Query parameters for filtering which volumes to prune.
type VolumePruneRequest struct {
	FilterRequest // Embeds Search, Filters, StartDate, EndDate
}

// VolumeCloneRequest represents a volume clone request
type VolumeCloneRequest struct {
	TargetName string            `json:"target_name" binding:"required"`
	Labels     map[string]string `json:"labels" example:"backup=true,environment=production"`
}

// VolumePermissionsRequest represents a request to update volume ownership (currently only supports transferring ownership).
// @description Specifies the user ID to whom the volume ownership should be transferred. This is an application-level concept, not a Docker feature.
type VolumePermissionsRequest struct {
	// UserID is the ID of the user who will become the new owner of the volume record in the application database.
	// required: true
	// example: 2
	UserID uint `json:"user_id" binding:"required"` // ID of the user to transfer ownership to
}

// -----------------------
// Network Requests
// -----------------------

// NetworkListRequest represents parameters for listing Docker networks.
// @description Query parameters for filtering, sorting, and paginating the list of Docker networks.
type NetworkListRequest struct {
	PaginationRequest // Embeds Page and PageSize
	SortRequest       // Embeds SortBy and SortOrder
	FilterRequest     // Embeds Search, Filters, StartDate, EndDate
	// Driver filters networks by the specified driver name.
	// example: bridge
	Driver string `json:"driver" form:"driver"`
}

// NetworkCreateRequest represents a network creation request.
// @description Configuration details for creating a new Docker network.
type NetworkCreateRequest struct {
	// Name is the name for the new network.
	// required: true
	// example: my-app-network
	Name string `json:"name" binding:"required" example:"my-app-network"`

	// Driver specifies the network driver to use (e.g., bridge, overlay). Defaults to bridge.
	// example: bridge
	Driver string `json:"driver" example:"bridge"`

	// Internal restricts external access to the network.
	// example: false
	Internal bool `json:"internal" example:"false"`

	// Labels are key-value pairs to apply to the network.
	// example: {"environment": "production", "project": "webapp"}
	Labels map[string]string `json:"labels" example:"project:myapp,tier:backend"`

	// Options are driver-specific options.
	// example: {"com.docker.network.bridge.name": "mybridge0"}
	Options map[string]string `json:"options"` // Example removed due to swag parsing issues

	// EnableIPv6 enables IPv6 support for the network.
	// example: false
	EnableIPv6 bool `json:"enable_ipv6" example:"false"`

	// Attachable allows non-service containers to attach to this network (useful for overlay networks).
	// example: true
	Attachable bool `json:"attachable" example:"true"`

	// Ingress indicates the network provides the routing-mesh in swarm mode.
	// example: false
	Ingress bool `json:"ingress"` // Added

	// ConfigOnly specifies that the network configuration is only used for services.
	// example: false
	ConfigOnly bool `json:"config_only"` // Added

	// Scope specifies the network scope (e.g., local, swarm).
	// example: local
	Scope string `json:"scope"` // Added

	// IPAM provides custom IP Address Management configuration.
	IPAM *IPAMCreateRequest `json:"ipam"` // Added

	// Notes are user-defined notes for the network (stored in the application DB).
	// example: "Main network for the web application stack."
	Notes string `json:"notes" example:"Network for backend services."`
}

// IPAMCreateRequest represents IPAM (IP Address Management) configuration for network creation.
// @description Detailed IPAM settings for a new Docker network.
type IPAMCreateRequest struct {
	// Driver specifies the IPAM driver to use (e.g., "default").
	// example: default
	Driver string `json:"driver" example:"default"`

	// Options are IPAM driver specific options.
	Options map[string]string `json:"options"` // Example removed due to swag parsing issues

	// Config is a list of IPAM configurations, each specifying subnet, gateway, etc.
	Config []IPAMConfigRequest `json:"config"`
}

// IPAMConfigRequest represents IPAM config details for network creation.
// @description Specific IPAM configuration block defining subnet, gateway, etc.
type IPAMConfigRequest struct {
	// Subnet in CIDR format that represents a network segment.
	// example: 172.28.0.0/16
	Subnet string `json:"subnet" example:"172.20.0.0/16"`

	// IPRange specifies a range of IP addresses for containers in CIDR format.
	// example: 172.28.5.0/24
	IPRange string `json:"ip_range" example:"172.20.10.0/24"`

	// Gateway is the IPv4 or IPv6 gateway for the subnet.
	// example: 172.28.5.254
	Gateway string `json:"gateway" example:"172.20.0.1"`

	// AuxAddress is a map of auxiliary addresses used by the IPAM driver.
	// example: {"host1": "172.28.1.5"}
	AuxAddress map[string]string `json:"aux_address"`
}

// NetworkConnectRequest represents a request to connect a container to a network.
// @description Specifies the container and optional endpoint settings for connecting to a network.
type NetworkConnectRequest struct {
	// Container is the ID or name of the container to connect.
	// required: true
	// example: my-web-container
	Container string `json:"container" binding:"required" example:"my-app-container"` // Container ID or Name

	// EndpointConfig provides custom network settings for the container within this network.
	EndpointConfig *EndpointSettingsRequest `json:"endpoint_config"` // Added
}

// EndpointSettingsRequest represents endpoint settings for connecting a container to a network.
// @description Configuration for the container's endpoint within the network.
type EndpointSettingsRequest struct {
	// IPAMConfig allows specifying a static IP address for the container in this network.
	IPAMConfig *EndpointIPAMConfigRequest `json:"ipam_config"`

	// Aliases are network-scoped aliases for the container.
	// example: ["web", "frontend"]
	Aliases []string `json:"aliases" example:"app,web"`
	// Add other fields like Links, DriverOpts if needed
}

// EndpointIPAMConfigRequest represents endpoint IPAM config for connecting a container.
// @description Specifies static IP addresses for a container's network endpoint.
type EndpointIPAMConfigRequest struct {
	// IPv4Address is the static IPv4 address to assign to the container.
	// example: 172.28.5.10
	IPv4Address string `json:"ipv4_address" example:"172.20.10.5"`

	// IPv6Address is the static IPv6 address to assign to the container.
	// example: "2001:db8:abcd::10"
	IPv6Address string `json:"ipv6_address" example:"2001:db8:abcd::5"`
	// Add LinkLocalIPs if needed
}

// NetworkDisconnectRequest represents a request to disconnect a container from a network.
// @description Specifies the container to disconnect from a network.
type NetworkDisconnectRequest struct {
	// Container is the ID or name of the container to disconnect.
	// required: true
	// example: my-web-container
	Container string `json:"container" binding:"required" example:"my-app-container"` // Container ID or Name

	// Force disconnects the container even if it is running.
	// example: false
	Force bool `json:"force" example:"false"`
}

// NetworkCreateOptions represents options for creating a network
// Based on fields used in pkg/client/networks.go CreateNetwork function
type NetworkCreateOptions struct {
	Name       string            `json:"Name" binding:"required"` // Match Docker API field name
	Driver     string            `json:"Driver,omitempty"`
	Internal   bool              `json:"Internal,omitempty"`
	Attachable bool              `json:"Attachable,omitempty"`
	Ingress    bool              `json:"Ingress,omitempty"` // Common overlay option
	EnableIPv6 bool              `json:"EnableIPv6,omitempty"`
	IPAM       *IPAM             `json:"IPAM,omitempty"` // Reusing IPAM struct from docker_entities.go
	Options    map[string]string `json:"Options,omitempty"`
	Labels     map[string]string `json:"Labels,omitempty"`
}

// NetworkUpdateOptions represents options for updating a network (Placeholder)
// pkg/client/networks.go UpdateNetwork currently takes this, but its fields aren't defined.
// Add fields as needed based on API requirements.
type NetworkUpdateOptions struct {
	// Example: Labels map[string]string `json:"Labels,omitempty"`
}

// -----------------------
// Volume Requests
// -----------------------

// VolumeCreateOptions represents options for creating a volume
// Based on fields used in pkg/client/volumes.go CreateVolume function
type VolumeCreateOptions struct {
	Name       string            `json:"Name" binding:"required"` // Match Docker API field name
	Driver     string            `json:"Driver,omitempty"`
	DriverOpts map[string]string `json:"DriverOpts,omitempty"`
	Labels     map[string]string `json:"Labels,omitempty"`
}

// NetworkPruneRequest represents parameters for pruning unused Docker networks.
// @description Query parameters for filtering which networks to prune.
type NetworkPruneRequest struct {
	FilterRequest // Embeds Search, Filters, StartDate, EndDate
}

// -----------------------
// Compose Requests
// -----------------------

// ComposeValidateRequest represents a request to validate compose file content.
// @description Contains the Docker Compose file content (YAML) to be validated.
type ComposeValidateRequest struct {
	// ComposeFileContent is the raw YAML content of the Docker Compose file.
	// required: true
	// example: "version: '3.8'\nservices:\n  web:\n    image: nginx:latest\n"
	ComposeFileContent string `json:"compose_file_content" binding:"required" example:"version: '3.8'\nservices:\n  web:\n    image: nginx:latest\n    ports:\n      - \"8080:80\"\n"`
}

// ComposeUpRequest represents a request to deploy a compose project.
// @description Contains the Docker Compose file content and options for deploying a project.
type ComposeUpRequest struct {
	// ProjectName is the name to assign to the Compose project.
	// required: true
	// example: "my-web-app"
	ProjectName string `json:"project_name" binding:"required"`

	// ComposeFileContent is the raw YAML content of the Docker Compose file.
	// required: true
	// example: "version: '3.8'\nservices:\n  web:\n    image: nginx:latest\n"
	ComposeFileContent string `json:"compose_file_content" binding:"required" example:"version: '3.8'\nservices:\n  web:\n    image: nginx:latest\n    ports:\n      - \"8080:80\"\n"`

	// ForceRecreate forces the recreation of containers even if their configuration hasn't changed.
	// example: false
	ForceRecreate bool `json:"force_recreate" example:"false"`

	// NoBuild disables building images before starting containers.
	// example: false
	NoBuild bool `json:"no_build" example:"false"`

	// NoStart creates containers but does not start them.
	// example: false
	NoStart bool `json:"no_start"`

	// Pull attempts to pull newer versions of images before starting containers.
	// example: true
	Pull bool `json:"pull"`

	// RemoveOrphans removes containers for services not defined in the Compose file.
	// example: false
	RemoveOrphans bool `json:"remove_orphans" example:"false"`
	// Add Timeout, DependencyTimeout if needed
}

// ComposeDownRequest represents parameters for removing a compose project.
// @description Query parameters specifying options for taking down a Compose deployment.
type ComposeDownRequest struct {
	// RemoveVolumes removes named volumes declared in the 'volumes' section of the Compose file and anonymous volumes attached to containers.
	// example: false
	RemoveVolumes bool `form:"remove_volumes"`

	// RemoveOrphans removes containers for services not defined in the Compose file.
	// example: false
	RemoveOrphans bool `form:"remove_orphans"`

	// Force forces the removal of containers.
	// example: false
	Force bool `form:"force"`
	// Add Timeout if needed
}

// ComposeStartRequest represents a request to start a compose project's services.
// @description Currently has no specific options, but acts as a placeholder.
type ComposeStartRequest struct {
	// Add Timeout if needed
}

// ComposeStopRequest represents parameters for stopping a compose project's services.
// @description Query parameters for stopping services in a Compose deployment.
type ComposeStopRequest struct {
	// Timeout specifies the shutdown timeout in seconds for containers.
	// example: 10
	Timeout int `form:"timeout" binding:"omitempty,gte=0"` // Timeout in seconds
}

// ComposeScaleRequest represents a request to scale a specific service within a compose project.
// @description Specifies the service and the desired number of replicas.
type ComposeScaleRequest struct {
	// Service is the name of the service to scale.
	// required: true
	// example: "worker"
	Service string `json:"service" binding:"required" example:"worker"`

	// Replicas is the desired number of containers for the service.
	// required: true
	// example: 3
	Replicas int `json:"replicas" binding:"required,gte=0" example:"3"`
}

// ComposeRestartRequest represents parameters for restarting a compose project's services.
// @description Query parameters for restarting services in a Compose deployment.
type ComposeRestartRequest struct {
	// Timeout specifies the shutdown timeout in seconds before restarting containers.
	// example: 10
	Timeout int `form:"timeout" binding:"omitempty,gte=0" example:"10"` // Timeout in seconds
}

// Removed duplicate definition
// ComposeListRequest represents parameters for listing compose deployments.
// @description Query parameters for filtering, sorting, and paginating the list of Compose deployments managed by the application.
type ComposeListRequest struct {
	PaginationRequest // Embeds Page and PageSize
	SortRequest       // Embeds SortBy and SortOrder
	FilterRequest     // Embeds Search, Filters, StartDate, EndDate
	// Status filters deployments by their current status (e.g., running, stopped, error).
	// example: running
	Status string `json:"status" form:"status" example:"running"`
}

// -----------------------
// System Requests
// -----------------------

// SystemPruneRequest represents a system prune request
type SystemPruneRequest struct {
	Containers bool              `json:"containers" example:"true"`               // Prune containers
	Images     bool              `json:"images" example:"false"`                  // Prune images
	Networks   bool              `json:"networks" example:"true"`                 // Prune networks
	Volumes    bool              `json:"volumes" example:"true"`                  // Prune volumes
	BuildCache bool              `json:"build_cache" example:"true"`              // Prune build cache
	Filters    map[string]string `json:"filters" example:"label:mylabel=myvalue"` // Filters to apply (e.g., {"label": ["key=value"]}) - Note: Docker API uses map[string][]string, adjust if needed
}
