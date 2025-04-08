package models

import (
	"time"
)

// --- Standard API Response Structures ---

// SuccessResponse represents a standard successful API response structure.
type SuccessResponse struct {
	Success bool             `json:"success" example:"true"`
	Data    interface{}      `json:"data,omitempty"`    // Use omitempty if data might be nil/empty
	Message string           `json:"message,omitempty"` // Optional success message
	Meta    MetadataResponse `json:"meta"`
}

// ErrorInfo represents the details of an API error.
// @description Detailed information about an error that occurred during an API request.
type ErrorInfo struct {
	// Code is a machine-readable error code identifying the specific error type.
	// required: true
	// example: RESOURCE_NOT_FOUND
	Code string `json:"code" example:"RESOURCE_NOT_FOUND"`

	// Message is a human-readable description of the error.
	// required: true
	// example: The requested container was not found.
	Message string `json:"message" example:"The requested container was not found."`

	// Details provides optional additional information about the error, such as validation failures.
	// example: {"field": "command", "error": "cannot be empty"}
	Details interface{} `json:"details,omitempty"`
}

// ErrorResponse represents a standard error API response structure.
// @description Standard structure for returning errors from the API.
type ErrorResponse struct {
	// Success indicates if the request was successful (always false for errors).
	// required: true
	// example: false
	Success bool `json:"success" example:"false"`

	// Error contains the detailed error information.
	// required: true
	Error ErrorInfo `json:"error"`

	// Meta contains metadata about the response.
	// required: true
	Meta MetadataResponse `json:"meta"`
}

// --- Specific Response Data Structures ---

// PaginationResponse represents pagination metadata for API responses
type PaginationResponse struct {
	Page       int `json:"page" example:"1"`
	PageSize   int `json:"page_size" example:"10"`
	TotalPages int `json:"total_pages" example:"5"`
	TotalItems int `json:"total_items" example:"42"`
}

// MetadataResponse represents common metadata for API responses
type MetadataResponse struct {
	Timestamp  time.Time           `json:"timestamp" example:"2023-10-27T10:30:00Z"`
	RequestID  string              `json:"request_id,omitempty" example:"req-12345"`
	Pagination *PaginationResponse `json:"pagination,omitempty"`
}

// PaginatedResponse is a generic structure for paginated list responses.
// Use specific list response types embedding this for Swagger documentation.
type PaginatedResponse struct {
	Success bool             `json:"success" example:"true"`
	Data    interface{}      `json:"data"` // Should hold the slice of items
	Meta    MetadataResponse `json:"meta"`
}

// -----------------------
// Authentication Responses
// -----------------------

// TokenResponse represents a token response for login and refresh operations
// @description Contains the JWT access and refresh tokens along with user details.
type TokenResponse struct {
	// AccessToken is the JWT token used for authenticating subsequent requests.
	// required: true
	// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (long token string)
	AccessToken string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`

	// RefreshToken is the token used to obtain a new access token when the current one expires.
	// required: true
	// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (different long token string)
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`

	// TokenType indicates the type of token (always "Bearer").
	// required: true
	// example: Bearer
	TokenType string `json:"token_type" example:"Bearer"`

	// ExpiresIn is the duration in seconds until the access token expires.
	// required: true
	// example: 3600
	ExpiresIn int `json:"expires_in" example:"3600"` // seconds

	// ExpiresAt is the exact timestamp when the access token expires.
	// required: true
	// example: 2023-10-27T11:00:00Z
	ExpiresAt time.Time `json:"expires_at" example:"2023-10-27T11:00:00Z"`

	// UserID is the unique identifier of the logged-in user.
	// required: true
	// example: 1
	UserID uint `json:"user_id" example:"1"`

	// Roles is the list of roles assigned to the user.
	// required: true
	// example: ["user", "admin"]
	Roles []string `json:"roles" example:"user,admin"`
}

// UserResponse represents a user response, excluding sensitive information like password.
// @description Detailed information about a user account.
type UserResponse struct {
	// ID is the unique identifier for the user.
	// required: true
	// example: 1
	ID uint `json:"id" example:"1"`

	// Email is the user's email address.
	// required: true
	// example: user@example.com
	Email string `json:"email" example:"user@example.com"`

	// Name is the user's display name.
	// required: true
	// example: John Doe
	Name string `json:"name" example:"John Doe"`

	// Roles is the list of roles assigned to the user.
	// required: true
	// example: ["user", "admin"]
	Roles []string `json:"roles" example:"user,admin"`

	// LastLogin is the timestamp of the user's last login. Omitted if the user has never logged in.
	// example: 2023-10-27T10:00:00Z
	LastLogin time.Time `json:"last_login,omitempty" example:"2023-10-27T10:00:00Z"`

	// EmailVerified indicates whether the user's email address has been verified.
	// required: true
	// example: true
	EmailVerified bool `json:"email_verified" example:"true"`

	// Active indicates whether the user account is currently active.
	// required: true
	// example: true
	Active bool `json:"active" example:"true"`

	// CreatedAt is the timestamp when the user account was created.
	// required: true
	// example: 2023-01-15T09:30:00Z
	CreatedAt time.Time `json:"created_at" example:"2023-01-15T09:30:00Z"`

	// UpdatedAt is the timestamp when the user account was last updated.
	// required: true
	// example: 2023-10-26T15:45:00Z
	UpdatedAt time.Time `json:"updated_at" example:"2023-10-26T15:45:00Z"`
}

// UserListResponse represents the response for listing users, including pagination metadata.
// @description Contains a list of user details along with pagination information.
type UserListResponse struct {
	// Users is the list of user objects returned for the current page.
	// required: true
	Users []UserResponse `json:"users"`

	// Metadata contains pagination and other metadata for the response.
	// required: true
	Metadata MetadataResponse `json:"metadata"`
}

// -----------------------
// Container Responses
// -----------------------

// ContainerResponse represents detailed information about a Docker container.
// @description Contains comprehensive details of a Docker container, including configuration, state, and associated resources.
type ContainerResponse struct {
	// ID is the internal database ID (if managed by the application).
	// example: 101
	ID uint `json:"id" example:"101"`

	// ContainerID is the unique identifier assigned by Docker.
	// required: true
	// example: "f7d9e8c7b6a5..."
	ContainerID string `json:"container_id" example:"f7d9e8c7b6a5"`

	// Name is the user-defined name of the container.
	// required: true
	// example: "my-nginx-container"
	Name string `json:"name" example:"my-nginx-container"`

	// Image is the name of the image used by the container.
	// required: true
	// example: "nginx:latest"
	Image string `json:"image" example:"nginx:latest"`

	// ImageID is the ID of the image used by the container.
	// required: true
	// example: "sha256:a1b2c3d4..."
	ImageID string `json:"image_id" example:"sha256:a1b2c3d4..."`

	// Command is the command executed when the container started.
	// example: "nginx -g daemon off;"
	Command string `json:"command" example:"nginx -g daemon off;"`

	// Status is a simplified status string (e.g., running, stopped).
	// required: true
	// example: "running"
	Status ContainerStatus `json:"status" example:"running"`

	// State is the detailed state string from Docker (e.g., "running", "exited (0)").
	// required: true
	// example: "running"
	State string `json:"state" example:"running"`

	// Created is the timestamp when the container was created by Docker.
	// required: true
	// example: "2023-10-27T10:00:00Z"
	Created time.Time `json:"created" example:"2023-10-27T10:00:00Z"`

	// Started is the timestamp when the container was last started.
	// example: "2023-10-27T10:01:00Z"
	Started time.Time `json:"started,omitempty" example:"2023-10-27T10:01:00Z"`

	// Finished is the timestamp when the container last finished.
	// example: "2023-10-27T11:00:00Z"
	Finished time.Time `json:"finished,omitempty" example:"2023-10-27T11:00:00Z"`

	// Ports lists the port mappings for the container.
	Ports []PortMapping `json:"ports"`

	// Volumes lists the volume mounts for the container.
	Volumes []VolumeMountResponse `json:"volumes"`

	// Networks lists the network connections for the container.
	Networks []NetworkConnectionResponse `json:"networks"`

	// Labels are the labels applied to the container.
	// example: {"environment": "development"}
	Labels map[string]string `json:"labels" example:"environment:development"`

	// RestartPolicy is the restart policy applied to the container.
	// example: "unless-stopped"
	RestartPolicy string `json:"restart_policy" example:"unless-stopped"`

	// Platform is the platform string (e.g., "linux/amd64").
	// example: "linux/amd64"
	Platform string `json:"platform" example:"linux/amd64"`

	// HostConfig contains details about the container's host configuration.
	HostConfig *HostConfigResponse `json:"host_config,omitempty"`

	// Stats contains the latest resource usage statistics (if requested/available).
	Stats *ContainerStatsResponse `json:"stats,omitempty"`

	// Notes are user-defined notes stored in the application database.
	// example: "Main web server container."
	Notes string `json:"notes" example:"Main web server container."`

	// UserID is the ID of the user who owns/created this container record in the application database.
	// required: true
	// example: 1
	UserID uint `json:"user_id" example:"1"`

	// CreatedAt is the timestamp when the container record was created in the application database.
	// required: true
	// example: "2023-10-27T10:00:05Z"
	CreatedAt time.Time `json:"created_at" example:"2023-10-27T10:00:05Z"`

	// UpdatedAt is the timestamp when the container record was last updated in the application database.
	// required: true
	// example: "2023-10-27T10:05:00Z"
	UpdatedAt time.Time `json:"updated_at" example:"2023-10-27T10:05:00Z"`
}

// VolumeMountResponse represents details about a volume mounted within a container.
// @description Information about a specific volume mount point inside a container.
type VolumeMountResponse struct {
	// Source is the source path on the host or the name of the Docker volume.
	// required: true
	// example: "/path/on/host" or "my-app-data"
	Source string `json:"source" example:"my-app-data"` // or "/path/on/host"

	// Destination is the absolute path inside the container where the volume is mounted.
	// required: true
	// example: "/data"
	Destination string `json:"destination" example:"/data"`

	// Mode provides driver-specific options, often includes SELinux labels like 'z' or 'Z'.
	// example: "z"
	Mode string `json:"mode" example:"z"`

	// RW indicates if the mount is read-write.
	// required: true
	// example: true
	RW bool `json:"rw" example:"true"`

	// VolumeID is the name of the Docker volume (if Source refers to a named volume).
	// example: "my-app-data"
	VolumeID string `json:"volume_id,omitempty" example:"my-app-data"`
}

// NetworkConnectionResponse represents details about a container's connection to a specific network.
// @description Information about a container's endpoint within a Docker network.
type NetworkConnectionResponse struct {
	// NetworkID is the ID of the network the container is connected to.
	// required: true
	// example: "b7cda8f3e9a1..."
	NetworkID string `json:"network_id" example:"b7cda8f3e9a1"`

	// NetworkName is the name of the network.
	// required: true
	// example: "my-app-network"
	NetworkName string `json:"network_name" example:"my-app-network"`

	// IPAddress is the IPv4 address assigned to the container within this network.
	// example: "172.28.0.3"
	IPAddress string `json:"ip_address" example:"172.28.0.3"`

	// Gateway is the gateway address for this network connection.
	// example: "172.28.0.1"
	Gateway string `json:"gateway" example:"172.28.0.1"`

	// MacAddress is the MAC address assigned to the container's endpoint in this network.
	// example: "02:42:ac:1c:00:03"
	MacAddress string `json:"mac_address" example:"02:42:ac:1c:00:03"`

	// Aliases are network-scoped aliases for the container within this network.
	// example: ["nginx", "webserver"]
	Aliases []string `json:"aliases,omitempty" example:"nginx,webserver"`
}

// HostConfigResponse represents a subset of the container's host configuration relevant to the API response.
// @description Key host configuration settings applied to the container.
type HostConfigResponse struct {
	// CPUShares is the relative CPU weight (vs. other containers).
	// example: 1024
	CPUShares int64 `json:"cpu_shares,omitempty" example:"1024"`

	// Memory is the memory limit in bytes. 0 means no limit.
	// example: 104857600
	Memory int64 `json:"memory,omitempty" example:"104857600"`

	// MemorySwap is the total memory (memory + swap). -1 means unlimited swap.
	// example: -1
	MemorySwap int64 `json:"memory_swap,omitempty" example:"-1"`

	// CPUPeriod is the CPU CFS period in microseconds.
	// example: 100000
	CPUPeriod int64 `json:"cpu_period,omitempty" example:"100000"`

	// CPUQuota is the CPU CFS quota in microseconds.
	// example: 50000
	CPUQuota int64 `json:"cpu_quota,omitempty" example:"50000"`

	// CpusetCpus specifies the CPUs the container can use (e.g., "0-3", "0,1").
	// example: "0,1"
	CpusetCpus string `json:"cpuset_cpus,omitempty" example:"0,1"`

	// CpusetMems specifies the memory nodes the container can use.
	// example: "0"
	CpusetMems string `json:"cpuset_mems,omitempty" example:"0"`

	// BlkioWeight is the block I/O weight (relative weight).
	// example: 500
	BlkioWeight uint16 `json:"blkio_weight,omitempty" example:"500"`

	// Privileged indicates if the container runs in privileged mode.
	// required: true
	// example: false
	Privileged bool `json:"privileged" example:"false"`

	// ReadonlyRootfs indicates if the container's root filesystem is read-only.
	// required: true
	// example: false
	ReadonlyRootfs bool `json:"readonly_rootfs" example:"false"`

	// SecurityOpt lists the security options applied to the container.
	// example: ["seccomp=unconfined"]
	SecurityOpt []string `json:"security_opt,omitempty" example:"seccomp=unconfined"`

	// CapAdd lists the capabilities added to the container.
	// example: ["NET_ADMIN"]
	CapAdd []string `json:"cap_add,omitempty" example:"NET_ADMIN"`

	// CapDrop lists the capabilities dropped from the container.
	// example: ["MKNOD"]
	CapDrop []string `json:"cap_drop,omitempty" example:"MKNOD"`

	// RestartPolicy is the full restart policy string (e.g., "unless-stopped").
	// required: true
	// example: "unless-stopped"
	RestartPolicy string `json:"restart_policy" example:"unless-stopped"`

	// NetworkMode is the network mode used by the container (e.g., "bridge", "host").
	// required: true
	// example: "bridge"
	NetworkMode string `json:"network_mode" example:"bridge"`
}

// ContainerStatsResponse represents real-time resource usage statistics for a container.
// @description Snapshot of CPU, memory, network, and block I/O usage for a container.
type ContainerStatsResponse struct {
	// CPUPercentage is the container's CPU usage percentage across all cores.
	// required: true
	// example: 12.34
	CPUPercentage float64 `json:"cpu_percentage" example:"12.34"`

	// MemoryUsage is the current memory usage in bytes.
	// required: true
	// example: 52428800
	MemoryUsage int64 `json:"memory_usage" example:"52428800"`

	// MemoryLimit is the memory limit for the container in bytes.
	// required: true
	// example: 104857600
	MemoryLimit int64 `json:"memory_limit" example:"104857600"`

	// MemoryPercentage is the current memory usage as a percentage of the limit.
	// required: true
	// example: 50.0
	MemoryPercentage float64 `json:"memory_percentage" example:"50.0"`

	// NetworkRx is the total bytes received over the network by the container.
	// required: true
	// example: 1024000
	NetworkRx int64 `json:"network_rx" example:"1024000"`

	// NetworkTx is the total bytes transmitted over the network by the container.
	// required: true
	// example: 512000
	NetworkTx int64 `json:"network_tx" example:"512000"`

	// BlockRead is the total bytes read from block devices by the container.
	// required: true
	// example: 204800
	BlockRead int64 `json:"block_read" example:"204800"`

	// BlockWrite is the total bytes written to block devices by the container.
	// required: true
	// example: 102400
	BlockWrite int64 `json:"block_write" example:"102400"`

	// PIDs is the number of processes currently running in the container.
	// required: true
	// example: 5
	PIDs int `json:"pids" example:"5"`

	// Timestamp is the time when the stats were collected.
	// required: true
	// example: "2023-10-27T10:15:00Z"
	Timestamp time.Time `json:"timestamp" example:"2023-10-27T10:15:00Z"`
}

// ContainerLogResponse represents container logs
type ContainerLogResponse struct {
	Logs       string    `json:"logs" example:"Log line 1\nLog line 2"`
	Timestamps bool      `json:"timestamps" example:"true"`
	Since      time.Time `json:"since,omitempty" example:"2023-10-27T10:00:00Z"`
	Until      time.Time `json:"until,omitempty" example:"2023-10-27T11:00:00Z"`
	Tail       string    `json:"tail,omitempty" example:"100"`
}

// ContainerExecResponse represents the state of an exec instance in a container.
// @description Details about an exec instance created within a container.
type ContainerExecResponse struct {
	// ID is the unique identifier of the exec instance.
	// required: true
	// example: "a1b2c3d4e5f6..."
	ID string `json:"id" example:"a1b2c3d4e5f6"`

	// Running indicates whether the exec process is currently running.
	// required: true
	// example: false
	Running bool `json:"running" example:"false"`

	// ExitCode is the exit code of the exec process. Only available after the process has finished.
	// example: 0
	ExitCode int `json:"exit_code" example:"0"`

	// ProcessConfig holds the configuration of the process executed.
	ProcessConfig struct {
		// EntryPoint is the entry point for the executed command.
		// example: "/bin/sh"
		EntryPoint string `json:"entrypoint" example:"/bin/sh"`
		// Arguments are the arguments passed to the command.
		// example: ["-c", "echo hello"]
		Arguments []string `json:"arguments" example:"-c,echo hello"`
		// Tty indicates if a TTY was allocated for the process.
		// example: false
		Tty bool `json:"tty" example:"false"`
		// Privileged indicates if the process ran with elevated privileges.
		// example: false
		Privileged bool `json:"privileged" example:"false"`
	} `json:"process_config"`

	// OpenStdin indicates if stdin was attached to the process.
	// required: true
	// example: false
	OpenStdin bool `json:"open_stdin" example:"false"`

	// OpenStderr indicates if stderr was attached to the process.
	// required: true
	// example: true
	OpenStderr bool `json:"open_stderr" example:"true"`

	// OpenStdout indicates if stdout was attached to the process.
	// required: true
	// example: true
	OpenStdout bool `json:"open_stdout" example:"true"`

	// ContainerID is the ID of the container where the exec instance ran.
	// required: true
	// example: "f7d9e8c7b6a5..."
	ContainerID string `json:"container_id" example:"f7d9e8c7b6a5"`

	// CreatedAt is the timestamp when the exec instance was created (Note: Docker API might not provide this directly in inspect).
	// example: "2023-10-27T10:00:00Z"
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// ContainerListResponse represents a paginated list of containers.
// @description Contains a list of container details along with pagination information.
type ContainerListResponse struct {
	// Containers is the list of container objects returned for the current page.
	// required: true
	Containers []ContainerResponse `json:"containers"`

	// Metadata contains pagination and other metadata for the response.
	// required: true
	Metadata MetadataResponse `json:"metadata"`
}

// ContainerExecStartResponse represents the response for starting an exec instance (non-websocket)
type ContainerExecStartResponse struct {
	ExecID   string `json:"exec_id"`
	Output   string `json:"output"` // Base64 encoded stdout
	Error    string `json:"error"`  // Base64 encoded stderr
	ExitCode int    `json:"exit_code"`
	Running  bool   `json:"running"`
}

// TopResponse represents the output of the 'top' or 'ps' command run inside a container.
// @description Lists the running processes within a container.
type TopResponse struct {
	// Titles are the column headers for the process list (e.g., "PID", "USER", "%CPU", "COMMAND").
	// required: true
	// example: ["PID", "USER", "COMMAND"]
	Titles []string `json:"titles"` // Process list titles (e.g., PID, USER, COMMAND)

	// Processes is a list of arrays, where each inner array represents a process and its corresponding column values.
	// required: true
	// example: [["1", "root", "/usr/sbin/nginx"], ["6", "nginx", "nginx: worker process"]]
	Processes [][]string `json:"processes"` // List of process information arrays
}

// ChangeItemResponse represents a single change detected in a container's filesystem.
// @description Details about a file or directory that has been modified, added, or deleted compared to the container's image.
type ChangeItemResponse struct {
	// Path is the path to the file or directory that has changed.
	// required: true
	// example: "/app/config.json"
	Path string `json:"path" example:"/etc/nginx/nginx.conf"`

	// Kind indicates the type of change: 0 for Modified, 1 for Added, 2 for Deleted.
	// required: true
	// example: 1
	Kind int `json:"kind"` // 0: Modified, 1: Added, 2: Deleted
}

// -----------------------
// Image Responses
// -----------------------

// ImageResponse represents detailed information about a Docker image.
// @description Contains comprehensive details of a Docker image, including tags, size, and history.
type ImageResponse struct {
	// ID is the internal database ID (if managed by the application).
	// example: 25
	ID uint `json:"id,omitempty"`

	// ImageID is the unique identifier assigned by Docker (SHA256 digest).
	// required: true
	// example: "sha256:a1b2c3d4e5f6..."
	ImageID string `json:"image_id"`

	// Name is the primary repository:tag associated with the image.
	// example: "nginx:latest"
	Name string `json:"name,omitempty"`

	// Repository is the repository part of the image name.
	// example: "nginx"
	Repository string `json:"repository"`

	// Tag is the tag part of the image name.
	// example: "latest"
	Tag string `json:"tag"`

	// Digest is the repository digest (SHA256) if available.
	// example: "sha256:f6d669c..."
	Digest string `json:"digest,omitempty"`

	// Created is the timestamp when the image was created.
	// required: true
	// example: "2023-10-26T14:00:00Z"
	Created time.Time `json:"created" example:"2023-09-15T14:00:00Z"`

	// Size is the total size of the image layers in bytes.
	// required: true
	// example: 135234567
	Size int64 `json:"size" example:"133000000"` // Bytes

	// SizeHuman is the total size in a human-readable format.
	// required: true
	// example: "129MB"
	SizeHuman string `json:"size_human"`

	// Architecture is the CPU architecture the image was built for.
	// example: "amd64"
	Architecture string `json:"architecture" example:"amd64"`

	// OS is the operating system the image was built for.
	// example: "linux"
	OS string `json:"os"`

	// Author is the author specified in the image metadata.
	// example: "Nginx Maintainers <nginx-devel@nginx.org>"
	Author string `json:"author,omitempty"`

	// Labels are the labels applied to the image.
	// example: {"maintainer": "Nginx Maintainers"}
	Labels map[string]string `json:"labels,omitempty"`

	// Containers lists the IDs of containers currently using this image.
	// example: ["f7d9e8c7b6a5"]
	Containers []string `json:"containers,omitempty"`

	// History provides details about the layers that make up the image.
	History []ImageHistoryResponse `json:"history,omitempty"`

	// Notes are user-defined notes stored in the application database.
	// example: "Base image for web servers."
	Notes string `json:"notes,omitempty"`

	// UserID is the ID of the user who owns/created this image record in the application database.
	// example: 1
	UserID uint `json:"user_id,omitempty"`

	// CreatedAt is the timestamp when the image record was created in the application database.
	// example: "2023-10-27T09:00:00Z"
	CreatedAt time.Time `json:"created_at,omitempty"`

	// UpdatedAt is the timestamp when the image record was last updated in the application database.
	// example: "2023-10-27T09:05:00Z"
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// ImageHistoryResponse represents a single layer in the history of a Docker image.
// @description Details about a specific layer, including how it was created and its size.
type ImageHistoryResponse struct {
	// ID is the identifier for this history record (often the layer ID or <missing>).
	// required: true
	// example: "sha256:b1c2d3e4..."
	ID string `json:"id" example:"sha256:a1b2c3d4..."`

	// Created is the timestamp when this layer was created.
	// required: true
	// example: "2023-10-26T13:50:00Z"
	Created time.Time `json:"created" example:"2023-09-15T14:00:00Z"`

	// CreatedBy is the command used to create this layer.
	// required: true
	// example: "/bin/sh -c #(nop) ADD file:abc in /"
	CreatedBy string `json:"created_by" example:"/bin/sh -c #(nop) CMD [\"nginx\" \"-g\" \"daemon off;\"]"`

	// Size is the size of this layer in bytes.
	// required: true
	// example: 5242880
	Size int64 `json:"size"`

	// SizeHuman is the size of this layer in a human-readable format.
	// required: true
	// example: "5MB"
	SizeHuman string `json:"size_human"`

	// Comment is an optional comment associated with the layer creation.
	// example: "Added base filesystem"
	Comment string `json:"comment,omitempty"`

	// Tags lists the tags associated with this specific history entry (usually empty).
	Tags []string `json:"tags,omitempty"`
}

// ImageHistoryItem represents a single layer in the history of a Docker image.
// @description Details about a specific layer, including how it was created and its size. (Note: This is functionally the same as ImageHistoryResponse but used for clarity in some contexts).
type ImageHistoryItem struct {
	// ID is the identifier for this history record (often the layer ID or <missing>).
	// required: true
	// example: "sha256:b1c2d3e4..."
	ID string `json:"id" example:"sha256:a1b2c3d4..."`

	// Created is the timestamp when this layer was created.
	// required: true
	// example: "2023-10-26T13:50:00Z"
	Created time.Time `json:"created" example:"2023-09-15T14:00:00Z"`

	// CreatedBy is the command used to create this layer.
	// required: true
	// example: "/bin/sh -c #(nop) ADD file:abc in /"
	CreatedBy string `json:"created_by" example:"/bin/sh -c #(nop) CMD [\"nginx\" \"-g\" \"daemon off;\"]"`

	// Size is the size of this layer in bytes.
	// required: true
	// example: 5242880
	Size int64 `json:"size" example:"0"` // Size of this layer

	// SizeHuman is the size of this layer in a human-readable format.
	// required: true
	// example: "5MB"
	SizeHuman string `json:"size_human"`

	// Comment is an optional comment associated with the layer creation.
	// example: "Added base filesystem"
	Comment string `json:"comment,omitempty"`

	// Tags lists the tags associated with this specific history entry (usually empty).
	Tags []string `json:"tags,omitempty"`
}

// ImageListResponse represents a paginated list of Docker images.
// @description Contains a list of image details along with pagination information.
type ImageListResponse struct {
	// Images is the list of image objects returned for the current page.
	// required: true
	Images []ImageResponse `json:"images"`

	// Metadata contains pagination and other metadata for the response.
	// required: true
	Metadata MetadataResponse `json:"metadata"`
}

// ImagePullResponse represents the result of an image pull operation.
// @description Provides details about the image that was pulled.
type ImagePullResponse struct {
	// Success indicates if the pull operation was successful (note: Docker pull itself doesn't return success/fail easily, this might be application-level).
	// required: true
	// example: true
	Success bool `json:"success"`

	// Image is the full name (repo:tag) of the image that was pulled.
	// required: true
	// example: "nginx:latest"
	Image string `json:"image"`

	// ID is the Docker Image ID (SHA256 digest) of the pulled image.
	// example: "sha256:a1b2c3d4..."
	ID string `json:"id,omitempty"`

	// Size is the size of the pulled image in bytes.
	// example: 135234567
	Size int64 `json:"size,omitempty"`

	// CreatedAt is the creation timestamp of the pulled image (from image inspect).
	// example: "2023-10-26T14:00:00Z"
	CreatedAt string `json:"created_at,omitempty"` // Keep as string from Docker API? Or parse?

	// Time is the timestamp when the pull operation completed on the server.
	// required: true
	// example: "2023-10-27T10:30:00Z"
	Time time.Time `json:"time"`
}

// ImageBuildResponse represents the result of an image build operation.
// @description Provides details about the image build process, including logs and timing.
type ImageBuildResponse struct {
	// Success indicates if the build operation completed successfully (may not mean the image is usable if errors occurred during build).
	// required: true
	// example: true
	Success bool `json:"success"`

	// ImageID is the Docker Image ID (SHA256 digest) of the built image, if successful.
	// example: "sha256:c3d4e5f6..."
	ImageID string `json:"image_id,omitempty" example:"sha256:b1c2d3e4..."`

	// Repository is the repository name used for tagging.
	// example: "my-custom-app"
	Repository string `json:"repository,omitempty"`

	// Tag is the tag applied to the built image.
	// example: "v1.1"
	Tag string `json:"tag,omitempty"`

	// Logs contains the output stream from the Docker build process.
	Logs []string `json:"logs,omitempty"`

	// ErrorDetail contains specific error information if the build failed.
	// example: "failed to solve: rpc error: code = Unknown desc = executor failed running..."
	ErrorDetail string `json:"error_detail,omitempty"`

	// StartTime is the timestamp when the build process started.
	// required: true
	// example: "2023-10-27T11:00:00Z"
	StartTime time.Time `json:"start_time"`

	// EndTime is the timestamp when the build process finished.
	// required: true
	// example: "2023-10-27T11:05:00Z"
	EndTime time.Time `json:"end_time"`

	// Duration is the total duration of the build process in a human-readable format.
	// required: true
	// example: "5m0s"
	Duration string `json:"duration"`
}

// ImageTagResponse represents an image tag response
type ImageTagResponse struct {
	Success    bool   `json:"success"`
	SourceID   string `json:"source_id"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	FullTag    string `json:"full_tag"`
}

// ImageRemoveResponse represents the result of an image remove operation.
// @description Summarizes the outcome of removing an image, including untagged and deleted layers. Note: This structure might need adjustment based on the actual Docker API response format for removal.
type ImageRemoveResponse struct {
	// Deleted is the count of deleted image layers/references.
	// example: 5
	Deleted int `json:"deleted"`

	// SpaceReclaimed is the total disk space freed in bytes.
	// example: 150000000
	SpaceReclaimed int64 `json:"space_reclaimed"`

	// Items provides details on untagged or deleted items (structure may vary based on Docker API).
	// example: [{"Untagged": "myimage:latest"}, {"Deleted": "sha256:a1b2..."}]
	Items []map[string]interface{} `json:"items"` // Use map for flexibility as DeleteResponse structure varies
}

// -----------------------
// Volume Responses
// -----------------------

// VolumeResponse represents detailed information about a Docker volume.
// @description Contains comprehensive details of a Docker volume, including configuration and usage.
type VolumeResponse struct {
	// ID is the internal database ID (if managed by the application).
	// example: 12
	ID uint `json:"id,omitempty"`

	// VolumeID is the unique identifier assigned by Docker (often the same as Name).
	// required: true
	// example: "my-app-data"
	VolumeID string `json:"volume_id"`

	// Name is the user-defined name of the volume.
	// required: true
	// example: "my-app-data"
	Name string `json:"name" example:"my-app-data"`

	// Driver is the volume driver used (e.g., local).
	// required: true
	// example: "local"
	Driver string `json:"driver" example:"local"`

	// Mountpoint is the path on the host where the volume data is stored.
	// required: true
	// example: "/var/lib/docker/volumes/my-app-data/_data"
	Mountpoint string `json:"mountpoint" example:"/var/lib/docker/volumes/my-app-data/_data"`

	// CreatedAt is the timestamp when the volume was created by Docker. Note: Docker API might return this as 'CreatedAt' string, needs parsing.
	// required: true
	// example: "2023-10-27T08:00:00Z"
	CreatedAt time.Time `json:"created_at" example:"2023-10-26T12:00:00Z"`

	// Scope indicates the scope of the volume (e.g., local, global).
	// required: true
	// example: "local"
	Scope string `json:"scope" example:"local"`

	// Labels are the labels applied to the volume.
	// example: {"environment": "production", "backup": "true"}
	Labels map[string]string `json:"labels,omitempty"`

	// Options are driver-specific options for the volume.
	Options map[string]string `json:"options,omitempty"`

	// Status provides low-level status information about the volume (driver-specific).
	Status map[string]string `json:"status,omitempty"`

	// InUse indicates whether the volume is currently used by any containers. Requires UsageData from Docker API.
	// example: true
	InUse bool `json:"in_use"`

	// Containers lists the IDs of containers currently using this volume. Requires UsageData from Docker API.
	// example: ["f7d9e8c7b6a5", "a1b2c3d4e5f6"]
	Containers []string `json:"containers,omitempty"`

	// Size is the calculated size of the volume in bytes. Requires UsageData from Docker API.
	// example: 104857600
	Size int64 `json:"size,omitempty"`

	// SizeHuman is the calculated size of the volume in a human-readable format.
	// example: "100MB"
	SizeHuman string `json:"size_human,omitempty"`

	// Notes are user-defined notes stored in the application database.
	// example: "Persistent data for the main database."
	Notes string `json:"notes,omitempty"`

	// UserID is the ID of the user who owns/created this volume record in the application database.
	// example: 1
	UserID uint `json:"user_id,omitempty"`

	// UpdatedAt is the timestamp when the volume record was last updated in the application database.
	// example: "2023-10-27T08:10:00Z"
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// VolumeListResponse represents a paginated list of Docker volumes.
// @description Contains a list of volume details along with pagination information.
type VolumeListResponse struct {
	// Volumes is the list of volume objects returned for the current page.
	// required: true
	Volumes []VolumeResponse `json:"volumes"`

	// Metadata contains pagination and other metadata for the response.
	// required: true
	Metadata MetadataResponse `json:"metadata"`
}

// -----------------------
// Network Responses
// -----------------------

// NetworkResponse represents detailed information about a Docker network.
// @description Contains comprehensive details of a Docker network, including configuration and connected containers.
type NetworkResponse struct {
	// ID is the internal database ID (if managed by the application).
	// example: 5
	ID uint `json:"id,omitempty"`

	// NetworkID is the unique identifier assigned by Docker.
	// required: true
	// example: "b7cda8f3e9a1..."
	NetworkID string `json:"network_id"`

	// Name is the user-defined name of the network.
	// required: true
	// example: "my-app-network"
	Name string `json:"name" example:"my-app-network"`

	// Driver is the network driver used (e.g., bridge, overlay).
	// required: true
	// example: "bridge"
	Driver string `json:"driver" example:"bridge"`

	// Scope indicates the scope of the network (e.g., local, swarm).
	// required: true
	// example: "local"
	Scope string `json:"scope" example:"local"`

	// Created is the timestamp when the network was created by Docker.
	// required: true
	// example: "2023-10-27T09:00:00Z"
	Created time.Time `json:"created" example:"2023-10-25T09:00:00Z"`

	// Gateway is the IPv4 gateway for the network's subnet.
	// example: "172.28.0.1"
	Gateway string `json:"gateway,omitempty"`

	// Subnet is the primary IPv4 subnet for the network in CIDR notation.
	// example: "172.28.0.0/16"
	Subnet string `json:"subnet,omitempty"`

	// IPRange is the range of IPs available within the subnet.
	// example: "172.28.5.0/24"
	IPRange string `json:"ip_range,omitempty"`

	// Internal indicates if the network is internal (restricts external access).
	// required: true
	// example: false
	Internal bool `json:"internal" example:"false"`

	// EnableIPv6 indicates if IPv6 is enabled for the network.
	// required: true
	// example: false
	EnableIPv6 bool `json:"enable_ipv6" example:"false"`

	// Attachable indicates if non-service containers can attach to the network.
	// required: true
	// example: true
	Attachable bool `json:"attachable" example:"true"`

	// Ingress indicates if the network provides the routing-mesh in swarm mode.
	// required: true
	// example: false
	Ingress bool `json:"ingress" example:"false"`

	// ConfigOnly indicates if the network configuration is only used for services.
	// required: true
	// example: false
	ConfigOnly bool `json:"config_only" example:"false"`

	// Labels are the labels applied to the network.
	// example: {"environment": "production"}
	Labels map[string]string `json:"labels,omitempty"`

	// Options are driver-specific options for the network.
	// example: {"com.docker.network.bridge.name": "mybridge0"}
	Options map[string]string `json:"options,omitempty"`

	// Containers lists the containers connected to this network and their endpoint details.
	Containers map[string]NetworkContainerResponse `json:"containers,omitempty"`

	// Notes are user-defined notes stored in the application database.
	// example: "Main network for the web application stack."
	Notes string `json:"notes,omitempty"`

	// UserID is the ID of the user who owns/created this network record in the application database.
	// example: 1
	UserID uint `json:"user_id,omitempty"`

	// CreatedAt is the timestamp when the network record was created in the application database.
	// example: "2023-10-27T09:05:00Z"
	CreatedAt time.Time `json:"created_at,omitempty"`

	// UpdatedAt is the timestamp when the network record was last updated in the application database.
	// example: "2023-10-27T09:10:00Z"
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// NetworkContainerResponse represents details about a container connected to a network.
// @description Information about a specific container's endpoint within a network.
type NetworkContainerResponse struct {
	// Name is the name of the connected container.
	// required: true
	// example: "my-web-container"
	Name string `json:"name" example:"my-app-container"`

	// EndpointID is the ID of the network endpoint for this container.
	// required: true
	// example: "ep-a1b2c3d4e5f6..."
	EndpointID string `json:"endpoint_id" example:"ep-a1b2c3d4..."`

	// MacAddress is the MAC address assigned to the container's endpoint.
	// required: true
	// example: "02:42:ac:1c:00:02"
	MacAddress string `json:"mac_address" example:"02:42:ac:1c:00:03"`

	// IPv4Address is the IPv4 address assigned to the container's endpoint.
	// example: "172.28.0.2"
	IPv4Address string `json:"ipv4_address,omitempty"`

	// IPv6Address is the IPv6 address assigned to the container's endpoint.
	// example: "2001:db8:abcd::2"
	IPv6Address string `json:"ipv6_address,omitempty"`

	// Aliases are network-scoped aliases for the container within this network.
	// example: ["web", "frontend"]
	Aliases []string `json:"aliases,omitempty"`
}

// NetworkListResponse represents a paginated list of Docker networks.
// @description Contains a list of network details along with pagination information.
type NetworkListResponse struct {
	// Networks is the list of network objects returned for the current page.
	// required: true
	Networks []NetworkResponse `json:"networks"`

	// Metadata contains pagination and other metadata for the response.
	// required: true
	Metadata MetadataResponse `json:"metadata"`
}

// -----------------------
// Compose Responses
// -----------------------

// ComposeDeploymentResponse represents a compose deployment response
type ComposeDeploymentResponse struct {
	ID           uint                     `json:"id" example:"1"`
	Name         string                   `json:"name"`
	ProjectName  string                   `json:"project_name" example:"my-web-app"`
	FilePath     string                   `json:"file_path,omitempty"`
	Status       string                   `json:"status" example:"running"`
	ServiceCount int                      `json:"service_count"`
	RunningCount int                      `json:"running_count"`
	Services     []ComposeServiceResponse `json:"services"`
	Networks     []NetworkResponse        `json:"networks,omitempty"`
	Volumes      []VolumeResponse         `json:"volumes,omitempty"`
	Labels       map[string]string        `json:"labels,omitempty"`
	Notes        string                   `json:"notes,omitempty"`
	LastDeployed time.Time                `json:"last_deployed" example:"2023-10-27T12:00:00Z"`
	LastUpdated  time.Time                `json:"last_updated"`
	UserID       uint                     `json:"user_id"`
	CreatedAt    time.Time                `json:"created_at"`
	UpdatedAt    time.Time                `json:"updated_at"`
}

// ComposeServiceResponse represents a compose service response
type ComposeServiceResponse struct {
	ID           uint                  `json:"id"`
	Name         string                `json:"name" example:"web"`
	ContainerID  string                `json:"container_id,omitempty"`
	ImageName    string                `json:"image_name"`
	Status       ContainerStatus       `json:"status"`
	Replicas     int                   `json:"replicas"`
	RunningCount int                   `json:"running_count"`
	Ports        []PortMapping         `json:"ports,omitempty"`
	Volumes      []VolumeMountResponse `json:"volumes,omitempty"`
	Networks     []string              `json:"networks,omitempty"`
	Environment  []string              `json:"environment,omitempty"`
	Command      string                `json:"command,omitempty"`
	Depends      []string              `json:"depends,omitempty"`
	LastUpdated  time.Time             `json:"last_updated"`
	CreatedAt    time.Time             `json:"created_at"`
	UpdatedAt    time.Time             `json:"updated_at"`
}

// ComposeListResponse represents a list of compose deployments
type ComposeListResponse struct {
	Deployments []ComposeDeploymentResponse `json:"deployments"`
	Metadata    MetadataResponse            `json:"metadata"`
}

// ComposeValidationResponse represents a compose validation response
type ComposeValidationResponse struct {
	Valid    bool     `json:"valid"`
	Warnings []string `json:"warnings,omitempty"`
	Errors   []string `json:"errors,omitempty" example:"service 'db' depends on undefined network 'external_net'"`
	Services []string `json:"services,omitempty"`
	Networks []string `json:"networks,omitempty"`
	Volumes  []string `json:"volumes,omitempty"`
}

// -----------------------
// System Responses
// -----------------------

// SystemInfoResponse represents system information
type SystemInfoResponse struct {
	ID                 string                 `json:"id" example:"system-id-123"`
	Name               string                 `json:"name"`
	ServerVersion      string                 `json:"server_version" example:"24.0.5"`
	APIVersion         string                 `json:"api_version"`
	KernelVersion      string                 `json:"kernel_version" example:"5.15.0-87-generic"`
	OperatingSystem    string                 `json:"operating_system" example:"Docker Desktop"`
	OSType             string                 `json:"os_type"`
	Architecture       string                 `json:"architecture" example:"aarch64"`
	CPUs               int                    `json:"cpus"`
	Memory             int64                  `json:"memory"`
	MemoryHuman        string                 `json:"memory_human"`
	ContainersRunning  int                    `json:"containers_running"`
	ContainersPaused   int                    `json:"containers_paused"`
	ContainersStopped  int                    `json:"containers_stopped"`
	Images             int                    `json:"images" example:"50"`
	Driver             string                 `json:"driver" example:"overlay2"`
	DriverStatus       [][]string             `json:"driver_status,omitempty"`
	DockerRootDir      string                 `json:"docker_root_dir"`
	ExperimentalBuild  bool                   `json:"experimental_build"`
	ServerTime         time.Time              `json:"server_time"`
	HTTPProxy          string                 `json:"http_proxy,omitempty"`
	HTTPSProxy         string                 `json:"https_proxy,omitempty"`
	NoProxy            string                 `json:"no_proxy,omitempty"`
	SecurityOptions    []string               `json:"security_options,omitempty"`
	RegistryConfig     map[string]interface{} `json:"registry_config,omitempty"`
	LiveRestoreEnabled bool                   `json:"live_restore_enabled"`
	Debug              bool                   `json:"debug"`
	NFd                int                    `json:"n_fd"`
	NGoroutines        int                    `json:"n_goroutines"`
	SystemTime         time.Time              `json:"system_time"`
	LoggingDriver      string                 `json:"logging_driver"`
	CgroupDriver       string                 `json:"cgroup_driver"`
	CgroupVersion      string                 `json:"cgroup_version"`
	NEventsListener    int                    `json:"n_events_listener"`
	KernelMemory       bool                   `json:"kernel_memory"`
	MemoryLimit        bool                   `json:"memory_limit"`
	SwapLimit          bool                   `json:"swap_limit"`
	KernelMemoryTCP    bool                   `json:"kernel_memory_tcp"`
	CPUCfsPeriod       bool                   `json:"cpu_cfs_period"`
	CPUCfsQuota        bool                   `json:"cpu_cfs_quota"`
	CPUShares          bool                   `json:"cpu_shares"`
	CPUSet             bool                   `json:"cpu_set"`
	PidsLimit          bool                   `json:"pids_limit"`
	IPv4Forwarding     bool                   `json:"ipv4_forwarding"`
	BridgeNfIptables   bool                   `json:"bridge_nf_iptables"`
	BridgeNfIp6tables  bool                   `json:"bridge_nf_ip6tables"`
	Debug0             bool                   `json:"debug0"`
	OomKillDisable     bool                   `json:"oom_kill_disable"`
}

// SystemPruneResponse represents the results of a system prune operation
type SystemPruneResponse struct {
	ContainersDeleted []string                  `json:"containers_deleted,omitempty"`  // Renamed from ContainersPruned
	ImagesDeleted     []ImageDeleteResponseItem `json:"images_deleted,omitempty"`      // Renamed from ImagesPruned, changed type
	NetworksDeleted   []string                  `json:"networks_deleted,omitempty"`    // Renamed from NetworksPruned
	VolumesDeleted    []string                  `json:"volumes_deleted,omitempty"`     // Renamed from VolumesPruned
	BuildCacheDeleted []string                  `json:"build_cache_deleted,omitempty"` // Keep this field
	SpaceReclaimed    int64                     `json:"space_reclaimed"`
	// SpaceReclaimedHuman string   `json:"space_reclaimed_human"` // Removed, can be calculated if needed
}

// ImageDeleteResponseItem represents an item in the ImagesDeleted list for prune/remove responses
// Based on types.ImageDeleteResponseItem
type ImageDeleteResponseItem struct {
	Untagged string `json:"untagged,omitempty"`
	Deleted  string `json:"deleted,omitempty" example:"sha256:a1b2c3d4..."`
}

// PingResponse represents the response from the Docker daemon ping endpoint
type PingResponse struct {
	APIVersion     string `json:"api_version"`
	OSType         string `json:"os_type"`
	Experimental   bool   `json:"experimental"`
	BuilderVersion string `json:"builder_version"`
}

// -----------------------
// Events Responses
// -----------------------

// EventResponse represents a Docker event
type EventResponse struct {
	ID           uint              `json:"id"`
	Type         string            `json:"type" example:"container"` // e.g., container, image, volume, network
	Action       string            `json:"action" example:"start"`   // e.g., create, start, stop, die, pull, tag, prune
	Actor        string            `json:"actor"`
	ActorID      string            `json:"actor_id"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	Scope        string            `json:"scope"`
	Timestamp    time.Time         `json:"timestamp" example:"2023-10-27T10:01:00Z"`
	TimeNano     int64             `json:"time_nano"`
	HostID       uint              `json:"host_id"`
	HostName     string            `json:"host_name"`
	Acknowledged bool              `json:"acknowledged"`
}

// EventListResponse represents a list of Docker events
type EventListResponse struct {
	Events   []EventResponse  `json:"events"`
	Metadata MetadataResponse `json:"metadata"`
}
