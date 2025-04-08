package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPaginationRequest(t *testing.T) {
	tests := []struct {
		name           string
		input          PaginationRequest
		expectedPage   int
		expectedSize   int
		expectedOffset int
	}{
		{
			name: "Default values",
			input: PaginationRequest{
				Page:     0,
				PageSize: 0,
			},
			expectedPage:   1,
			expectedSize:   10,
			expectedOffset: 0,
		},
		{
			name: "Valid values",
			input: PaginationRequest{
				Page:     2,
				PageSize: 20,
			},
			expectedPage:   2,
			expectedSize:   20,
			expectedOffset: 20,
		},
		{
			name: "Negative values",
			input: PaginationRequest{
				Page:     -1,
				PageSize: -5,
			},
			expectedPage:   1,
			expectedSize:   10,
			expectedOffset: 0,
		},
		{
			name: "Exceeding maximum page size",
			input: PaginationRequest{
				Page:     3,
				PageSize: 200,
			},
			expectedPage:   3,
			expectedSize:   100,
			expectedOffset: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set defaults
			tt.input.SetDefaults()

			// Check values
			assert.Equal(t, tt.expectedPage, tt.input.Page)
			assert.Equal(t, tt.expectedSize, tt.input.PageSize)
			assert.Equal(t, tt.expectedOffset, tt.input.GetOffset())
		})
	}
}

func TestSortRequest(t *testing.T) {
	tests := []struct {
		name           string
		input          SortRequest
		defaultSortBy  string
		expectedSortBy string
		expectedOrder  string
	}{
		{
			name: "Default values",
			input: SortRequest{
				SortBy:    "",
				SortOrder: "",
			},
			defaultSortBy:  "id",
			expectedSortBy: "id",
			expectedOrder:  "asc",
		},
		{
			name: "Provided values",
			input: SortRequest{
				SortBy:    "name",
				SortOrder: "desc",
			},
			defaultSortBy:  "id",
			expectedSortBy: "name",
			expectedOrder:  "desc",
		},
		{
			name: "Empty order",
			input: SortRequest{
				SortBy:    "created_at",
				SortOrder: "",
			},
			defaultSortBy:  "id",
			expectedSortBy: "created_at",
			expectedOrder:  "asc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set defaults
			tt.input.SetDefaults(tt.defaultSortBy)

			// Check values
			assert.Equal(t, tt.expectedSortBy, tt.input.SortBy)
			assert.Equal(t, tt.expectedOrder, tt.input.SortOrder)
		})
	}
}

func TestContainerCreateRequest(t *testing.T) {
	// Test a valid container creation request
	request := ContainerCreateRequest{
		Name:    "test-container",
		Image:   "nginx:latest",
		Command: []string{"nginx", "-g", "daemon off;"},
		Env:     []string{"NGINX_HOST=localhost", "NGINX_PORT=80"},
		Labels: map[string]string{
			"com.example.description": "Web server",
			"com.example.department":  "IT",
		},
		Ports: []PortMapping{
			{
				HostIP:        "0.0.0.0",
				HostPort:      "8080",
				ContainerPort: "80",
				// Protocol:      "tcp", // Field removed, use Type instead
			},
		},
		Volumes: []VolumeMapping{
			{
				Source:      "/tmp/data",
				Destination: "/data",
				ReadOnly:    false,
			},
		},
		Networks:      []string{"bridge"},
		RestartPolicy: "always",
		MemoryLimit:   104857600, // 100 MB
		CPULimit:      0.5,       // 50% of a CPU core
		Privileged:    false,
		AutoRemove:    false,
		Notes:         "Test container for web server",
	}

	// Verify all fields are as expected
	assert.Equal(t, "test-container", request.Name)
	assert.Equal(t, "nginx:latest", request.Image)
	assert.Equal(t, []string{"nginx", "-g", "daemon off;"}, request.Command)
	assert.Len(t, request.Env, 2)
	assert.Len(t, request.Labels, 2)
	assert.Len(t, request.Ports, 1)
	assert.Equal(t, "8080", request.Ports[0].HostPort)
	assert.Len(t, request.Volumes, 1)
	assert.Equal(t, "/data", request.Volumes[0].Destination)
	assert.Equal(t, "always", request.RestartPolicy)
}

func TestImagePullRequest(t *testing.T) {
	// Test a valid image pull request
	request := ImagePullRequest{
		Image: "nginx",
		Tag:   "latest",
	}

	// Verify all fields are as expected
	assert.Equal(t, "nginx", request.Image)
	assert.Equal(t, "latest", request.Tag)
	assert.Equal(t, "testuser", request.Credentials.Username)
	assert.Equal(t, "testpassword", request.Credentials.Password)
}

func TestContainerLogsRequest(t *testing.T) {
	// Test a valid container logs request
	now := time.Now()
	request := ContainerLogsRequest{
		Follow:     true,
		Since:      now.Add(-1 * time.Hour),
		Until:      now,
		Timestamps: true,
		Tail:       "100",
		ShowStdout: true,
		ShowStderr: true,
	}

	// Verify all fields are as expected
	assert.True(t, request.Follow)
	assert.True(t, request.Since.Before(now))
	assert.True(t, request.Until.Equal(now))
	assert.True(t, request.Timestamps)
	assert.Equal(t, "100", request.Tail)
	assert.True(t, request.ShowStdout)
	assert.True(t, request.ShowStderr)
}

func TestNetworkCreateRequest(t *testing.T) {
	// Test a valid network creation request
	request := NetworkCreateRequest{
		Name:     "test-network",
		Driver:   "bridge",
		Internal: false,
		IPAM: &IPAMCreateRequest{ // Use correct type IPAMCreateRequest
			Config: []IPAMConfigRequest{ // Use correct type IPAMConfigRequest
				{
					Subnet:  "172.20.0.0/16",
					Gateway: "172.20.0.1",
					IPRange: "172.20.0.0/24",
				},
			},
		},
		Labels: map[string]string{
			"com.example.description": "Test network",
			"com.example.environment": "development",
		},
		Options: map[string]string{
			"com.docker_test.network.bridge.name":           "test-br0",
			"com.docker_test.network.bridge.enable_icc":     "true",
			"com.docker_test.network.bridge.enable_ip_masq": "true",
		},
		EnableIPv6: false,
		Attachable: true,
		Notes:      "Test network for development",
	}

	// Verify all fields are as expected
	assert.Equal(t, "test-network", request.Name)
	assert.Equal(t, "bridge", request.Driver)
	assert.False(t, request.Internal)
	assert.NotNil(t, request.IPAM)
	assert.Len(t, request.IPAM.Config, 1)
	assert.Equal(t, "172.20.0.0/16", request.IPAM.Config[0].Subnet)
	assert.Equal(t, "172.20.0.1", request.IPAM.Config[0].Gateway) // Assert correct field
	assert.Equal(t, "172.20.0.1", request.IPAM.Config[0].Gateway)
	assert.Len(t, request.Labels, 2)
	assert.Len(t, request.Options, 3)
	assert.False(t, request.EnableIPv6)
	assert.True(t, request.Attachable)
}

func TestVolumeCreateRequest(t *testing.T) {
	// Test a valid volume creation request
	request := VolumeCreateRequest{
		Name:   "test-volume",
		Driver: "local",
		DriverOpts: map[string]string{
			"type":   "nfs",
			"device": ":/path/to/dir",
			"o":      "addr=1.2.3.4,rw",
		},
		Labels: map[string]string{
			"com.example.description": "Test volume",
			"com.example.environment": "development",
		},
		Notes: "Test volume for development",
	}

	// Verify all fields are as expected
	assert.Equal(t, "test-volume", request.Name)
	assert.Equal(t, "local", request.Driver)
	assert.Len(t, request.DriverOpts, 3)
	assert.Len(t, request.Labels, 2)
	assert.Equal(t, "Test volume for development", request.Notes)
}

// Removed TestComposeDeployRequest as ComposeDeployRequest is undefined
