package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaginationResponse(t *testing.T) {
	// Create a test pagination response
	pagination := &PaginationResponse{
		Page:       2,
		PageSize:   10,
		TotalPages: 5,
		TotalItems: 42,
	}

	// Marshal to JSON
	data, err := json.Marshal(pagination)
	require.NoError(t, err)

	// Unmarshal from JSON
	var result PaginationResponse
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Check that fields match
	assert.Equal(t, pagination.Page, result.Page)
	assert.Equal(t, pagination.PageSize, result.PageSize)
	assert.Equal(t, pagination.TotalPages, result.TotalPages)
	assert.Equal(t, pagination.TotalItems, result.TotalItems)
}

func TestMetadataResponse(t *testing.T) {
	// Create a test metadata response
	now := time.Now()
	metadata := &MetadataResponse{
		Timestamp: now,
		RequestID: "req-123456",
		Pagination: &PaginationResponse{
			Page:       1,
			PageSize:   25,
			TotalPages: 4,
			TotalItems: 90,
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(metadata)
	require.NoError(t, err)

	// Unmarshal from JSON
	var result MetadataResponse
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Check that fields match
	assert.Equal(t, metadata.Timestamp.Unix(), result.Timestamp.Unix())
	assert.Equal(t, metadata.RequestID, result.RequestID)
	assert.NotNil(t, result.Pagination)
	assert.Equal(t, metadata.Pagination.Page, result.Pagination.Page)
	assert.Equal(t, metadata.Pagination.TotalItems, result.Pagination.TotalItems)
}

func TestTokenResponse(t *testing.T) {
	// Create a test token response
	expiresAt := time.Now().Add(1 * time.Hour)
	token := &TokenResponse{
		AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
		RefreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		ExpiresAt:    expiresAt,
		UserID:       1,
		Roles:        []string{"admin", "user"},
	}

	// Marshal to JSON
	data, err := json.Marshal(token)
	require.NoError(t, err)

	// Unmarshal from JSON
	var result TokenResponse
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Check that fields match
	assert.Equal(t, token.AccessToken, result.AccessToken)
	assert.Equal(t, token.RefreshToken, result.RefreshToken)
	assert.Equal(t, token.TokenType, result.TokenType)
	assert.Equal(t, token.ExpiresIn, result.ExpiresIn)
	assert.Equal(t, token.ExpiresAt.Unix(), result.ExpiresAt.Unix())
	assert.Equal(t, token.UserID, result.UserID)
	assert.Equal(t, token.Roles, result.Roles)
}

func TestUserResponse(t *testing.T) {
	// Create a test user response
	now := time.Now()
	user := &UserResponse{
		ID:            1,
		Email:         "test@example.com",
		Name:          "Test User",
		Roles:         []string{"admin", "user"},
		LastLogin:     now.Add(-24 * time.Hour),
		EmailVerified: true,
		Active:        true,
		CreatedAt:     now.Add(-30 * 24 * time.Hour),
		UpdatedAt:     now.Add(-7 * 24 * time.Hour),
	}

	// Marshal to JSON
	data, err := json.Marshal(user)
	require.NoError(t, err)

	// Unmarshal from JSON
	var result UserResponse
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Check that fields match
	assert.Equal(t, user.ID, result.ID)
	assert.Equal(t, user.Email, result.Email)
	assert.Equal(t, user.Name, result.Name)
	assert.Equal(t, user.Roles, result.Roles)
	assert.Equal(t, user.LastLogin.Unix(), result.LastLogin.Unix())
	assert.Equal(t, user.EmailVerified, result.EmailVerified)
	assert.Equal(t, user.Active, result.Active)
}

func TestContainerResponse(t *testing.T) {
	// Create a test container response
	now := time.Now()
	container := &ContainerResponse{
		ID:          1,
		ContainerID: "abc123",
		Name:        "test-container",
		Image:       "nginx:latest",
		ImageID:     "sha256:1234567890abcdef",
		Command:     "nginx -g 'daemon off;'",
		Status:      ContainerStatusRunning,
		State:       "running",
		Created:     now.Add(-24 * time.Hour),
		Started:     now.Add(-24 * time.Hour),
		Ports: []PortMapping{
			{
				HostIP:        "0.0.0.0",
				HostPort:      "8080",
				ContainerPort: "80",
				// Protocol:      "tcp", // Field removed, use Type instead
			},
		},
		Volumes: []VolumeMountResponse{
			{
				Source:      "/tmp/data",
				Destination: "/data",
				Mode:        "rw",
				RW:          true,
			},
		},
		Networks: []NetworkConnectionResponse{
			{
				NetworkID:   "net123",
				NetworkName: "bridge",
				IPAddress:   "172.17.0.2",
				Gateway:     "172.17.0.1",
				MacAddress:  "02:42:ac:11:00:02",
			},
		},
		Labels: map[string]string{
			"com.example.label1": "value1",
			"com.example.label2": "value2",
		},
		RestartPolicy: "always",
		Platform:      "linux/amd64",
		HostConfig: &HostConfigResponse{
			CPUShares:     512,
			Memory:        104857600,
			Privileged:    false,
			SecurityOpt:   []string{"no-new-privileges:true"},
			RestartPolicy: "always",
			NetworkMode:   "bridge",
		},
		Stats: &ContainerStatsResponse{
			CPUPercentage:    2.5,
			MemoryUsage:      52428800,
			MemoryLimit:      104857600,
			MemoryPercentage: 50.0,
			NetworkRx:        1024,
			NetworkTx:        2048,
			BlockRead:        4096,
			BlockWrite:       8192,
			PIDs:             5,
			Timestamp:        now,
		},
		Notes:     "Test container",
		UserID:    1,
		CreatedAt: now.Add(-24 * time.Hour),
		UpdatedAt: now,
	}

	// Marshal to JSON
	data, err := json.Marshal(container)
	require.NoError(t, err)

	// Unmarshal from JSON
	var result ContainerResponse
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Check that fields match
	assert.Equal(t, container.ID, result.ID)
	assert.Equal(t, container.ContainerID, result.ContainerID)
	assert.Equal(t, container.Name, result.Name)
	assert.Equal(t, container.Image, result.Image)
	assert.Equal(t, container.Status, result.Status)
	assert.Len(t, result.Ports, 1)
	assert.Len(t, result.Volumes, 1)
	assert.Len(t, result.Networks, 1)
	assert.Len(t, result.Labels, 2)
	assert.NotNil(t, result.HostConfig)
	assert.NotNil(t, result.Stats)
}

func TestImageResponse(t *testing.T) {
	// Create a test image response
	now := time.Now()
	image := &ImageResponse{
		ID:           1,
		ImageID:      "sha256:1234567890abcdef",
		Name:         "test-image",
		Repository:   "nginx",
		Tag:          "latest",
		Digest:       "sha256:1234567890abcdef",
		Created:      now.Add(-7 * 24 * time.Hour),
		Size:         104857600,
		SizeHuman:    "100 MB",
		Architecture: "amd64",
		OS:           "linux",
		Author:       "NGINX Docker Maintainers",
		Labels: map[string]string{
			"maintainer": "NGINX Docker Maintainers",
		},
		Containers: []string{"container1", "container2"},
		History: []ImageHistoryResponse{
			{
				ID:        "layer1",
				Created:   now.Add(-7 * 24 * time.Hour),
				CreatedBy: "ADD file:4b1019a12f1fe75eba3831dd5e4c5c886a025ccab0a58b589211434a84f66a13 in /",
				Size:      73220151,
				SizeHuman: "69.8 MB",
				Tags:      []string{},
			},
			{
				ID:        "layer2",
				Created:   now.Add(-7 * 24 * time.Hour),
				CreatedBy: "/bin/sh -c #(nop) CMD [\"nginx\" \"-g\" \"daemon off;\"]",
				Size:      0,
				SizeHuman: "0 B",
				Tags:      []string{"nginx:latest"},
			},
		},
		Notes:     "Test image",
		UserID:    1,
		CreatedAt: now.Add(-24 * time.Hour),
		UpdatedAt: now,
	}

	// Marshal to JSON
	data, err := json.Marshal(image)
	require.NoError(t, err)

	// Unmarshal from JSON
	var result ImageResponse
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Check that fields match
	assert.Equal(t, image.ID, result.ID)
	assert.Equal(t, image.ImageID, result.ImageID)
	assert.Equal(t, image.Repository, result.Repository)
	assert.Equal(t, image.Tag, result.Tag)
	assert.Equal(t, image.Size, result.Size)
	assert.Equal(t, image.SizeHuman, result.SizeHuman)
	assert.Len(t, result.Containers, 2)
	assert.Len(t, result.History, 2)
	assert.Equal(t, "layer1", result.History[0].ID)
	assert.Equal(t, "layer2", result.History[1].ID)
}

func TestVolumeResponse(t *testing.T) {
	// Create a test volume response
	now := time.Now()
	volume := &VolumeResponse{
		ID:         1,
		VolumeID:   "vol123",
		Name:       "test-volume",
		Driver:     "local",
		Mountpoint: "/var/lib/docker_test/volumes/test-volume/_data",
		CreatedAt:  now.Add(-24 * time.Hour),
		Scope:      "local",
		Labels: map[string]string{
			"com.example.label1": "value1",
		},
		InUse:      true,
		Containers: []string{"container1", "container2"},
		Size:       104857600,
		SizeHuman:  "100 MB",
		Notes:      "Test volume",
		UserID:     1,
		UpdatedAt:  now,
	}

	// Marshal to JSON
	data, err := json.Marshal(volume)
	require.NoError(t, err)

	// Unmarshal from JSON
	var result VolumeResponse
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Check that fields match
	assert.Equal(t, volume.ID, result.ID)
	assert.Equal(t, volume.VolumeID, result.VolumeID)
	assert.Equal(t, volume.Name, result.Name)
	assert.Equal(t, volume.Driver, result.Driver)
	assert.Equal(t, volume.Mountpoint, result.Mountpoint)
	assert.Equal(t, volume.Scope, result.Scope)
	assert.True(t, result.InUse)
	assert.Len(t, result.Containers, 2)
	assert.Equal(t, "container1", result.Containers[0])
}

func TestNetworkResponse(t *testing.T) {
	// Create a test network response
	now := time.Now()
	network := &NetworkResponse{
		ID:         1,
		NetworkID:  "net123",
		Name:       "test-network",
		Driver:     "bridge",
		Scope:      "local",
		Created:    now.Add(-24 * time.Hour),
		Gateway:    "172.18.0.1",
		Subnet:     "172.18.0.0/16",
		Internal:   false,
		EnableIPv6: false,
		Attachable: true,
		Ingress:    false,
		ConfigOnly: false,
		Labels: map[string]string{
			"com.example.label1": "value1",
		},
		Options: map[string]string{
			"com.docker_test.network.bridge.name": "br0",
		},
		Containers: map[string]NetworkContainerResponse{
			"container1": {
				Name:        "container1",
				EndpointID:  "endpoint1",
				MacAddress:  "02:42:ac:12:00:02",
				IPv4Address: "172.18.0.2/16",
				Aliases:     []string{"web"},
			},
		},
		Notes:     "Test network",
		UserID:    1,
		CreatedAt: now.Add(-24 * time.Hour),
		UpdatedAt: now,
	}

	// Marshal to JSON
	data, err := json.Marshal(network)
	require.NoError(t, err)

	// Unmarshal from JSON
	var result NetworkResponse
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Check that fields match
	assert.Equal(t, network.ID, result.ID)
	assert.Equal(t, network.NetworkID, result.NetworkID)
	assert.Equal(t, network.Name, result.Name)
	assert.Equal(t, network.Driver, result.Driver)
	assert.Equal(t, network.Scope, result.Scope)
	assert.Equal(t, network.Gateway, result.Gateway)
	assert.Equal(t, network.Subnet, result.Subnet)
	assert.False(t, result.Internal)
	assert.True(t, result.Attachable)
	assert.Len(t, result.Containers, 1)
	assert.Equal(t, "container1", result.Containers["container1"].Name)
}

func TestComposeDeploymentResponse(t *testing.T) {
	// Create a test compose deployment response
	now := time.Now()
	deployment := &ComposeDeploymentResponse{
		ID:           1,
		Name:         "test-project",
		ProjectName:  "test-project",
		FilePath:     "/tmp/docker_test-compose.yml",
		Status:       "running",
		ServiceCount: 2,
		RunningCount: 2,
		Services: []ComposeServiceResponse{
			{
				ID:           1,
				Name:         "web",
				ContainerID:  "container1",
				ImageName:    "nginx:latest",
				Status:       ContainerStatusRunning,
				Replicas:     1,
				RunningCount: 1,
				Ports: []PortMapping{
					{
						HostIP:        "0.0.0.0",
						HostPort:      "8080",
						ContainerPort: "80",
						// Protocol:      "tcp", // Field removed, use Type instead
					},
				},
				Networks:    []string{"test-project_default"},
				Environment: []string{"NGINX_HOST=localhost"},
				Command:     "nginx -g 'daemon off;'",
				LastUpdated: now,
				CreatedAt:   now.Add(-1 * time.Hour),
				UpdatedAt:   now,
			},
			{
				ID:           2,
				Name:         "db",
				ContainerID:  "container2",
				ImageName:    "postgres:13",
				Status:       ContainerStatusRunning,
				Replicas:     1,
				RunningCount: 1,
				Networks:     []string{"test-project_default"},
				Environment:  []string{"POSTGRES_PASSWORD=password"},
				LastUpdated:  now,
				CreatedAt:    now.Add(-1 * time.Hour),
				UpdatedAt:    now,
			},
		},
		Networks: []NetworkResponse{
			{
				NetworkID:  "net123",
				Name:       "test-project_default",
				Driver:     "bridge",
				Scope:      "local",
				Created:    now.Add(-1 * time.Hour),
				Gateway:    "172.18.0.1",
				Subnet:     "172.18.0.0/16",
				Internal:   false,
				Attachable: true,
			},
		},
		Volumes: []VolumeResponse{
			{
				VolumeID:   "vol123",
				Name:       "test-project_data",
				Driver:     "local",
				Mountpoint: "/var/lib/docker_test/volumes/test-project_data/_data",
				CreatedAt:  now.Add(-1 * time.Hour),
				Scope:      "local",
				InUse:      true,
			},
		},
		Labels: map[string]string{
			"com.docker_test.compose.project": "test-project",
		},
		Notes:        "Test project",
		LastDeployed: now.Add(-1 * time.Hour),
		LastUpdated:  now,
		UserID:       1,
		CreatedAt:    now.Add(-1 * time.Hour),
		UpdatedAt:    now,
	}

	// Marshal to JSON
	data, err := json.Marshal(deployment)
	require.NoError(t, err)

	// Unmarshal from JSON
	var result ComposeDeploymentResponse
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Check that fields match
	assert.Equal(t, deployment.ID, result.ID)
	assert.Equal(t, deployment.Name, result.Name)
	assert.Equal(t, deployment.ProjectName, result.ProjectName)
	assert.Equal(t, deployment.Status, result.Status)
	assert.Equal(t, deployment.ServiceCount, result.ServiceCount)
	assert.Equal(t, deployment.RunningCount, result.RunningCount)
	assert.Len(t, result.Services, 2)
	assert.Equal(t, "web", result.Services[0].Name)
	assert.Equal(t, "db", result.Services[1].Name)
	assert.Len(t, result.Networks, 1)
	assert.Len(t, result.Volumes, 1)
}

func TestSystemInfoResponse(t *testing.T) {
	// Create a test system info response
	now := time.Now()
	sysInfo := &SystemInfoResponse{
		ID:                "abcd1234",
		Name:              "docker_test-host",
		ServerVersion:     "20.10.7",
		APIVersion:        "1.41",
		KernelVersion:     "5.4.0-74-generic",
		OperatingSystem:   "Ubuntu 20.04.2 LTS",
		OSType:            "linux",
		Architecture:      "x86_64",
		CPUs:              4,
		Memory:            8000000000, // 8 GB
		MemoryHuman:       "8 GB",
		ContainersRunning: 3,
		ContainersPaused:  0,
		ContainersStopped: 2,
		Images:            10,
		Driver:            "overlay2",
		DriverStatus:      [][]string{{"Backing Filesystem", "extfs"}},
		DockerRootDir:     "/var/lib/docker_test",
		ExperimentalBuild: false,
		ServerTime:        now,
		NFd:               100,
		NGoroutines:       50,
		SystemTime:        now,
		LoggingDriver:     "json-file",
		CgroupDriver:      "systemd",
		CgroupVersion:     "2",
		NEventsListener:   30,
	}

	// Marshal to JSON
	data, err := json.Marshal(sysInfo)
	require.NoError(t, err)

	// Unmarshal from JSON
	var result SystemInfoResponse
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Check that fields match
	assert.Equal(t, sysInfo.ID, result.ID)
	assert.Equal(t, sysInfo.Name, result.Name)
	assert.Equal(t, sysInfo.ServerVersion, result.ServerVersion)
	assert.Equal(t, sysInfo.APIVersion, result.APIVersion)
	assert.Equal(t, sysInfo.OSType, result.OSType)
	assert.Equal(t, sysInfo.CPUs, result.CPUs)
	assert.Equal(t, sysInfo.Memory, result.Memory)
	assert.Equal(t, sysInfo.ContainersRunning, result.ContainersRunning)
	assert.Equal(t, sysInfo.Images, result.Images)
	assert.Equal(t, sysInfo.Driver, result.Driver)
}

func TestEventResponse(t *testing.T) {
	// Create a test event response
	now := time.Now()
	event := &EventResponse{
		ID:      1,
		Type:    "container",
		Action:  "start",
		Actor:   "container",
		ActorID: "abc123",
		Attributes: map[string]string{
			"name":  "test-container",
			"image": "nginx:latest",
		},
		Scope:        "local",
		Timestamp:    now.Add(-5 * time.Minute),
		TimeNano:     now.Add(-5 * time.Minute).UnixNano(),
		HostID:       1,
		HostName:     "docker_test-host",
		Acknowledged: false,
	}

	// Marshal to JSON
	data, err := json.Marshal(event)
	require.NoError(t, err)

	// Unmarshal from JSON
	var result EventResponse
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Check that fields match
	assert.Equal(t, event.ID, result.ID)
	assert.Equal(t, event.Type, result.Type)
	assert.Equal(t, event.Action, result.Action)
	assert.Equal(t, event.Actor, result.Actor)
	assert.Equal(t, event.ActorID, result.ActorID)
	assert.Len(t, result.Attributes, 2)
	assert.Equal(t, "test-container", result.Attributes["name"])
	assert.Equal(t, "nginx:latest", result.Attributes["image"])
	assert.Equal(t, event.Scope, result.Scope)
	assert.Equal(t, event.Timestamp.Unix(), result.Timestamp.Unix())
}
