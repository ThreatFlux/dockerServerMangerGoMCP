package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate the schemas
	err = db.AutoMigrate(
		&User{},
		&UserRole{},
		&Token{},
		&Container{},
		&Image{},
		&Volume{},
		&Network{},
		&ComposeDeployment{},
		&ComposeService{},
		// &DockerHost{}, // Model removed or renamed
		// &DockerEvent{}, // Model removed or renamed
	)
	require.NoError(t, err)

	return db
}

func TestContainerModel(t *testing.T) {
	db := setupTestDB(t)

	// Create a test user
	user := User{
		Email:    "test@example.com",
		Password: "password",
		Name:     "Test User",
		Roles: []UserRole{
			{Role: RoleUser},
		},
	}
	result := db.Create(&user)
	require.NoError(t, result.Error)
	assert.NotZero(t, user.ID)

	// Create a test container
	container := Container{
		DockerResource: DockerResource{
			UserID: user.ID,
			Name:   "test-container",
			Labels: JSONMap{"app": "test", "environment": "dev"},
			Notes:  "Test container for unit tests",
		},
		ContainerID:   "abc123",
		ImageID:       "alpine:latest",
		Command:       "sleep infinity",
		Status:        ContainerStatusRunning,
		Ports:         JSONMap{"80/tcp": []map[string]interface{}{{"HostPort": "8080"}}},
		Volumes:       JSONMap{"/data": map[string]interface{}{"Source": "/tmp", "Mode": "rw"}},
		Networks:      JSONMap{"bridge": map[string]interface{}{}},
		IPAddress:     "172.17.0.2",
		ExitCode:      0,
		RestartPolicy: "always",
		LastInspected: time.Now(),
	}

	result = db.Create(&container)
	require.NoError(t, result.Error)
	assert.NotZero(t, container.ID)

	// Retrieve container from the database
	var retrievedContainer Container
	result = db.First(&retrievedContainer, container.ID)
	require.NoError(t, result.Error)

	// Check that fields match
	assert.Equal(t, container.Name, retrievedContainer.Name)
	assert.Equal(t, container.ContainerID, retrievedContainer.ContainerID)
	assert.Equal(t, container.Status, retrievedContainer.Status)
	assert.Equal(t, container.IPAddress, retrievedContainer.IPAddress)
}

func TestImageModel(t *testing.T) {
	db := setupTestDB(t)

	// Create a test user
	user := User{
		Email:    "test@example.com",
		Password: "password",
		Name:     "Test User",
		Roles: []UserRole{
			{Role: RoleUser},
		},
	}
	result := db.Create(&user)
	require.NoError(t, result.Error)

	// Create a test image
	image := Image{
		DockerResource: DockerResource{
			UserID: user.ID,
			Name:   "test-image",
			Labels: JSONMap{"app": "test", "version": "1.0"},
			Notes:  "Test image for unit tests",
		},
		ImageID:       "sha256:1234567890abcdef",
		Repository:    "alpine",
		Tag:           "latest",
		Digest:        "sha256:1234567890abcdef",
		Size:          5242880, // 5 MB
		Created:       time.Now().Add(-24 * time.Hour),
		Author:        "Test Author",
		Architecture:  "amd64",
		OS:            "linux",
		LastInspected: time.Now(),
	}

	result = db.Create(&image)
	require.NoError(t, result.Error)
	assert.NotZero(t, image.ID)

	// Retrieve image from the database
	var retrievedImage Image
	result = db.First(&retrievedImage, image.ID)
	require.NoError(t, result.Error)

	// Check that fields match
	assert.Equal(t, image.Name, retrievedImage.Name)
	assert.Equal(t, image.ImageID, retrievedImage.ImageID)
	assert.Equal(t, image.Repository, retrievedImage.Repository)
	assert.Equal(t, image.Tag, retrievedImage.Tag)
}

func TestVolumeModel(t *testing.T) {
	db := setupTestDB(t)

	// Create a test user
	user := User{
		Email:    "test@example.com",
		Password: "password",
		Name:     "Test User",
		Roles: []UserRole{
			{Role: RoleUser},
		},
	}
	result := db.Create(&user)
	require.NoError(t, result.Error)

	// Create a test volume
	volume := Volume{
		DockerResource: DockerResource{
			UserID: user.ID,
			Name:   "test-volume",
			Labels: JSONMap{"app": "test", "environment": "dev"},
			Notes:  "Test volume for unit tests",
		},
		VolumeID:      "test-volume-id",
		Driver:        "local",
		Mountpoint:    "/var/lib/docker_test/volumes/test-volume/_data",
		Scope:         "local",
		InUse:         false,
		LastInspected: time.Now(),
	}

	result = db.Create(&volume)
	require.NoError(t, result.Error)
	assert.NotZero(t, volume.ID)

	// Retrieve volume from the database
	var retrievedVolume Volume
	result = db.First(&retrievedVolume, volume.ID)
	require.NoError(t, result.Error)

	// Check that fields match
	assert.Equal(t, volume.Name, retrievedVolume.Name)
	assert.Equal(t, volume.VolumeID, retrievedVolume.VolumeID)
	assert.Equal(t, volume.Driver, retrievedVolume.Driver)
	assert.Equal(t, volume.Mountpoint, retrievedVolume.Mountpoint)
}

func TestNetworkModel(t *testing.T) {
	db := setupTestDB(t)

	// Create a test user
	user := User{
		Email:    "test@example.com",
		Password: "password",
		Name:     "Test User",
		Roles: []UserRole{
			{Role: RoleUser},
		},
	}
	result := db.Create(&user)
	require.NoError(t, result.Error)

	// Create a test network
	network := Network{
		DockerResource: DockerResource{
			UserID: user.ID,
			Name:   "test-network",
			Labels: JSONMap{"app": "test", "environment": "dev"},
			Notes:  "Test network for unit tests",
		},
		NetworkID:     "test-network-id",
		Driver:        "bridge",
		Scope:         "local",
		Gateway:       "172.18.0.1",
		Subnet:        "172.18.0.0/16",
		IPRange:       "",
		Internal:      false,
		EnableIPv6:    false,
		Attachable:    true,
		Ingress:       false,
		ConfigOnly:    false,
		Containers:    JSONMap{"container1": "172.18.0.2", "container2": "172.18.0.3"},
		LastInspected: time.Now(),
	}

	result = db.Create(&network)
	require.NoError(t, result.Error)
	assert.NotZero(t, network.ID)

	// Retrieve network from the database
	var retrievedNetwork Network
	result = db.First(&retrievedNetwork, network.ID)
	require.NoError(t, result.Error)

	// Check that fields match
	assert.Equal(t, network.Name, retrievedNetwork.Name)
	assert.Equal(t, network.NetworkID, retrievedNetwork.NetworkID)
	assert.Equal(t, network.Driver, retrievedNetwork.Driver)
	assert.Equal(t, network.Gateway, retrievedNetwork.Gateway)
	assert.Equal(t, network.Subnet, retrievedNetwork.Subnet)
}

func TestComposeDeploymentModel(t *testing.T) {
	db := setupTestDB(t)

	// Create a test user
	user := User{
		Email:    "test@example.com",
		Password: "password",
		Name:     "Test User",
		Roles: []UserRole{
			{Role: RoleUser},
		},
	}
	result := db.Create(&user)
	require.NoError(t, result.Error)

	// Create a test compose deployment
	deployment := ComposeDeployment{
		DockerResource: DockerResource{
			UserID: user.ID,
			Name:   "test-project",
			Labels: JSONMap{"app": "test", "environment": "dev"},
			Notes:  "Test compose deployment for unit tests",
		},
		ProjectName:  "test-project",
		FilePath:     "/tmp/docker_test-compose.yml",
		Content:      "version: '3'\nservices:\n  web:\n    image: nginx\n    ports:\n      - 80:80", // Use Content field
		Status:       "running",
		ServiceCount: 1,
		RunningCount: 1,
		// Networks and Volumes are not direct fields of ComposeDeployment
		LastDeployed: time.Now().Add(-1 * time.Hour),
		LastUpdated:  time.Now(),
	}

	result = db.Create(&deployment)
	require.NoError(t, result.Error)
	assert.NotZero(t, deployment.ID)

	// Create a test compose service
	service := ComposeService{
		DeploymentID: deployment.ID,
		Name:         "web",
		// ContainerID:  "test-container-id", // ContainerID is not a field of ComposeService model
		ImageName:    "nginx:latest",
		Status:       ContainerStatusRunning,
		Replicas:     1,
		RunningCount: 1,
		LastUpdated:  time.Now(),
	}

	result = db.Create(&service)
	require.NoError(t, result.Error)
	assert.NotZero(t, service.ID)

	// Retrieve deployment with services from the database
	var retrievedDeployment ComposeDeployment
	result = db.Preload("Services").First(&retrievedDeployment, deployment.ID)
	require.NoError(t, result.Error)

	// Check that fields match
	assert.Equal(t, deployment.Name, retrievedDeployment.Name)
	assert.Equal(t, deployment.ProjectName, retrievedDeployment.ProjectName)
	assert.Equal(t, deployment.Status, retrievedDeployment.Status)
	assert.Len(t, retrievedDeployment.Services, 1)
	assert.Equal(t, service.Name, retrievedDeployment.Services[0].Name)
	assert.Equal(t, service.Status, retrievedDeployment.Services[0].Status)
}

// func TestDockerEventModel(t *testing.T) { ... } // Commented out as DockerHost/DockerEvent models removed/renamed
