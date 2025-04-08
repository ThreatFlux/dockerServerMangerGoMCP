package client

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestListNetworks tests listing networks
func TestListNetworks(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/networks", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		filters := r.URL.Query().Get("filters")
		if filters != "" {
			var filterMap map[string][]string
			err := json.Unmarshal([]byte(filters), &filterMap)
			require.NoError(t, err)
			assert.Equal(t, []string{"bridge"}, filterMap["driver"])
		}
		networks := []models.Network{
			{DockerResource: models.DockerResource{ID: 1, Name: "bridge"}, NetworkID: "net1", Driver: "bridge", Scope: "local"},
			{DockerResource: models.DockerResource{ID: 2, Name: "host"}, NetworkID: "net2", Driver: "host", Scope: "local"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(networks)
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	networks, err := client.ListNetworks(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, networks, 2)

	filtersMap := map[string]string{"driver": "bridge"}
	networks, err = client.ListNetworks(context.Background(), filtersMap)
	require.NoError(t, err)
	assert.Len(t, networks, 2)
}

// TestGetNetwork tests getting a network
func TestGetNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasPrefix(r.URL.Path, "/api/v1/networks/"))
		assert.Equal(t, http.MethodGet, r.Method)
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/networks/")

		if id == "net1" {
			network := models.Network{ // Use fields directly available on models.Network
				DockerResource: models.DockerResource{ID: 1, Name: "bridge"},
				NetworkID:      "net1", Driver: "bridge", Scope: "local",
				Subnet:  "172.17.0.0/16", // Example direct field
				Gateway: "172.17.0.1",    // Example direct field
				// IPAMOptions:    models.JSONMap{"Driver": "default"}, // Example IPAMOptions
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(network)
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Network not found"}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	network, err := client.GetNetwork(context.Background(), "net1")
	require.NoError(t, err)
	assert.Equal(t, "net1", network.NetworkID)
	assert.Equal(t, "bridge", network.Driver)
	assert.Equal(t, "172.17.0.0/16", network.Subnet) // Assert direct field
	assert.Equal(t, "172.17.0.1", network.Gateway)   // Assert direct field

	_, err = client.GetNetwork(context.Background(), "nonexistent")
	assert.Error(t, err)
	_, err = client.GetNetwork(context.Background(), "")
	assert.Error(t, err)
}

// TestCreateNetwork tests creating a network
func TestCreateNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/networks", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var reqBody models.NetworkCreateRequest // Use correct request type
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)

		if reqBody.Name == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "Network name cannot be empty"}`))
			return
		}

		network := models.Network{ // Use fields directly available on models.Network
			DockerResource: models.DockerResource{ID: 3, Name: reqBody.Name},
			NetworkID:      "new_net_" + reqBody.Name,
			Driver:         reqBody.Driver,
			Scope:          "local",
			// IPAM related fields are now separate or within IPAMOptions
		}
		if reqBody.IPAM != nil && len(reqBody.IPAM.Config) > 0 {
			// Populate direct fields if possible from request
			network.Subnet = reqBody.IPAM.Config[0].Subnet
			network.Gateway = reqBody.IPAM.Config[0].Gateway
			network.IPRange = reqBody.IPAM.Config[0].IPRange
			// Populate IPAMOptions map
			network.IPAMOptions = models.JSONMap{}
			if reqBody.IPAM.Driver != "" {
				network.IPAMOptions["Driver"] = reqBody.IPAM.Driver
			}
			// Add other IPAM options if needed
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(network)
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	createReq := &models.NetworkCreateRequest{ // Use correct request type
		Name:   "test_network",
		Driver: "bridge",
		IPAM: &models.IPAMCreateRequest{ // Use correct IPAM request type
			Config: []models.IPAMConfigRequest{ // Use correct IPAM config request type
				{Subnet: "10.0.0.0/24", Gateway: "10.0.0.1"},
			},
		},
	}
	network, err := client.CreateNetwork(context.Background(), createReq)
	require.NoError(t, err)
	assert.Equal(t, "test_network", network.Name)
	assert.Equal(t, "bridge", network.Driver)
	assert.Equal(t, "10.0.0.0/24", network.Subnet) // Assert direct field
	assert.Equal(t, "10.0.0.1", network.Gateway)   // Assert direct field

	_, err = client.CreateNetwork(context.Background(), nil)
	assert.Error(t, err)

	createReq.Name = ""
	_, err = client.CreateNetwork(context.Background(), createReq)
	assert.Error(t, err)
}

// TestRemoveNetwork tests removing a network
func TestRemoveNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasPrefix(r.URL.Path, "/api/v1/networks/"))
		assert.Equal(t, http.MethodDelete, r.Method)
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/networks/")

		if id == "net_to_remove" {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Network not found"}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL))
	require.NoError(t, err)

	err = client.RemoveNetwork(context.Background(), "net_to_remove")
	require.NoError(t, err)

	err = client.RemoveNetwork(context.Background(), "nonexistent")
	assert.Error(t, err)

	err = client.RemoveNetwork(context.Background(), "")
	assert.Error(t, err)
}

// Add other tests for Connect, Disconnect, Prune, etc. following similar patterns
