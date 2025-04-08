package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Assuming models.Network is defined here
)

// EncodeRegistryAuth encodes registry authentication details into a base64 string
// suitable for the X-Registry-Auth header.
func EncodeRegistryAuth(authConfig models.RegistryAuth) (string, error) {
	authBytes, err := json.Marshal(authConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal registry auth config: %w", err)
	}
	return base64.URLEncoding.EncodeToString(authBytes), nil
}

// ContainsString checks if a slice of strings contains a specific string.
// Case-insensitive comparison.
// NOTE: This specific implementation is not used by network_controller.go anymore,
// but kept here in case it's used elsewhere or intended for a different purpose.
func ContainsString(slice []string, str string) bool {
	lowerStr := strings.ToLower(str)
	for _, item := range slice {
		if strings.ToLower(item) == lowerStr {
			return true
		}
	}
	return false
}

// SortNetworks sorts a slice of Network models.
// Placeholder implementation - returns the original slice.
// TODO: Implement actual sorting logic based on sortBy and sortOrder.
func SortNetworks(networks []*models.Network, sortBy string, sortOrder string) []*models.Network {
	// Placeholder: Add actual sorting logic here using sort.SliceStable
	// Example:
	// sort.SliceStable(networks, func(i, j int) bool {
	//     netI := networks[i]
	//     netJ := networks[j]
	//     var less bool
	//     switch sortBy {
	//     case "name":
	//         less = netI.Name < netJ.Name
	//     case "driver":
	//         less = netI.Driver < netJ.Driver
	//     case "created":
	//         less = netI.Created.Before(netJ.Created)
	//     default: // Default sort by name
	//         less = netI.Name < netJ.Name
	//     }
	//     if sortOrder == "desc" {
	//         return !less
	//     }
	//     return less
	// })
	return networks
}

// StringHasPrefix is a simple wrapper around strings.HasPrefix.
func StringHasPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}

// ConvertJSONMapToStringMap converts models.JSONMap to map[string]string
func ConvertJSONMapToStringMap(jsonMap models.JSONMap) map[string]string {
	if jsonMap == nil {
		return nil
	}
	stringMap := make(map[string]string)
	for k, v := range jsonMap {
		stringMap[k] = fmt.Sprintf("%v", v) // Simple conversion
	}
	return stringMap
}

// TODO: Add other missing helper functions like ConvertStringMapToFilters etc.
