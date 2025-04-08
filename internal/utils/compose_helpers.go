package utils

import "strings"

// IsExternalResource checks if a resource is marked as external in compose files.
func IsExternalResource(external interface{}) bool {
	if external == nil {
		return false
	}
	switch v := external.(type) {
	case bool:
		return v
	case map[string]interface{}:
		// Handle structure like external: { name: some_name }
		// Consider it external if the map exists.
		return true
	case string:
		// Handle deprecated string format external: "true"
		return strings.ToLower(v) == "true"
	default:
		return false
	}
}

// GetResourceName generates the full resource name based on project and prefix.
// Follows Docker Compose naming convention (project_name) if prefix is empty.
func GetResourceName(projectName, prefix, name string) string {
	if prefix != "" {
		// Use prefix if provided (overrides project name convention)
		return prefix + name
	}
	if projectName != "" {
		// Default Docker Compose naming convention: project_name
		return projectName + "_" + name
	}
	// Fallback to just the name if no project or prefix
	return name
}

// GetExternalResourceName gets the name of an external resource from compose config.
func GetExternalResourceName(external interface{}, defaultName string) string {
	if external == nil {
		return defaultName
	}
	switch v := external.(type) {
	case map[string]interface{}:
		// Check for external: { name: "actual_resource_name" }
		if name, ok := v["name"].(string); ok && name != "" {
			return name
		}
	case string: // Handle deprecated string format external: "true" or external: "some_name"
		// If it's not "true" and not empty, assume it's the external name
		if strings.ToLower(v) != "true" && v != "" {
			return v
		}
	}
	// Fallback to the default name if external format is unexpected or name isn't specified
	return defaultName
}
