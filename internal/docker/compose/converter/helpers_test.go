package converter

import (
	"testing"

	"github.com/docker/docker/api/types/mount"
	"github.com/docker/go-connections/nat"
	"time" // Added for durationPtr

	compose "github.com/compose-spec/compose-go/v2/types" // Import compose-go types
	"github.com/docker/docker/api/types/container"        // Added for container.HealthConfig
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// Helper functions for pointers in tests
func durationPtr(d time.Duration) *compose.Duration {
	cd := compose.Duration(d)
	return &cd
}

func uint64Ptr(u uint64) *uint64 {
	return &u
}

func TestStringOrStringSlice(t *testing.T) {
	testCases := []struct {
		name          string
		input         interface{}
		expected      []string
		expectError   bool
		errorContains string
	}{
		{
			name:        "string",
			input:       "value",
			expected:    []string{"value"},
			expectError: false,
		},
		{
			name:        "string slice",
			input:       []string{"value1", "value2"},
			expected:    []string{"value1", "value2"},
			expectError: false,
		},
		{
			name:        "interface slice with strings",
			input:       []interface{}{"value1", "value2"},
			expected:    []string{"value1", "value2"},
			expectError: false,
		},
		{
			name:          "interface slice with non-strings",
			input:         []interface{}{"value1", 123},
			expected:      nil,
			expectError:   true,
			errorContains: "invalid string item",
		},
		{
			name:        "nil",
			input:       nil,
			expected:    nil,
			expectError: false,
		},
		{
			name:          "unsupported type",
			input:         123,
			expected:      nil,
			expectError:   true,
			errorContains: "unsupported type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := StringOrStringSlice(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestMapOrListToMap(t *testing.T) {
	testCases := []struct {
		name          string
		input         interface{}
		expected      map[string]string
		expectError   bool
		errorContains string
	}{
		{
			name: "string map",
			input: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectError: false,
		},
		{
			name: "string interface map",
			input: map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectError: false,
		},
		{
			name: "interface interface map",
			input: map[interface{}]interface{}{
				"key1": "value1",
				"key2": "value2",
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectError: false,
		},
		{
			name:  "string slice with key=value pairs",
			input: []string{"key1=value1", "key2=value2"},
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectError: false,
		},
		{
			name:  "interface slice with key=value strings",
			input: []interface{}{"key1=value1", "key2=value2"},
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectError: false,
		},
		{
			name:          "interface slice with non-strings",
			input:         []interface{}{"key1=value1", 123},
			expected:      nil,
			expectError:   true,
			errorContains: "invalid string item",
		},
		{
			name:          "invalid key=value format",
			input:         []string{"key1:value1"},
			expected:      nil,
			expectError:   true,
			errorContains: "invalid key=value pair",
		},
		{
			name:        "nil",
			input:       nil,
			expected:    nil,
			expectError: false,
		},
		{
			name:          "unsupported type",
			input:         123,
			expected:      nil,
			expectError:   true,
			errorContains: "unsupported type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := MapOrListToMap(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestConvertCommand(t *testing.T) {
	testCases := []struct {
		name          string
		input         interface{}
		expected      []string
		expectError   bool
		errorContains string
	}{
		{
			name:        "string",
			input:       "echo hello",
			expected:    []string{"/bin/sh", "-c", "echo hello"},
			expectError: false,
		},
		{
			name:        "string slice",
			input:       []string{"echo", "hello"},
			expected:    []string{"echo", "hello"},
			expectError: false,
		},
		{
			name:        "interface slice with strings",
			input:       []interface{}{"echo", "hello"},
			expected:    []string{"echo", "hello"},
			expectError: false,
		},
		{
			name:          "interface slice with non-strings",
			input:         []interface{}{"echo", 123},
			expected:      nil,
			expectError:   true,
			errorContains: "invalid string item",
		},
		{
			name:        "nil",
			input:       nil,
			expected:    nil,
			expectError: false,
		},
		{
			name:          "unsupported type",
			input:         123,
			expected:      nil,
			expectError:   true,
			errorContains: "unsupported type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ConvertCommand(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestConvertPorts(t *testing.T) {
	testCases := []struct {
		name           string
		input          interface{}
		expectedBinds  nat.PortMap
		expectedExpose nat.PortSet
		expectError    bool
		errorContains  string
	}{
		{
			name:  "string slice",
			input: []string{"80:80", "443:443"},
			expectedBinds: nat.PortMap{
				"80/tcp":  []nat.PortBinding{{HostIP: "", HostPort: "80"}},
				"443/tcp": []nat.PortBinding{{HostIP: "", HostPort: "443"}},
			},
			expectedExpose: nat.PortSet{
				"80/tcp":  struct{}{},
				"443/tcp": struct{}{},
			},
			expectError: false,
		},
		{
			name:  "interface slice with strings",
			input: []interface{}{"80:80", "443:443"},
			expectedBinds: nat.PortMap{
				"80/tcp":  []nat.PortBinding{{HostIP: "", HostPort: "80"}},
				"443/tcp": []nat.PortBinding{{HostIP: "", HostPort: "443"}},
			},
			expectedExpose: nat.PortSet{
				"80/tcp":  struct{}{},
				"443/tcp": struct{}{},
			},
			expectError: false,
		},
		{
			name:          "exposed port only",
			input:         []string{"80"},
			expectedBinds: nat.PortMap{},
			expectedExpose: nat.PortSet{
				"80/tcp": struct{}{},
			},
			expectError: false,
		},
		{
			name:           "interface slice with non-strings",
			input:          []interface{}{"80:80", 123},
			expectedBinds:  nil,
			expectedExpose: nil,
			expectError:    true,
			errorContains:  "invalid string item",
		},
		{
			name:           "invalid port specification",
			input:          []string{"invalid"},
			expectedBinds:  nil,
			expectedExpose: nil,
			expectError:    true,
			errorContains:  "invalid port specification",
		},
		{
			name:           "nil",
			input:          nil,
			expectedBinds:  nat.PortMap{},
			expectedExpose: nat.PortSet{},
			expectError:    false,
		},
		{
			name:           "unsupported type",
			input:          123,
			expectedBinds:  nil,
			expectedExpose: nil,
			expectError:    true,
			errorContains:  "unsupported type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			binds, expose, err := ConvertPorts(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedBinds, binds)
				assert.Equal(t, tc.expectedExpose, expose)
			}
		})
	}
}

func TestConvertExposedPorts(t *testing.T) {
	testCases := []struct {
		name          string
		input         interface{}
		expected      nat.PortSet
		expectError   bool
		errorContains string
	}{
		{
			name:  "string slice",
			input: []string{"80", "443"},
			expected: nat.PortSet{
				"80/tcp":  struct{}{},
				"443/tcp": struct{}{},
			},
			expectError: false,
		},
		{
			name:  "interface slice with strings",
			input: []interface{}{"80", "443"},
			expected: nat.PortSet{
				"80/tcp":  struct{}{},
				"443/tcp": struct{}{},
			},
			expectError: false,
		},
		{
			name:          "interface slice with non-strings",
			input:         []interface{}{"80", 123},
			expected:      nil,
			expectError:   true,
			errorContains: "invalid string item",
		},
		{
			name:          "invalid port",
			input:         []string{"invalid"},
			expected:      nil,
			expectError:   true,
			errorContains: "invalid exposed port",
		},
		{
			name:        "nil",
			input:       nil,
			expected:    nat.PortSet{},
			expectError: false,
		},
		{
			name:          "unsupported type",
			input:         123,
			expected:      nil,
			expectError:   true,
			errorContains: "unsupported type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ConvertExposedPorts(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseVolumeSpec(t *testing.T) {
	testCases := []struct {
		name          string
		spec          string
		workingDir    string
		expected      mount.Mount
		anonymous     bool
		expectError   bool
		errorContains string
	}{
		{
			name:       "anonymous volume",
			spec:       "/data",
			workingDir: "/app",
			expected: mount.Mount{
				Type:     mount.TypeVolume,
				Source:   "",
				Target:   "/data",
				ReadOnly: false,
			},
			anonymous:   true,
			expectError: false,
		},
		{
			name:       "named volume",
			spec:       "myvolume:/data",
			workingDir: "/app",
			expected: mount.Mount{
				Type:     mount.TypeVolume,
				Source:   "myvolume",
				Target:   "/data",
				ReadOnly: false,
			},
			anonymous:   false,
			expectError: false,
		},
		{
			name:       "bind mount with absolute path",
			spec:       "/src:/data",
			workingDir: "/app",
			expected: mount.Mount{
				Type:     mount.TypeBind,
				Source:   "/src",
				Target:   "/data",
				ReadOnly: false,
			},
			anonymous:   false,
			expectError: false,
		},
		{
			name:       "bind mount with relative path",
			spec:       "./src:/data",
			workingDir: "/app",
			expected: mount.Mount{
				Type:     mount.TypeBind,
				Source:   "/app/src",
				Target:   "/data",
				ReadOnly: false,
			},
			anonymous:   false,
			expectError: false,
		},
		{
			name:       "readonly volume",
			spec:       "myvolume:/data:ro",
			workingDir: "/app",
			expected: mount.Mount{
				Type:     mount.TypeVolume,
				Source:   "myvolume",
				Target:   "/data",
				ReadOnly: true,
			},
			anonymous:   false,
			expectError: false,
		},
		{
			name:          "invalid volume spec",
			spec:          "invalid:spec:with:too:many:colons",
			workingDir:    "/app",
			expected:      mount.Mount{},
			anonymous:     false,
			expectError:   true,
			errorContains: "invalid volume specification",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, anonymous, err := ParseVolumeSpec(tc.spec, tc.workingDir)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
				assert.Equal(t, tc.anonymous, anonymous)
			}
		})
	}
}

func TestConvertVolumes(t *testing.T) {
	testCases := []struct {
		name           string
		input          interface{}
		workingDir     string
		expectedMounts []mount.Mount
		expectedVols   map[string]struct{}
		expectError    bool
		errorContains  string
	}{
		{
			name:       "string slice",
			input:      []string{"/data", "myvolume:/app/data"},
			workingDir: "/app",
			expectedMounts: []mount.Mount{
				{
					Type:     mount.TypeVolume,
					Source:   "",
					Target:   "/data",
					ReadOnly: false,
				},
				{
					Type:     mount.TypeVolume,
					Source:   "myvolume",
					Target:   "/app/data",
					ReadOnly: false,
				},
			},
			expectedVols: map[string]struct{}{
				"": {},
			},
			expectError: false,
		},
		{
			name:       "interface slice with strings",
			input:      []interface{}{"/data", "myvolume:/app/data"},
			workingDir: "/app",
			expectedMounts: []mount.Mount{
				{
					Type:     mount.TypeVolume,
					Source:   "",
					Target:   "/data",
					ReadOnly: false,
				},
				{
					Type:     mount.TypeVolume,
					Source:   "myvolume",
					Target:   "/app/data",
					ReadOnly: false,
				},
			},
			expectedVols: map[string]struct{}{
				"": {},
			},
			expectError: false,
		},
		{
			name:           "nil",
			input:          nil,
			workingDir:     "/app",
			expectedMounts: []mount.Mount{},
			expectedVols:   map[string]struct{}{},
			expectError:    false,
		},
		{
			name:           "unsupported type",
			input:          123,
			workingDir:     "/app",
			expectedMounts: nil,
			expectedVols:   nil,
			expectError:    true,
			errorContains:  "unsupported type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := logrus.New()
			mounts, vols, err := ConvertVolumes(tc.input, tc.workingDir, logger)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedMounts, mounts)
				assert.Equal(t, tc.expectedVols, vols)
			}
		})
	}
}

func TestConvertRestartPolicy(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no",
			input:    "no",
			expected: "no",
		},
		{
			name:     "always",
			input:    "always",
			expected: "always",
		},
		{
			name:     "on-failure",
			input:    "on-failure",
			expected: "on-failure",
		},
		{
			name:     "unless-stopped",
			input:    "unless-stopped",
			expected: "unless-stopped",
		},
		{
			name:     "invalid",
			input:    "invalid",
			expected: "no",
		},
		{
			name:     "empty",
			input:    "",
			expected: "no",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ConvertRestartPolicy(tc.input)
			assert.Equal(t, tc.expected, result.Name)
		})
	}
}

func TestConvertHealthCheck(t *testing.T) {
	logger := logrus.New() // Add logger instance
	logger.SetLevel(logrus.ErrorLevel)

	testCases := []struct {
		name          string
		input         *compose.HealthCheckConfig
		expected      *container.HealthConfig // Expect container.HealthConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "string test",
			input: &compose.HealthCheckConfig{
				Test:     compose.HealthCheckTest{"CMD-SHELL", "curl -f http://localhost"}, // Use correct type
				Interval: durationPtr(30 * time.Second),                                    // Use pointer helper
				Timeout:  durationPtr(10 * time.Second),                                    // Use pointer helper
				Retries:  uint64Ptr(3),                                                     // Use pointer helper
			},
			expected: &container.HealthConfig{ // Expect container.HealthConfig
				Test:     []string{"CMD-SHELL", "curl -f http://localhost"},
				Interval: 30 * time.Second,
				Timeout:  10 * time.Second,
				Retries:  3,
			},
			expectError: false,
		},
		{
			name: "string slice test",
			input: &compose.HealthCheckConfig{
				Test:     compose.HealthCheckTest{"CMD", "curl", "-f", "http://localhost"}, // Use correct type
				Interval: durationPtr(30 * time.Second),                                    // Use pointer helper
				Timeout:  durationPtr(10 * time.Second),                                    // Use pointer helper
				Retries:  uint64Ptr(3),                                                     // Use pointer helper
			},
			expected: &container.HealthConfig{ // Expect container.HealthConfig
				Test:     []string{"CMD", "curl", "-f", "http://localhost"},
				Interval: 30 * time.Second,
				Timeout:  10 * time.Second,
				Retries:  3,
			},
			expectError: false,
		},
		// Note: compose-go doesn't support []interface{} for Test, only []string.
		// Removing the "interface slice test" case.
		{
			name: "disabled",
			input: &compose.HealthCheckConfig{
				Disable: true,
			},
			expected: &container.HealthConfig{ // Expect container.HealthConfig
				Test: []string{"NONE"},
			},
			expectError: false,
		},
		{
			name:        "nil",
			input:       nil,
			expected:    nil, // Expect nil container.HealthConfig
			expectError: false,
		},
		{
			name: "invalid interval",
			input: &compose.HealthCheckConfig{
				Test: compose.HealthCheckTest{"CMD-SHELL", "curl -f http://localhost"}, // Use correct type
				// Interval: durationPtr("invalid"), // Cannot create duration from invalid string directly
			},
			// Expected error comes from ConvertHealthCheck parsing the duration
			expected:      nil,
			expectError:   true,
			errorContains: "invalid interval",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Handle the invalid interval case specifically
			if tc.name == "invalid interval" {
				tc.input.Interval = nil // Simulate missing or invalid interval for error check
			}

			// Pass logger to ConvertHealthCheck
			result, err := ConvertHealthCheck(tc.input) // Remove logger argument

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result) // Expect nil on error
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				// Compare container.HealthConfig structs
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseMemory(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expected      int64
		expectError   bool
		errorContains string
	}{
		{
			name:        "bytes",
			input:       "1024",
			expected:    1024,
			expectError: false,
		},
		{
			name:        "kilobytes",
			input:       "1k",
			expected:    1024,
			expectError: false,
		},
		{
			name:        "kilobytes with KB suffix",
			input:       "1kb",
			expected:    1024,
			expectError: false,
		},
		{
			name:        "megabytes",
			input:       "1m",
			expected:    1048576, // 1024 * 1024
			expectError: false,
		},
		{
			name:        "megabytes with MB suffix",
			input:       "1mb",
			expected:    1048576, // 1024 * 1024
			expectError: false,
		},
		{
			name:        "gigabytes",
			input:       "1g",
			expected:    1073741824, // 1024 * 1024 * 1024
			expectError: false,
		},
		{
			name:        "gigabytes with GB suffix",
			input:       "1gb",
			expected:    1073741824, // 1024 * 1024 * 1024
			expectError: false,
		},
		{
			name:        "fractional value",
			input:       "0.5g",
			expected:    536870912, // 0.5 * 1024 * 1024 * 1024
			expectError: false,
		},
		{
			name:        "empty",
			input:       "",
			expected:    0,
			expectError: false,
		},
		{
			name:          "invalid value",
			input:         "invalid",
			expected:      0,
			expectError:   true,
			errorContains: "invalid memory value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseMemory(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseCPUs(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expected      int64
		expectError   bool
		errorContains string
	}{
		{
			name:        "single CPU",
			input:       "1",
			expected:    1000000000, // 1 * 10^9 (nano CPUs)
			expectError: false,
		},
		{
			name:        "fractional CPU",
			input:       "0.5",
			expected:    500000000, // 0.5 * 10^9 (nano CPUs)
			expectError: false,
		},
		{
			name:        "multiple CPUs",
			input:       "2.5",
			expected:    2500000000, // 2.5 * 10^9 (nano CPUs)
			expectError: false,
		},
		{
			name:        "empty",
			input:       "",
			expected:    0,
			expectError: false,
		},
		{
			name:          "invalid value",
			input:         "invalid",
			expected:      0,
			expectError:   true,
			errorContains: "invalid CPU value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseCPUs(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestMergeStringMaps(t *testing.T) {
	testCases := []struct {
		name     string
		map1     map[string]string
		map2     map[string]string
		expected map[string]string
	}{
		{
			name: "non-overlapping maps",
			map1: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			map2: map[string]string{
				"key3": "value3",
				"key4": "value4",
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
				"key4": "value4",
			},
		},
		{
			name: "overlapping maps",
			map1: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			map2: map[string]string{
				"key2": "new-value2",
				"key3": "value3",
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "new-value2",
				"key3": "value3",
			},
		},
		{
			name: "empty first map",
			map1: map[string]string{},
			map2: map[string]string{
				"key1": "value1",
			},
			expected: map[string]string{
				"key1": "value1",
			},
		},
		{
			name: "empty second map",
			map1: map[string]string{
				"key1": "value1",
			},
			map2: map[string]string{},
			expected: map[string]string{
				"key1": "value1",
			},
		},
		{
			name:     "both empty maps",
			map1:     map[string]string{},
			map2:     map[string]string{},
			expected: map[string]string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := MergeStringMaps(tc.map1, tc.map2)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestConvertNetworkConfig(t *testing.T) {
	testCases := []struct {
		name            string
		input           interface{}
		expectedConfigs map[string]bool // Just check the keys, not the full config
		expectedNames   []string
		expectError     bool
		errorContains   string
	}{
		{
			name:  "string slice",
			input: []string{"network1", "network2"},
			expectedConfigs: map[string]bool{
				"network1": true,
				"network2": true,
			},
			expectedNames: []string{"network1", "network2"},
			expectError:   false,
		},
		{
			name:  "interface slice with strings",
			input: []interface{}{"network1", "network2"},
			expectedConfigs: map[string]bool{
				"network1": true,
				"network2": true,
			},
			expectedNames: []string{"network1", "network2"},
			expectError:   false,
		},
		{
			name: "map with configs",
			input: map[string]interface{}{
				"network1": map[string]interface{}{
					"aliases": []string{"alias1", "alias2"},
				},
				"network2": map[string]interface{}{
					"ipv4_address": "192.168.1.5",
				},
			},
			expectedConfigs: map[string]bool{
				"network1": true,
				"network2": true,
			},
			expectedNames: []string{"network1", "network2"},
			expectError:   false,
		},
		{
			name:            "nil",
			input:           nil,
			expectedConfigs: map[string]bool{},
			expectedNames:   []string{},
			expectError:     false,
		},
		{
			name:            "unsupported type",
			input:           123,
			expectedConfigs: nil,
			expectedNames:   nil,
			expectError:     true,
			errorContains:   "unsupported type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configs, names, err := ConvertNetworkConfig(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, configs)
				assert.Nil(t, names)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)

				// Check that all expected configs are present
				for name := range tc.expectedConfigs {
					assert.Contains(t, configs, name)
				}

				// Check that the number of configs matches
				assert.Equal(t, len(tc.expectedConfigs), len(configs))

				// Check that all expected names are present
				for _, name := range tc.expectedNames {
					assert.Contains(t, names, name)
				}

				// Check that the number of names matches
				assert.Equal(t, len(tc.expectedNames), len(names))
			}
		})
	}
}

func TestConvertDependsOn(t *testing.T) {
	testCases := []struct {
		name               string
		input              interface{}
		expectedDeps       []string
		expectedConditions map[string]string
		expectError        bool
		errorContains      string
	}{
		{
			name:         "string slice",
			input:        []string{"service1", "service2"},
			expectedDeps: []string{"service1", "service2"},
			expectedConditions: map[string]string{
				"service1": "service_started",
				"service2": "service_started",
			},
			expectError: false,
		},
		{
			name:         "interface slice with strings",
			input:        []interface{}{"service1", "service2"},
			expectedDeps: []string{"service1", "service2"},
			expectedConditions: map[string]string{
				"service1": "service_started",
				"service2": "service_started",
			},
			expectError: false,
		},
		{
			name: "map with conditions",
			input: map[string]interface{}{
				"service1": map[string]interface{}{
					"condition": "service_healthy",
				},
				"service2": map[string]interface{}{
					"condition": "service_completed_successfully",
				},
			},
			expectedDeps: []string{"service1", "service2"},
			expectedConditions: map[string]string{
				"service1": "service_healthy",
				"service2": "service_completed_successfully",
			},
			expectError: false,
		},
		{
			name:               "nil",
			input:              nil,
			expectedDeps:       []string{},
			expectedConditions: map[string]string{},
			expectError:        false,
		},
		{
			name:               "unsupported type",
			input:              123,
			expectedDeps:       nil,
			expectedConditions: nil,
			expectError:        true,
			errorContains:      "unsupported type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			deps, conditions, err := ConvertDependsOn(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, deps)
				assert.Nil(t, conditions)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)

				// Sort deps for comparison
				assert.ElementsMatch(t, tc.expectedDeps, deps)

				// Check conditions
				for name, condition := range tc.expectedConditions {
					assert.Equal(t, condition, conditions[name])
				}

				// Check that the number of conditions matches
				assert.Equal(t, len(tc.expectedConditions), len(conditions))
			}
		})
	}
}

func TestSanitizeContainerName(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple name",
			input:    "container1",
			expected: "container1",
		},
		{
			name:     "name with spaces",
			input:    "container 1",
			expected: "container_1",
		},
		{
			name:     "name with slashes",
			input:    "project/container1",
			expected: "project_container1",
		},
		{
			name:     "empty name",
			input:    "",
			expected: "container",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := SanitizeContainerName(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGenerateContainerName(t *testing.T) {
	testCases := []struct {
		name        string
		projectName string
		serviceName string
		index       int
		expected    string
	}{
		{
			name:        "simple names",
			projectName: "project1",
			serviceName: "service1",
			index:       0,
			expected:    "project1_service1",
		},
		{
			name:        "with index",
			projectName: "project1",
			serviceName: "service1",
			index:       1,
			expected:    "project1_service1_1",
		},
		{
			name:        "names with spaces and slashes",
			projectName: "my project",
			serviceName: "web/app",
			index:       0,
			expected:    "my_project_web_app",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := GenerateContainerName(tc.projectName, tc.serviceName, tc.index)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateExternalResource(t *testing.T) {
	testCases := []struct {
		name          string
		input         interface{}
		resourceType  string
		resourceName  string
		isExternal    bool
		externalName  string
		expectError   bool
		errorContains string
	}{
		{
			name:         "boolean true",
			input:        true,
			resourceType: "volume",
			resourceName: "myvolume",
			isExternal:   true,
			externalName: "myvolume",
			expectError:  false,
		},
		{
			name:         "boolean false",
			input:        false,
			resourceType: "volume",
			resourceName: "myvolume",
			isExternal:   false,
			externalName: "myvolume",
			expectError:  false,
		},
		{
			name: "map with name",
			input: map[string]interface{}{
				"name": "external-volume",
			},
			resourceType: "volume",
			resourceName: "myvolume",
			isExternal:   true,
			externalName: "external-volume",
			expectError:  false,
		},
		{
			name:          "unsupported type",
			input:         123,
			resourceType:  "volume",
			resourceName:  "myvolume",
			isExternal:    false,
			externalName:  "",
			expectError:   true,
			errorContains: "unsupported type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isExternal, externalName, err := ValidateExternalResource(tc.input, tc.resourceType, tc.resourceName)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.isExternal, isExternal)
				assert.Equal(t, tc.externalName, externalName)
			}
		})
	}
}
