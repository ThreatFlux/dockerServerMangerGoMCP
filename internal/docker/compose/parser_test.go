package compose

import (
	"context"
	// "os" // Removed unused import
	// "path/filepath" // Removed unused import
	"strings"
	"testing"
	// "time" // Removed unused import

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	// composetypes "github.com/compose-spec/compose-go/v2/types" // Removed unused import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models" // Added models import
)

// TestParser_Parse tests the Parse method
func TestParser_Parse(t *testing.T) {
	// Create test cases
	testCases := []struct {
		name          string
		yaml          string
		options       models.ParseOptions // Use models.ParseOptions
		expectError   bool
		errorContains string
		verify        func(t *testing.T, compose *models.ComposeFile) // Revert to models.ComposeFile
	}{
		{
			name: "basic valid compose file",
			yaml: `
version: '3'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
  db:
    image: postgres:13
    environment:
      POSTGRES_PASSWORD: example
`,
			options:     models.ParseOptions{}, // Use models.ParseOptions
			expectError: false,
			verify: func(t *testing.T, compose *models.ComposeFile) { // Revert to models.ComposeFile
				assert.Equal(t, "3", compose.Version) // models.ComposeFile has Version
				assert.Len(t, compose.Services, 2)
				assert.Contains(t, compose.Services, "web")
				assert.Contains(t, compose.Services, "db")
				assert.Equal(t, "nginx:latest", compose.Services["web"].Image)
				assert.Equal(t, "postgres:13", compose.Services["db"].Image)
			},
		},
		{
			name: "missing version",
			yaml: `
services:
  web:
    image: nginx:latest
`,
			options:       models.ParseOptions{}, // Use models.ParseOptions
			expectError:   true,
			errorContains: "missing required field: version",
		},
		{
			name: "unsupported version",
			yaml: `
version: '1'
services:
  web:
    image: nginx:latest
`,
			options:       models.ParseOptions{}, // Use models.ParseOptions
			expectError:   true,
			errorContains: "unsupported compose file version",
		},
		{
			name: "no services",
			yaml: `
version: '3'
`,
			options:       models.ParseOptions{}, // Use models.ParseOptions
			expectError:   true,
			errorContains: "at least one service is required",
		},
		{
			name: "service with no image or build",
			yaml: `
version: '3'
services:
  web:
    ports:
      - "80:80"
`,
			options:       models.ParseOptions{}, // Use models.ParseOptions
			expectError:   true,
			errorContains: "either image or build must be specified",
		},
		{
			name: "environment variable interpolation",
			yaml: `
version: '3'
services:
  web:
    image: ${IMAGE_NAME:-nginx:latest}
    environment:
      DB_HOST: ${DB_HOST}
      DB_PORT: ${DB_PORT:-5432}
`,
			options: models.ParseOptions{ // Use models.ParseOptions
				// Environment field does not exist in models.ParseOptions.
				// Interpolation relies on OS env or EnvFile.
				// EnvFile: "", // Optionally set EnvFile if needed
			},
			expectError: false,
			verify: func(t *testing.T, compose *models.ComposeFile) { // Revert to models.ComposeFile
				assert.Equal(t, "custom-nginx:1.0", compose.Services["web"].Image)

				// Check environment variables (interface{})
				env, ok := compose.Services["web"].Environment.(map[string]interface{})
				require.True(t, ok, "Environment should be map[string]interface{}")
				require.NotNil(t, env)

				dbHost, ok := env["DB_HOST"].(string)
				require.True(t, ok)
				assert.Equal(t, "db.example.com", dbHost)

				dbPort, ok := env["DB_PORT"].(string)
				require.True(t, ok)
				assert.Equal(t, "5432", dbPort)
			},
		},
		{
			name: "with build configuration",
			yaml: `
version: '3'
services:
  web:
    build:
      context: ./app
      dockerfile: Dockerfile.dev
      args:
        - NODE_ENV=development
`,
			options:     models.ParseOptions{}, // Use models.ParseOptions
			expectError: false,
			verify: func(t *testing.T, compose *models.ComposeFile) { // Revert to models.ComposeFile
				buildConfig, ok := compose.Services["web"].Build.(map[string]interface{})
				require.True(t, ok, "Build should be map[string]interface{}")
				assert.NotNil(t, buildConfig)
				assert.Equal(t, "./app", buildConfig["context"])
				assert.Equal(t, "Dockerfile.dev", buildConfig["dockerfile"])
			},
		},
		{
			name: "with volumes and networks",
			yaml: `
version: '3'
services:
  web:
    image: nginx:latest
    volumes:
      - data:/var/www/html
    networks:
      - frontend
networks:
  frontend:
    driver: bridge
volumes:
  data:
    driver: local
`,
			options:     models.ParseOptions{}, // Use models.ParseOptions
			expectError: false,
			verify: func(t *testing.T, compose *models.ComposeFile) { // Revert to models.ComposeFile
				assert.Len(t, compose.Networks, 1)
				assert.Contains(t, compose.Networks, "frontend")
				assert.Equal(t, "bridge", compose.Networks["frontend"].Driver)

				assert.Len(t, compose.Volumes, 1)
				assert.Contains(t, compose.Volumes, "data")
				assert.Equal(t, "local", compose.Volumes["data"].Driver)
			},
		},
		{
			name: "with healthcheck",
			yaml: `
version: '3'
services:
  web:
    image: nginx:latest
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s
`,
			options:     models.ParseOptions{}, // Use models.ParseOptions
			expectError: false,
			verify: func(t *testing.T, compose *models.ComposeFile) { // Revert to models.ComposeFile
				hc := compose.Services["web"].HealthCheck // Already map[string]interface{}
				ok := hc != nil                           // Check if the map is not nil
				require.True(t, ok, "HealthCheck should be map[string]interface{}")
				assert.NotNil(t, hc)
				testCmd, ok := hc["test"].([]interface{}) // YAML unmarshals to []interface{}
				require.True(t, ok)
				assert.Equal(t, []interface{}{"CMD", "curl", "-f", "http://localhost"}, testCmd)
				assert.Equal(t, "30s", hc["interval"])
				assert.Equal(t, "10s", hc["timeout"])
				// YAML unmarshals numbers as float64 or int depending on value
				assert.Equal(t, 3, int(hc["retries"].(float64))) // Assert as int after type assertion
				assert.Equal(t, "5s", hc["start_period"])
			},
		},
		{
			name: "with invalid healthcheck",
			yaml: `
version: '3'
services:
  web:
    image: nginx:latest
    healthcheck:
      interval: not-a-duration
`,
			options:       models.ParseOptions{}, // Use models.ParseOptions
			expectError:   true,
			errorContains: "invalid interval",
		},
		{
			name: "with deploy configuration",
			yaml: `
version: '3'
services:
  web:
    image: nginx:latest
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
      restart_policy:
        condition: on-failure
        max_attempts: 3
      update_config:
        parallelism: 2
        delay: 10s
        order: stop-first
`,
			options:     models.ParseOptions{}, // Use models.ParseOptions
			expectError: false,
			verify: func(t *testing.T, compose *models.ComposeFile) { // Revert to models.ComposeFile
				deploy := compose.Services["web"].Deploy // Already map[string]interface{}
				ok := deploy != nil                      // Check if the map is not nil
				require.True(t, ok, "Deploy should be map[string]interface{}")
				assert.NotNil(t, deploy)
				assert.Equal(t, 3, int(deploy["replicas"].(float64))) // Assert as int

				resources, ok := deploy["resources"].(map[string]interface{})
				require.True(t, ok)
				limits, ok := resources["limits"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "0.5", limits["cpus"])
				assert.Equal(t, "512M", limits["memory"])

				restartPolicy, ok := deploy["restart_policy"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "on-failure", restartPolicy["condition"])
				assert.Equal(t, 3, int(restartPolicy["max_attempts"].(float64))) // Assert as int

				updateConfig, ok := deploy["update_config"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, 2, int(updateConfig["parallelism"].(float64))) // Assert as int
				assert.Equal(t, "10s", updateConfig["delay"])
				assert.Equal(t, "stop-first", updateConfig["order"])
			},
		},
		{
			name: "with invalid deploy configuration",
			yaml: `
version: '3'
services:
  web:
    image: nginx:latest
    deploy:
      restart_policy:
        condition: invalid-condition
`,
			options:       models.ParseOptions{}, // Use models.ParseOptions
			expectError:   true,
			errorContains: "invalid condition",
		},
		{
			name: "with secrets and configs",
			yaml: `
version: '3'
services:
  web:
    image: nginx:latest
    secrets:
      - site_key
    configs:
      - source: nginx_config
        target: /etc/nginx/nginx.conf
secrets:
  site_key:
    file: ./secrets/site_key.txt
configs:
  nginx_config:
    file: ./configs/nginx.conf
`,
			options:     models.ParseOptions{}, // Use models.ParseOptions
			expectError: false,
			verify: func(t *testing.T, compose *models.ComposeFile) { // Revert to models.ComposeFile
				assert.Len(t, compose.Secrets, 1)
				assert.Contains(t, compose.Secrets, "site_key")
				assert.Equal(t, "./secrets/site_key.txt", compose.Secrets["site_key"].File)

				assert.Len(t, compose.Configs, 1)
				assert.Contains(t, compose.Configs, "nginx_config")
				assert.Equal(t, "./configs/nginx.conf", compose.Configs["nginx_config"].File)
			},
		},
		{
			name: "with extension fields",
			yaml: `
version: '3'
services:
  web:
    image: nginx:latest
    x-custom-field: value
x-custom-top-level:
  some: value
`,
			// options: ParseOptions{ // Remove IncludeExtensions field
			// 	IncludeExtensions: true,
			// },
			options:     models.ParseOptions{}, // Use models.ParseOptions
			expectError: false,
			verify: func(t *testing.T, compose *models.ComposeFile) { // Revert to models.ComposeFile
				assert.NotNil(t, compose.Extensions)
				assert.Contains(t, compose.Extensions, "x-custom-top-level")

				assert.NotNil(t, compose.Services["web"].Extensions)
				assert.Contains(t, compose.Services["web"].Extensions, "x-custom-field")
				assert.Equal(t, "value", compose.Services["web"].Extensions["x-custom-field"])
			},
		},
		{
			name: "without extension fields",
			yaml: `
version: '3'
services:
  web:
    image: nginx:latest
    x-custom-field: value
x-custom-top-level:
  some: value
`,
			// options: ParseOptions{ // Remove IncludeExtensions field
			// 	IncludeExtensions: false,
			// },
			options:     models.ParseOptions{}, // Use models.ParseOptions
			expectError: false,
			verify: func(t *testing.T, compose *models.ComposeFile) { // Revert to models.ComposeFile
				// Check if extensions are parsed (they should be due to `yaml:",inline"`)
				assert.NotNil(t, compose.Extensions)
				assert.NotNil(t, compose.Services["web"].Extensions)
			},
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a parser
			parser := NewParser(logrus.New())

			// Create a reader from the YAML string
			reader := strings.NewReader(tc.yaml)

			// Parse the compose file
			compose, err := parser.Parse(context.Background(), reader, tc.options)

			// Check for expected errors
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				return
			}

			// If no error is expected, verify the compose file
			assert.NoError(t, err)
			require.NotNil(t, compose)

			// Run verification function if provided
			if tc.verify != nil {
				tc.verify(t, compose)
			}
		})
	}
}

// TestParser_ParseFile removed as ParseFile method was removed from Parser

// // TestParser_InterpolateEnvVars tests the interpolateEnvVars method
// // NOTE: Interpolation is now handled by the compose-go library itself during parsing.
// // This test is removed as the internal method no longer exists.
// func TestParser_InterpolateEnvVars(t *testing.T) {
// 	// ... (removed test content)
// }
