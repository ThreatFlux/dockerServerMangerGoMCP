package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	registrytypes "github.com/docker/docker/api/types/registry" // Added for AuthConfig
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/image"
)

// BuildManager manages image build operations
type BuildManager struct {
	client       client.APIClient
	logger       *logrus.Logger
	buildTimeout time.Duration
}

// BuildResult represents the result of a build operation
type BuildResult struct {
	ImageID   string
	Error     error
	BuildTime time.Duration
	Warnings  []string
}

// NewBuildManager creates a new build manager
func NewBuildManager(client client.APIClient, logger *logrus.Logger) *BuildManager {
	if logger == nil {
		logger = logrus.New()
	}

	return &BuildManager{
		client:       client,
		logger:       logger,
		buildTimeout: 30 * time.Minute,
	}
}

// Build builds an image
func (m *BuildManager) Build(ctx context.Context, options image.BuildOptions) (io.ReadCloser, error) {
	startTime := time.Now()
	m.logger.WithFields(logrus.Fields{
		"dockerfile": options.Dockerfile,
		"tags":       options.Tags,
		"no_cache":   options.NoCache,
	}).Info("Building Docker image")

	// Validate options
	if err := m.validateBuildOptions(options); err != nil {
		return nil, err
	}

	// Create context with timeout if not already set
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, m.buildTimeout)
		defer cancel()
	}

	// Prepare build context
	buildContext, err := m.prepareBuildContext(options)
	if err != nil {
		return nil, err
	}

	// Prepare build options
	buildOpts := types.ImageBuildOptions{
		Tags:           options.Tags,
		Dockerfile:     options.Dockerfile,
		NoCache:        options.NoCache,
		Remove:         options.Remove,
		ForceRemove:    options.ForceRemove,
		PullParent:     options.PullParent,
		SuppressOutput: options.ProgressOutput == nil,
		Labels:         options.BuildLabels,
		BuildArgs:      options.BuildArgs,
		Target:         options.Target,
		Platform:       options.Platform,
		Version:        types.BuilderV1, // Use BuildKit if available
	}

	// If auth provided, add it to build options
	if options.RegistryAuth != "" {
		buildOpts.AuthConfigs = map[string]registrytypes.AuthConfig{} // Use registrytypes
		var authConfig registrytypes.AuthConfig                       // Use registrytypes
		if err := json.Unmarshal([]byte(options.RegistryAuth), &authConfig); err == nil {
			registry := authConfig.ServerAddress
			if registry == "" {
				registry = "https://index.docker.io/v1/"
			}
			buildOpts.AuthConfigs[registry] = authConfig
		}
	}

	// Build the image
	response, err := m.client.ImageBuild(ctx, buildContext, buildOpts)
	if err != nil {
		// Check if operation was cancelled
		if ctx.Err() == context.Canceled {
			return nil, ErrBuildCancelled
		} else if ctx.Err() == context.DeadlineExceeded {
			return nil, ErrBuildTimeout
		}
		return nil, fmt.Errorf("%w: %v", ErrImageBuild, err)
	}

	m.logger.WithField("duration", time.Since(startTime).String()).Info("Docker image build initiated")

	// If progress output is set, decode JSON messages
	if options.ProgressOutput != nil {
		// Create a pipe to connect the response to the progress output
		pr, pw := io.Pipe()

		go func() {
			defer pw.Close()
			defer response.Body.Close()

			// Forward and decode JSON messages
			err := jsonmessage.DisplayJSONMessagesStream(response.Body, pw, 0, false, nil)
			if err != nil && err != io.EOF {
				m.logger.WithError(err).Warning("Error processing image build progress")
			}
		}()

		// Return the read end of the pipe
		return pr, nil
	}

	return response.Body, nil
}

// BuildAndWait builds an image and waits for completion
func (m *BuildManager) BuildAndWait(ctx context.Context, options image.BuildOptions) (BuildResult, error) {
	startTime := time.Now()
	result := BuildResult{}

	// Build the image
	responseBody, err := m.Build(ctx, options)
	if err != nil {
		result.Error = err
		return result, err
	}
	defer responseBody.Close()

	// Decode JSON messages to extract image ID and warnings
	decoder := json.NewDecoder(responseBody)
	for {
		var msg jsonmessage.JSONMessage
		if err := decoder.Decode(&msg); err != nil {
			if err == io.EOF {
				break
			}
			result.Error = fmt.Errorf("error decoding build response: %w", err)
			return result, result.Error
		}

		// Check for error
		if msg.Error != nil {
			result.Error = errors.New(msg.Error.Message)
			return result, result.Error
		}

		// Extract image ID from aux field
		if msg.Aux != nil {
			var buildResponse struct {
				ID string `json:"ID"`
			}
			if err := json.Unmarshal(*msg.Aux, &buildResponse); err == nil && buildResponse.ID != "" {
				result.ImageID = buildResponse.ID
			}
		}

		// Collect warnings
		if msg.Stream != "" && strings.Contains(msg.Stream, "WARNING") {
			result.Warnings = append(result.Warnings, strings.TrimSpace(msg.Stream))
		}
	}

	result.BuildTime = time.Since(startTime)
	return result, nil
}

// validateBuildOptions validates build options
func (m *BuildManager) validateBuildOptions(options image.BuildOptions) error {
	// Check if we have a context or context directory
	if options.Context == nil && options.ContextDir == "" {
		return fmt.Errorf("%w: either Context or ContextDir must be provided", ErrInvalidBuildOptions)
	}

	// Check if we have at least one tag
	if len(options.Tags) == 0 {
		return fmt.Errorf("%w: at least one tag must be provided", ErrInvalidBuildOptions)
	}

	return nil
}

// prepareBuildContext prepares the build context
func (m *BuildManager) prepareBuildContext(options image.BuildOptions) (io.Reader, error) {
	// If context is already provided, use it
	if options.Context != nil {
		return options.Context, nil
	}

	// Use context directory
	if options.ContextDir != "" {
		// Check if directory exists
		if _, err := os.Stat(options.ContextDir); os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: directory %s does not exist", ErrBuildContextNotFound, options.ContextDir)
		}

		// Check if Dockerfile exists if specified
		if options.Dockerfile != "" && options.Dockerfile != "Dockerfile" {
			dockerfilePath := filepath.Join(options.ContextDir, options.Dockerfile)
			if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
				return nil, fmt.Errorf("%w: %s not found in context directory", ErrDockerfileNotFound, options.Dockerfile)
			}
		}

		// Create tar archive of the directory
		tarContext, err := archive.TarWithOptions(options.ContextDir, &archive.TarOptions{
			Compression:     archive.Gzip,
			ExcludePatterns: []string{".git", "node_modules", ".DS_Store"},
		})
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBuildContextCreation, err)
		}

		return tarContext, nil
	}

	return nil, fmt.Errorf("%w: no build context provided", ErrInvalidBuildOptions)
}

// SetBuildTimeout sets the timeout for build operations
func (m *BuildManager) SetBuildTimeout(timeout time.Duration) {
	if timeout > 0 {
		m.buildTimeout = timeout
	}
}
