package operations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/distribution/reference"                         // Use the non-deprecated path
	imagetypes "github.com/docker/docker/api/types/image"       // Added for PullOptions
	registrytypes "github.com/docker/docker/api/types/registry" // Added for AuthConfig
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/image"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/docker/registry"
)

// PullManager manages image pull operations
type PullManager struct {
	client       client.APIClient
	logger       *logrus.Logger
	credentials  registry.CredentialStore
	pullTimeout  time.Duration
	defaultRetry int
}

// PullOptions defines options for the pull operation
type PullOptions struct {
	// All controls whether all tags for the repository should be pulled
	All bool

	// Platform specifies the platform for the pulled image (e.g., linux/amd64)
	Platform string

	// RegistryAuth is the base64-encoded auth configuration
	RegistryAuth string

	// Progress is a channel for receiving progress updates
	Progress chan<- jsonmessage.JSONMessage

	// Username for registry authentication
	Username string

	// Password for registry authentication
	Password string

	// ProgressOutput is a writer where progress is written
	ProgressOutput io.Writer

	// Quiet suppresses verbose output
	Quiet bool

	// ForcePull pulls even if the image exists locally
	ForcePull bool

	// RetryCount is the number of retry attempts
	RetryCount int

	// RetryDelay is the delay between retry attempts
	RetryDelay time.Duration
}

// NewPullManager creates a new pull manager
func NewPullManager(client client.APIClient, credentials registry.CredentialStore, logger *logrus.Logger) *PullManager {
	if logger == nil {
		logger = logrus.New()
	}

	return &PullManager{
		client:       client,
		logger:       logger,
		credentials:  credentials,
		pullTimeout:  5 * time.Minute,
		defaultRetry: 3,
	}
}

// Pull pulls an image from a registry
func (m *PullManager) Pull(ctx context.Context, refStr string, options image.PullOptions) (io.ReadCloser, error) {
	// Validate reference
	if refStr == "" {
		return nil, ErrInvalidImageReference
	}

	// Log pull attempt
	m.logger.WithFields(logrus.Fields{
		"image":    refStr,
		"all":      options.All,
		"platform": options.Platform,
	}).Info("Pulling Docker image")

	// Create context with timeout
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, m.pullTimeout)
		defer cancel()
	}

	// Parse image reference to extract registry for auth
	namedRef, err := reference.ParseNormalizedNamed(refStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidImageReference, err)
	}

	// Get auth configuration
	var encodedAuth string
	if options.RegistryAuth != "" {
		// Use provided auth
		encodedAuth = options.RegistryAuth
	} else if m.credentials != nil {
		// Try to get auth from credential store
		registryDomain := reference.Domain(namedRef)
		// Use GetAuthConfig which returns the correct type
		authConfig, err := m.credentials.GetAuthConfig(ctx, registryDomain, "") // Pass context and empty user
		if err == nil && (authConfig.Username != "" || authConfig.IdentityToken != "" || authConfig.RegistryToken != "") {
			// Encode the retrieved auth config (authConfig is already defined and of the correct type)
			encodedAuth, err = encodeAuthToBase64(authConfig) // Pass the retrieved authConfig
			if err != nil {
				m.logger.WithError(err).Warning("Failed to encode auth credentials")
			}
		}
	}

	// Prepare pull options
	pullOpts := imagetypes.PullOptions{ // Use imagetypes.PullOptions
		All:           options.All,
		RegistryAuth:  encodedAuth,
		Platform:      options.Platform,
		PrivilegeFunc: nil, // We don't support privilege escalation for auth
	}

	// Perform the pull operation
	responseBody, err := m.client.ImagePull(ctx, refStr, pullOpts)
	if err != nil {
		// Check for specific error types
		if strings.Contains(err.Error(), "authentication required") {
			return nil, fmt.Errorf("%w: authentication required for %s", ErrRegistryAuth, reference.Domain(namedRef)) // Use reference.Domain(namedRef)
		}

		// Check if operation was cancelled
		if ctx.Err() == context.Canceled {
			return nil, ErrPullCancelled
		} else if ctx.Err() == context.DeadlineExceeded {
			return nil, ErrPullTimeout
		}

		return nil, fmt.Errorf("%w: %v", ErrImagePull, err)
	}

	// If progress output is set, decode JSON messages
	if options.ProgressOutput != nil {
		// Create a pipe to connect the response to the progress output
		pr, pw := io.Pipe()

		go func() {
			defer pw.Close()
			defer responseBody.Close()

			// Forward and decode JSON messages
			err := jsonmessage.DisplayJSONMessagesStream(responseBody, pw, 0, !options.Quiet, nil)
			if err != nil && err != io.EOF {
				m.logger.WithError(err).Warning("Error processing image pull progress")
			}
		}()

		// Return the read end of the pipe
		return pr, nil
	}

	return responseBody, nil
}

// PullAndWait pulls an image and waits for completion
func (m *PullManager) PullAndWait(ctx context.Context, refStr string, options image.PullOptions) error {
	// Pull the image
	responseBody, err := m.Pull(ctx, refStr, options)
	if err != nil {
		return err
	}
	defer responseBody.Close()

	// Read the whole response body to wait for completion
	_, err = io.Copy(io.Discard, responseBody)
	if err != nil && err != io.EOF {
		return fmt.Errorf("error processing pull response: %w", err)
	}

	return nil
}

// encodeAuthToBase64 serializes and encodes auth configuration to base64
func encodeAuthToBase64(authConfig registrytypes.AuthConfig) (string, error) { // Use registrytypes.AuthConfig
	jsonBytes, err := json.Marshal(authConfig)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(jsonBytes), nil
}

// CheckAndPull checks if an image exists locally, and pulls it if not
func (m *PullManager) CheckAndPull(ctx context.Context, refStr string, options image.PullOptions) (bool, error) {
	// Check if we should force pull
	forcePull := false
	if v, ok := ctx.Value("force_pull").(bool); ok {
		forcePull = v
	}

	// Check if image exists locally
	inspector := image.NewInspector(m.client, m.logger)
	exists, err := inspector.ImageExists(ctx, refStr)
	if err != nil {
		return false, err
	}

	// If image exists and we're not forcing pull, return
	if exists && !forcePull {
		m.logger.WithField("image", refStr).Debug("Image already exists locally")
		return false, nil
	}

	// Pull the image
	err = m.PullAndWait(ctx, refStr, options)
	if err != nil {
		return false, err
	}

	return true, nil
}

// SetPullTimeout sets the timeout for pull operations
func (m *PullManager) SetPullTimeout(timeout time.Duration) {
	if timeout > 0 {
		m.pullTimeout = timeout
	}
}

// SetDefaultRetry sets the default retry count for pull operations
func (m *PullManager) SetDefaultRetry(count int) {
	if count >= 0 {
		m.defaultRetry = count
	}
}
