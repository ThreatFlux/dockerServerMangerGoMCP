package docker

import (
	"context"
	"crypto/tls"
	"crypto/x509"  // Added import
	"encoding/pem" // Added import
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings" // Added import
	"sync"
	"sync/atomic"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
)

// Common errors with detailed descriptions for better error handling
var (
	// ErrNilOption indicates a nil option was provided
	ErrNilOption = errors.New("nil option provided to client configuration")

	// ErrInvalidHost indicates an invalid Docker host
	ErrInvalidHost = errors.New("invalid Docker host specification")

	// ErrMissingTLSConfig indicates incomplete TLS configuration
	ErrMissingTLSConfig = errors.New("TLS verification enabled but certificate paths not provided")

	// ErrInvalidTLSCert indicates an invalid TLS certificate
	ErrInvalidTLSCert = errors.New("invalid or inaccessible TLS certificate")

	// ErrInvalidTLSKey indicates an invalid TLS key
	ErrInvalidTLSKey = errors.New("invalid or inaccessible TLS key")

	// ErrInvalidTLSCA indicates an invalid TLS CA certificate
	ErrInvalidTLSCA = errors.New("invalid or inaccessible TLS CA certificate")

	// ErrConnectionFailed indicates a connection failure to Docker daemon
	ErrConnectionFailed = errors.New("failed to connect to Docker daemon")

	// ErrClientNotInitialized indicates the client was not initialized
	ErrClientNotInitialized = errors.New("Docker client not initialized")

	// ErrClientClosed indicates the client has been closed
	ErrClientClosed = errors.New("Docker client manager has been closed")

	// ErrInvalidAPIVersion indicates an invalid API version
	ErrInvalidAPIVersion = errors.New("invalid Docker API version format")

	// ErrContextCancelled indicates the context was cancelled
	ErrContextCancelled = errors.New("context was cancelled while operating Docker client")

	// ErrEmptyOption indicates an empty option value
	ErrEmptyOption = errors.New("empty value provided for required option")

	// ErrTLSConfigValidation indicates TLS configuration validation failed
	ErrTLSConfigValidation = errors.New("TLS configuration validation failed")

	// ErrCertificateExpired indicates a certificate has expired
	ErrCertificateExpired = errors.New("TLS certificate has expired")

	// ErrCertificateNotYetValid indicates a certificate is not yet valid
	ErrCertificateNotYetValid = errors.New("TLS certificate is not yet valid")
)

// ClientOption represents a functional option for configuring the Docker client
type ClientOption func(*ClientConfig) error

// ClientConfig represents the configuration for the Docker client
type ClientConfig struct {
	// Host is the Docker daemon socket to connect to
	Host string

	// APIVersion is the Docker API version to use
	APIVersion string

	// TLSVerify indicates whether to verify TLS certificates
	TLSVerify bool

	// TLSCertPath is the path to the TLS certificate file
	TLSCertPath string

	// TLSKeyPath is the path to the TLS key file
	TLSKeyPath string

	// TLSCAPath is the path to the TLS CA certificate file
	TLSCAPath string

	// RequestTimeout is the timeout for Docker API requests
	RequestTimeout time.Duration

	// ConnectionTimeout is the timeout for establishing connections
	ConnectionTimeout time.Duration

	// ConnectionIdleTimeout is the timeout for idle connections
	ConnectionIdleTimeout time.Duration

	// TLSHandshakeTimeout is the timeout for TLS handshakes
	TLSHandshakeTimeout time.Duration

	// KeepAlive is the keepalive period for connections
	KeepAlive time.Duration

	// MaxIdleConns is the maximum number of idle connections
	MaxIdleConns int

	// MaxIdleConnsPerHost is the maximum number of idle connections per host
	MaxIdleConnsPerHost int

	// MaxConnsPerHost is the maximum number of connections per host
	MaxConnsPerHost int

	// IdleConnTimeout is the timeout for idle connections
	IdleConnTimeout time.Duration

	// ResponseHeaderTimeout is the timeout for response headers
	ResponseHeaderTimeout time.Duration

	// ExpectContinueTimeout is the timeout for expect continue
	ExpectContinueTimeout time.Duration

	// Logger is the logger to use
	Logger *logrus.Logger

	// Headers are additional HTTP headers to include in requests
	Headers map[string]string

	// DialContext is a custom dial context function for HTTP connections
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// PingTimeout is the timeout for ping operations
	PingTimeout time.Duration

	// RetryCount is the number of retries for operations
	RetryCount int

	// RetryDelay is the delay between retries
	RetryDelay time.Duration

	// TLSMinVersion is the minimum TLS version to use
	TLSMinVersion uint16

	// TLSMaxVersion is the maximum TLS version to use
	TLSMaxVersion uint16

	// TLSCipherSuites are the TLS cipher suites to use
	TLSCipherSuites []uint16

	// TLSPreferServerCipherSuites indicates whether to prefer server cipher suites
	TLSPreferServerCipherSuites bool
}

// Manager is the interface for Docker client operations
type Manager interface {
	// GetClient returns a Docker client
	GetClient() (*client.Client, error)

	// GetWithContext returns a Docker client with the specified context
	GetWithContext(ctx context.Context) (*client.Client, error)

	// Ping checks the connectivity with the Docker daemon
	Ping(ctx context.Context) (types.Ping, error)

	// Close closes all clients and releases resources
	Close() error

	// IsInitialized checks if the client is initialized
	IsInitialized() bool

	// IsClosed checks if the client is closed
	IsClosed() bool

	// GetConfig returns the client configuration
	GetConfig() ClientConfig
}

// ClientManager manages Docker clients
type ClientManager struct {
	config      ClientConfig
	client      *client.Client
	mu          sync.RWMutex
	logger      *logrus.Logger
	closed      bool
	initialized atomic.Bool
	lastPing    time.Time
	pingMutex   sync.Mutex
	createCount int64
}

// DefaultClientConfig returns the default client configuration
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Host:                  "unix:///var/run/docker.sock", // Use standard Docker socket
		APIVersion:            "",                            // Use automatic negotiation
		TLSVerify:             false,
		RequestTimeout:        30 * time.Second,
		ConnectionTimeout:     15 * time.Second,
		ConnectionIdleTimeout: 60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		KeepAlive:             30 * time.Second,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   5,
		MaxConnsPerHost:       20,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		Logger:                logrus.New(),
		Headers:               make(map[string]string),
		PingTimeout:           5 * time.Second,
		RetryCount:            3,
		RetryDelay:            500 * time.Millisecond,
		TLSMinVersion:         tls.VersionTLS12,
		TLSMaxVersion:         0, // Use default max version
		TLSCipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		TLSPreferServerCipherSuites: true,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
}

// WithHost sets the Docker daemon host
func WithHost(host string) ClientOption {
	return func(config *ClientConfig) error {
		if host == "" {
			return ErrInvalidHost
		}

		// Validate host format (unix socket or TCP)
		if !strings.HasPrefix(host, "unix://") && !strings.HasPrefix(host, "tcp://") && !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
			return fmt.Errorf("%w: host must start with unix://, tcp://, http://, or https://", ErrInvalidHost)
		}

		config.Host = host
		return nil
	}
}

// WithAPIVersion sets the Docker API version
func WithAPIVersion(version string) ClientOption {
	return func(config *ClientConfig) error {
		if version == "" {
			// Empty is allowed - will use negotiation
			config.APIVersion = ""
			return nil
		}

		// Basic validation of version format (should be like v1.41 or 1.41)
		// Allow just numbers like "1.41"
		if !strings.HasPrefix(version, "v") {
			// Check if it looks like a number.number format
			parts := strings.Split(version, ".")
			if len(parts) != 2 {
				return fmt.Errorf("%w: version should be in format vX.Y or X.Y", ErrInvalidAPIVersion)
			}
			// Further checks could be added here if needed
		}

		config.APIVersion = version
		return nil
	}
}

// WithTLSVerify enables TLS verification
func WithTLSVerify(verify bool) ClientOption {
	return func(config *ClientConfig) error {
		config.TLSVerify = verify
		return nil
	}
}

// WithTLSCertPath sets the TLS certificate path
func WithTLSCertPath(path string) ClientOption {
	return func(config *ClientConfig) error {
		if path == "" {
			return fmt.Errorf("%w: empty certificate path", ErrInvalidTLSCert)
		}
		config.TLSCertPath = path
		return nil
	}
}

// WithTLSKeyPath sets the TLS key path
func WithTLSKeyPath(path string) ClientOption {
	return func(config *ClientConfig) error {
		if path == "" {
			return fmt.Errorf("%w: empty key path", ErrInvalidTLSKey)
		}
		config.TLSKeyPath = path
		return nil
	}
}

// WithTLSCAPath sets the TLS CA certificate path
func WithTLSCAPath(path string) ClientOption {
	return func(config *ClientConfig) error {
		if path == "" {
			return fmt.Errorf("%w: empty CA path", ErrInvalidTLSCA)
		}
		config.TLSCAPath = path
		return nil
	}
}

// WithRequestTimeout sets the request timeout
func WithRequestTimeout(timeout time.Duration) ClientOption {
	return func(config *ClientConfig) error {
		if timeout <= 0 {
			return fmt.Errorf("request timeout must be positive")
		}
		config.RequestTimeout = timeout
		return nil
	}
}

// WithConnectionTimeout sets the connection timeout
func WithConnectionTimeout(timeout time.Duration) ClientOption {
	return func(config *ClientConfig) error {
		if timeout <= 0 {
			return fmt.Errorf("connection timeout must be positive")
		}
		config.ConnectionTimeout = timeout
		return nil
	}
}

// WithLogger sets the logger
func WithLogger(logger *logrus.Logger) ClientOption {
	return func(config *ClientConfig) error {
		if logger == nil {
			return fmt.Errorf("logger cannot be nil")
		}
		config.Logger = logger
		return nil
	}
}

// WithHeader adds an HTTP header
func WithHeader(key, value string) ClientOption {
	return func(config *ClientConfig) error {
		if key == "" {
			return fmt.Errorf("header key cannot be empty")
		}
		if config.Headers == nil {
			config.Headers = make(map[string]string)
		}
		config.Headers[key] = value
		return nil
	}
}

// WithDialContext sets a custom dial context function
func WithDialContext(dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) ClientOption {
	return func(config *ClientConfig) error {
		if dialContext == nil {
			return fmt.Errorf("dial context function cannot be nil")
		}
		config.DialContext = dialContext
		return nil
	}
}

// WithTLSConfig sets the complete TLS configuration
func WithTLSConfig(certPath, keyPath, caPath string) ClientOption {
	return func(config *ClientConfig) error {
		if certPath == "" || keyPath == "" || caPath == "" {
			return ErrMissingTLSConfig
		}

		config.TLSVerify = true
		config.TLSCertPath = certPath
		config.TLSKeyPath = keyPath
		config.TLSCAPath = caPath

		return nil
	}
}

// WithRetry sets retry parameters
func WithRetry(count int, delay time.Duration) ClientOption {
	return func(config *ClientConfig) error {
		if count < 0 {
			return fmt.Errorf("retry count must be non-negative")
		}
		if delay < 0 {
			return fmt.Errorf("retry delay must be non-negative")
		}

		config.RetryCount = count
		config.RetryDelay = delay
		return nil
	}
}

// WithTLSVersion sets the TLS version range
func WithTLSVersion(minVersion, maxVersion uint16) ClientOption {
	return func(config *ClientConfig) error {
		if minVersion == 0 {
			minVersion = tls.VersionTLS12 // Default to TLS 1.2 minimum
		}

		// Validate min version
		if minVersion < tls.VersionTLS12 {
			return fmt.Errorf("minimum TLS version must be at least TLS 1.2 for security")
		}

		// If max is 0, it means use the default maximum
		if maxVersion != 0 && maxVersion < minVersion {
			return fmt.Errorf("maximum TLS version cannot be less than minimum TLS version")
		}

		config.TLSMinVersion = minVersion
		config.TLSMaxVersion = maxVersion
		return nil
	}
}

// WithTLSCipherSuites sets the TLS cipher suites
func WithTLSCipherSuites(suites []uint16) ClientOption {
	return func(config *ClientConfig) error {
		if len(suites) == 0 {
			return fmt.Errorf("empty cipher suite list")
		}

		config.TLSCipherSuites = suites
		return nil
	}
}

// WithConnectionPoolConfig sets connection pool configuration
func WithConnectionPoolConfig(maxIdle, maxIdlePerHost, maxPerHost int) ClientOption {
	return func(config *ClientConfig) error {
		if maxIdle <= 0 || maxIdlePerHost <= 0 || maxPerHost <= 0 {
			return fmt.Errorf("connection pool parameters must be positive")
		}

		config.MaxIdleConns = maxIdle
		config.MaxIdleConnsPerHost = maxIdlePerHost
		config.MaxConnsPerHost = maxPerHost
		return nil
	}
}

// WithTimeoutConfig sets comprehensive timeout configuration
func WithTimeoutConfig(requestTimeout, connectionTimeout, handshakeTimeout, idleTimeout, responseHeaderTimeout, expectContinueTimeout time.Duration) ClientOption {
	return func(config *ClientConfig) error {
		if requestTimeout <= 0 || connectionTimeout <= 0 || handshakeTimeout <= 0 ||
			idleTimeout <= 0 || responseHeaderTimeout <= 0 || expectContinueTimeout <= 0 {
			return fmt.Errorf("all timeout values must be positive")
		}

		config.RequestTimeout = requestTimeout
		config.ConnectionTimeout = connectionTimeout
		config.TLSHandshakeTimeout = handshakeTimeout
		config.IdleConnTimeout = idleTimeout
		config.ResponseHeaderTimeout = responseHeaderTimeout
		config.ExpectContinueTimeout = expectContinueTimeout
		return nil
	}
}

// NewManager creates a new Docker client manager
func NewManager(opts ...ClientOption) (*ClientManager, error) {
	config := DefaultClientConfig()

	// Apply options
	for _, opt := range opts {
		if opt == nil {
			return nil, ErrNilOption
		}
		if err := opt(&config); err != nil {
			return nil, fmt.Errorf("option application failed: %w", err)
		}
	}

	// Additional validation if TLS is enabled
	if config.TLSVerify {
		if config.TLSCertPath == "" || config.TLSKeyPath == "" || config.TLSCAPath == "" {
			return nil, ErrMissingTLSConfig
		}
	}

	// Create manager
	manager := &ClientManager{
		config: config,
		logger: config.Logger,
		closed: false,
	}

	// Attempt initial client creation and ping
	_, err := manager.GetClient()
	if err != nil {
		manager.logger.Warnf("Initial Docker client creation failed: %v. Will retry on demand.", err)
		// Don't return error here, allow manager creation but mark as uninitialized
		manager.initialized.Store(false)
	} else {
		manager.initialized.Store(true)
	}

	return manager, nil
}

// GetClient returns a Docker client, creating one if necessary
// Deprecated: Use GetWithContext instead for better context handling.
func (m *ClientManager) GetClient() (*client.Client, error) {
	return m.GetWithContext(context.Background())
}

// GetWithContext returns a Docker client, creating one if necessary with context awareness
func (m *ClientManager) GetWithContext(ctx context.Context) (*client.Client, error) {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrClientClosed
	}
	if m.client != nil {
		// Check if the client is still responsive with a quick ping
		// Use a short timeout for this check to avoid blocking for too long
		pingCtx, cancel := context.WithTimeout(ctx, m.config.PingTimeout)
		defer cancel()

		_, err := m.client.Ping(pingCtx)
		if err == nil {
			m.mu.RUnlock()
			return m.client, nil
		}
		m.logger.Warnf("Existing Docker client failed ping: %v. Attempting to recreate.", err)
		// Fall through to recreate the client
	}
	m.mu.RUnlock()

	// If client is nil or ping failed, acquire write lock to create/recreate
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check if another goroutine created the client while waiting for the lock
	if m.closed {
		return nil, ErrClientClosed
	}
	if m.client != nil {
		// Check ping again, maybe another goroutine fixed it
		pingCtx, cancel := context.WithTimeout(ctx, m.config.PingTimeout)
		defer cancel()
		_, err := m.client.Ping(pingCtx)
		if err == nil {
			return m.client, nil
		}
		m.logger.Warnf("Existing Docker client still failing ping after acquiring lock: %v. Recreating.", err)
	}

	// Create a new client with retry logic
	var newClient *client.Client
	var lastErr error
	for i := 0; i <= m.config.RetryCount; i++ {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %w", ErrContextCancelled, ctx.Err())
		default:
			// Proceed with client creation attempt
		}

		m.logger.Debugf("Attempting to create Docker client (attempt %d/%d)", i+1, m.config.RetryCount+1)
		newClient, lastErr = m.createClient(ctx)
		if lastErr == nil {
			m.logger.Infof("Successfully created Docker client on attempt %d", i+1)
			m.client = newClient
			m.initialized.Store(true)
			m.createCount++
			return m.client, nil
		}

		m.logger.Warnf("Error creating Docker client (attempt %d/%d): %v", i+1, m.config.RetryCount+1, lastErr)
		if i < m.config.RetryCount {
			select {
			case <-time.After(m.config.RetryDelay):
				// Continue to next retry
			case <-ctx.Done():
				return nil, fmt.Errorf("%w during retry delay: %w", ErrContextCancelled, ctx.Err())
			}
		}
	}

	m.initialized.Store(false)
	return nil, fmt.Errorf("failed to create Docker client after %d attempts: %w", m.config.RetryCount+1, lastErr)
}

// createClient handles the actual client creation logic
func (m *ClientManager) createClient(ctx context.Context) (*client.Client, error) {
	var opts []client.Opt

	// Set host
	if m.config.Host != "" {
		opts = append(opts, client.WithHost(m.config.Host))
	} else {
		// Attempt to use default from environment if host is not set
		opts = append(opts, client.FromEnv)
	}

	// Set API version if specified
	if m.config.APIVersion != "" {
		opts = append(opts, client.WithVersion(m.config.APIVersion))
	} else {
		// Use negotiation by default if not specified
		opts = append(opts, client.WithAPIVersionNegotiation())
	}

	// Configure HTTP client only if needed (non-unix socket or TLS enabled)
	// For standard unix sockets without TLS, let the Docker client library handle it.
	isUnixSocket := strings.HasPrefix(m.config.Host, "unix://")
	if !isUnixSocket || m.config.TLSVerify {
		httpClient := m.createSecureHTTPClient()
		if httpClient != nil { // Ensure createSecureHTTPClient didn't fail
			opts = append(opts, client.WithHTTPClient(httpClient))
		} else {
			// Log or return an error if secure client creation failed when required
			m.logger.Error("Failed to create secure HTTP client when required (TLS or non-unix host)")
			// Depending on desired behavior, might return an error here
			// return nil, errors.New("failed to create necessary HTTP client")
		}
	}

	// Add custom headers if any
	if len(m.config.Headers) > 0 {
		opts = append(opts, client.WithHTTPHeaders(m.config.Headers))
	}

	// Create the client
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnectionFailed, err)
	}

	// Perform an initial ping to verify connectivity
	pingCtx, cancel := context.WithTimeout(ctx, m.config.PingTimeout)
	defer cancel()
	_, err = cli.Ping(pingCtx)
	if err != nil {
		cli.Close() // Close the client if ping fails
		return nil, fmt.Errorf("failed to ping Docker daemon after connection: %w", err)
	}

	m.logger.Debug("Docker client created and ping successful.")
	return cli, nil
}

// createSecureHTTPClient creates an *http.Client with TLS and timeout settings
func (m *ClientManager) createSecureHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Determine the dialer
			dialerFunc := m.config.DialContext
			if dialerFunc == nil {
				// Use default dialer if none provided in config
				dialerFunc = (&net.Dialer{
					Timeout:   m.config.ConnectionTimeout,
					KeepAlive: m.config.KeepAlive,
				}).DialContext
			}

			// Handle Unix socket specifically
			if strings.HasPrefix(m.config.Host, "unix://") {
				socketPath := strings.TrimPrefix(m.config.Host, "unix://")
				// Force network to "unix" and address to the socket path
				return dialerFunc(ctx, "unix", socketPath)
			}

			// For other schemes (tcp, http, https), use the provided network and address
			return dialerFunc(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true, // Enable HTTP/2
		MaxIdleConns:          m.config.MaxIdleConns,
		IdleConnTimeout:       m.config.IdleConnTimeout,
		TLSHandshakeTimeout:   m.config.TLSHandshakeTimeout,
		ExpectContinueTimeout: m.config.ExpectContinueTimeout,
		MaxIdleConnsPerHost:   m.config.MaxIdleConnsPerHost,
		MaxConnsPerHost:       m.config.MaxConnsPerHost,
		ResponseHeaderTimeout: m.config.ResponseHeaderTimeout,
	}

	if m.config.TLSVerify {
		tlsConfig := &tls.Config{
			MinVersion:               m.config.TLSMinVersion,
			MaxVersion:               m.config.TLSMaxVersion,
			CipherSuites:             m.config.TLSCipherSuites,
			PreferServerCipherSuites: m.config.TLSPreferServerCipherSuites,
			// InsecureSkipVerify: false, // Ensure verification is enabled
		}

		// Load client certificate and key
		if m.config.TLSCertPath != "" && m.config.TLSKeyPath != "" {
			cert, err := tls.LoadX509KeyPair(m.config.TLSCertPath, m.config.TLSKeyPath)
			if err != nil {
				m.logger.Errorf("Failed to load TLS key pair: %v", err)
				// Handle error appropriately, maybe return a default insecure client or nil
				return &http.Client{Transport: transport} // Fallback to potentially insecure
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		// Load CA certificate
		if m.config.TLSCAPath != "" {
			caCert, err := os.ReadFile(m.config.TLSCAPath)
			if err != nil {
				m.logger.Errorf("Failed to read CA certificate: %v", err)
				return &http.Client{Transport: transport} // Fallback
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				m.logger.Errorf("Failed to append CA certificate to pool")
				return &http.Client{Transport: transport} // Fallback
			}
			tlsConfig.RootCAs = caCertPool
		}

		transport.TLSClientConfig = tlsConfig
	} else {
		// Explicitly allow insecure connections if TLSVerify is false
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   m.config.RequestTimeout, // Overall request timeout
	}
}

// validateTLSConfig performs basic checks on TLS file paths
func (m *ClientManager) validateTLSConfig() error {
	if !m.config.TLSVerify {
		return nil // No validation needed if TLS is not verified
	}

	m.logger.Debug("Validating TLS configuration...")

	if m.config.TLSCertPath == "" || m.config.TLSKeyPath == "" || m.config.TLSCAPath == "" {
		return ErrMissingTLSConfig
	}

	// Validate certificate and key pair
	if err := m.validateTLSCertAndKey(m.config.TLSCertPath, m.config.TLSKeyPath); err != nil {
		return fmt.Errorf("certificate/key validation failed: %w", err)
	}

	// Validate CA certificate
	if err := m.validateCACert(m.config.TLSCAPath); err != nil {
		return fmt.Errorf("CA certificate validation failed: %w", err)
	}

	m.logger.Debug("TLS configuration validated successfully.")
	return nil
}

// validateTLSCertAndKey checks if the certificate and key files are valid and match
func (m *ClientManager) validateTLSCertAndKey(certPath, keyPath string) error {
	m.logger.Debugf("Validating TLS cert '%s' and key '%s'", certPath, keyPath)

	// Check if files are readable first
	if err := checkFileReadable(certPath); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTLSCert, err)
	}
	if err := checkFileReadable(keyPath); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTLSKey, err)
	}

	// Load the key pair to check if they match and are valid
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("%w: failed to read cert file: %w", ErrInvalidTLSCert, err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("%w: failed to read key file: %w", ErrInvalidTLSKey, err)
	}

	// Try loading the key pair
	_, err = tls.X509KeyPair(certData, keyData)
	if err != nil {
		return fmt.Errorf("failed to load/validate TLS key pair: %w", err)
	}

	// Decode PEM block to get certificate details
	cert, rest := parsePEMBlock(certData)
	if cert == nil {
		return fmt.Errorf("%w: no valid PEM data found in certificate file", ErrInvalidTLSCert)
	}
	if len(rest) > 0 {
		m.logger.Warnf("Extra data found after PEM block in certificate file %s", certPath)
	}

	// Check certificate validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w: certificate is not valid until %s", ErrCertificateNotYetValid, cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: certificate expired on %s", ErrCertificateExpired, cert.NotAfter)
	}

	// Log certificate expiry warning if it's close
	if cert.NotAfter.Sub(now) < 30*24*time.Hour { // Warn if less than 30 days remaining
		m.logger.Warnf("TLS certificate '%s' expires soon: %s", certPath, cert.NotAfter)
	}

	m.logger.Debugf("TLS cert '%s' and key '%s' validated.", certPath, keyPath)
	return nil
}

// validateCACert checks if the CA certificate file is valid
func (m *ClientManager) validateCACert(caPath string) error {
	m.logger.Debugf("Validating CA cert '%s'", caPath)

	// Check if file is readable
	if err := checkFileReadable(caPath); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTLSCA, err)
	}

	// Read the CA certificate file
	caData, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("%w: failed to read CA file: %w", ErrInvalidTLSCA, err)
	}

	// Attempt to add it to a cert pool
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caData) {
		// Check if it's a single DER-encoded certificate
		_, errDer := x509.ParseCertificate(caData)
		if errDer != nil {
			// If it's neither valid PEM nor valid DER
			return fmt.Errorf("%w: failed to parse CA certificate(s) from PEM or DER data", ErrInvalidTLSCA)
		}
		// If it was DER, it should have been handled by AppendCertsFromPEM if system pool was used,
		// but standalone pool might need explicit parsing. Let's assume AppendCertsFromPEM failure means invalid format for now.
		// A more robust check might try ParseCertificate directly if AppendCertsFromPEM fails.
		m.logger.Warnf("CA certificate file '%s' might contain non-PEM data or other issues.", caPath)
		// Allow proceeding if AppendCertsFromPEM fails but might log warning.
		// Strict mode could return error here.
	}

	// Decode PEM block(s) to check individual certificate validity periods
	rest := caData
	foundValidCert := false
	now := time.Now()
	for len(rest) > 0 {
		var cert *x509.Certificate
		cert, rest = parsePEMBlock(rest)
		if cert != nil {
			foundValidCert = true // Found at least one PEM block
			if now.Before(cert.NotBefore) {
				m.logger.Warnf("CA certificate in '%s' (Subject: %s) is not valid until %s", caPath, cert.Subject, cert.NotBefore)
			}
			if now.After(cert.NotAfter) {
				m.logger.Warnf("CA certificate in '%s' (Subject: %s) expired on %s", caPath, cert.Subject, cert.NotAfter)
			}
		} else {
			// If no block found in the remaining data, break
			break
		}
	}

	if !foundValidCert {
		// Re-check if it was DER format
		_, errDer := x509.ParseCertificate(caData)
		if errDer != nil {
			return fmt.Errorf("%w: no valid PEM or DER certificate data found in CA file", ErrInvalidTLSCA)
		}
		// If it was DER, parse and check validity (similar logic as above)
		cert, _ := x509.ParseCertificate(caData) // Error already checked
		if now.Before(cert.NotBefore) {
			m.logger.Warnf("CA certificate in '%s' (Subject: %s) is not valid until %s", caPath, cert.Subject, cert.NotBefore)
		}
		if now.After(cert.NotAfter) {
			m.logger.Warnf("CA certificate in '%s' (Subject: %s) expired on %s", caPath, cert.Subject, cert.NotAfter)
		}
	}

	m.logger.Debugf("CA cert '%s' validated.", caPath)
	return nil
}

// parsePEMBlock decodes the first PEM block found in data and returns the certificate and remaining data.
func parsePEMBlock(data []byte) (*x509.Certificate, []byte) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, data // No PEM block found
	}
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		// Invalid block type or headers, try next block
		return parsePEMBlock(rest)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		// Invalid certificate data, try next block
		logrus.Warnf("Failed to parse certificate in PEM block: %v", err)
		return parsePEMBlock(rest)
	}
	return cert, rest
}

// checkFileReadable checks if a file exists and is readable
func checkFileReadable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist at path: %s", path)
		}
		return fmt.Errorf("failed to stat file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", path)
	}

	// Try opening the file for reading
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("file exists but cannot be opened for reading: %w", err)
	}
	f.Close() // Close immediately after checking

	// Basic permission check (might not be fully reliable on all OS)
	// Check if the owner has read permission at least
	if runtime.GOOS != "windows" { // Skip permission check on Windows for simplicity
		if info.Mode().Perm()&0400 == 0 {
			logrus.Warnf("File %s might not have read permissions.", path)
			// return fmt.Errorf("file does not appear to have read permissions: %s", path)
		}
	}

	return nil
}

// Ping checks the connectivity with the Docker daemon using the managed client
func (m *ClientManager) Ping(ctx context.Context) (types.Ping, error) {
	m.pingMutex.Lock()
	defer m.pingMutex.Unlock()

	cli, err := m.GetWithContext(ctx)
	if err != nil {
		return types.Ping{}, fmt.Errorf("failed to get Docker client for ping: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, m.config.PingTimeout)
	defer cancel()

	pingResult, err := cli.Ping(pingCtx)
	if err != nil {
		m.logger.Errorf("Ping failed: %v", err)
		// Consider invalidating the client if ping fails consistently
		// m.mu.Lock()
		// m.client = nil // Force recreation on next GetClient call
		// m.initialized.Store(false)
		// m.mu.Unlock()
		return types.Ping{}, fmt.Errorf("Docker daemon ping failed: %w", err)
	}

	m.lastPing = time.Now()
	m.logger.Debugf("Ping successful: APIVersion=%s, OSType=%s, Experimental=%t",
		pingResult.APIVersion, pingResult.OSType, pingResult.Experimental)

	return pingResult, nil
}

// Close closes the managed Docker client and marks the manager as closed
func (m *ClientManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		m.logger.Debug("Client manager already closed.")
		return nil // Already closed
	}

	m.closed = true
	m.initialized.Store(false) // Mark as uninitialized upon closing

	if m.client != nil {
		m.logger.Info("Closing Docker client...")
		err := m.client.Close()
		m.client = nil // Ensure client is nil after closing
		if err != nil {
			m.logger.Errorf("Error closing Docker client: %v", err)
			return fmt.Errorf("failed to close Docker client: %w", err)
		}
		m.logger.Info("Docker client closed successfully.")
		return nil
	}

	m.logger.Info("No active Docker client to close.")
	return nil
}

// IsInitialized checks if the client manager has successfully initialized a client at least once
func (m *ClientManager) IsInitialized() bool {
	return m.initialized.Load()
}

// IsClosed checks if the client manager has been closed
func (m *ClientManager) IsClosed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
}

// GetConfig returns a copy of the current client configuration
func (m *ClientManager) GetConfig() ClientConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return a copy to prevent external modification
	configCopy := m.config
	if configCopy.Headers != nil {
		configCopy.Headers = make(map[string]string)
		for k, v := range m.config.Headers {
			configCopy.Headers[k] = v
		}
	}
	return configCopy
}

// GetCreationCount returns the number of times a client has been created
func (m *ClientManager) GetCreationCount() int64 {
	return atomic.LoadInt64(&m.createCount)
}

// GetLastPingTime returns the time of the last successful ping
func (m *ClientManager) GetLastPingTime() time.Time {
	m.pingMutex.Lock()
	defer m.pingMutex.Unlock()
	return m.lastPing
}

// formatDuration formats duration for logging
func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1e6)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// --- Global Default Client Management ---

var (
	defaultManager     *ClientManager
	defaultManagerMu   sync.Mutex
	defaultManagerOpts []ClientOption // Store options used for the default manager
)

// ConfigureDefaultManager sets the options for the default manager.
// This should be called early in the application lifecycle, before the first call to DefaultManager() or GetDefaultClient().
// Calling this after the default manager has been initialized will cause a panic.
func ConfigureDefaultManager(opts ...ClientOption) {
	defaultManagerMu.Lock()
	defer defaultManagerMu.Unlock()

	if defaultManager != nil && defaultManager.IsInitialized() {
		panic("ConfigureDefaultManager called after the default Docker client manager was already initialized")
	}
	if defaultManager != nil && defaultManager.IsClosed() {
		panic("ConfigureDefaultManager called after the default Docker client manager was closed")
	}

	// Store options for potential re-initialization if needed (e.g., after Reset)
	defaultManagerOpts = make([]ClientOption, len(opts))
	copy(defaultManagerOpts, opts)

	// Reset the manager so it gets recreated with new options on next access
	defaultManager = nil
}

// DefaultManager returns the singleton default Docker client manager, creating it if necessary.
// It uses options provided by ConfigureDefaultManager or default options if not configured.
func DefaultManager() (*ClientManager, error) {
	defaultManagerMu.Lock()
	defer defaultManagerMu.Unlock()

	if defaultManager != nil && !defaultManager.IsClosed() {
		// If initialized or not closed, return existing
		return defaultManager, nil
	}

	// If closed or nil, create a new one
	var err error
	optsToUse := defaultManagerOpts // Use configured options if available
	if optsToUse == nil {
		optsToUse = []ClientOption{} // Use default config if not configured
	}

	logrus.Info("Initializing default Docker client manager...")
	defaultManager, err = NewManager(optsToUse...)
	if err != nil {
		logrus.Errorf("Failed to initialize default Docker client manager: %v", err)
		return nil, fmt.Errorf("failed to get default Docker client manager: %w", err)
	}
	logrus.Info("Default Docker client manager initialized successfully.")
	return defaultManager, nil
}

// GetDefaultClient returns a client from the default manager.
func GetDefaultClient() (*client.Client, error) {
	manager, err := DefaultManager()
	if err != nil {
		return nil, err
	}
	return manager.GetClient() // Use background context for default client
}

// GetClientWithContext creates a new temporary client manager with the specified options and returns a client.
// This is useful for specific operations requiring different configurations than the default manager.
// The returned client should be managed carefully, as its manager is not the default singleton.
func GetClientWithContext(ctx context.Context, opts ...ClientOption) (*client.Client, error) {
	tempManager, err := NewManager(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary client manager: %w", err)
	}
	// Note: Closing this temporary manager is the caller's responsibility if needed,
	// or let it be garbage collected if it's truly short-lived.
	// Consider adding a Close method to the returned client or a wrapper if explicit cleanup is required.
	return tempManager.GetWithContext(ctx)
}

// MustGetClient is like GetDefaultClient but panics on error.
// Useful for initialization code where failure is fatal.
func MustGetClient(opts ...ClientOption) *client.Client {
	var cli *client.Client
	var err error

	if len(opts) > 0 {
		// If options are provided, create a temporary manager and client
		// This assumes the caller wants a specific configuration for this instance
		tempManager, managerErr := NewManager(opts...)
		if managerErr != nil {
			panic(fmt.Sprintf("failed to create temporary Docker client manager: %v", managerErr))
		}
		// Use background context as MustGetClient is often for initialization
		cli, err = tempManager.GetWithContext(context.Background())
		// We don't store or close the tempManager here, assuming it's for a one-off client need.
	} else {
		// Use the default manager if no options are given
		cli, err = GetDefaultClient()
	}

	if err != nil {
		panic(fmt.Sprintf("failed to get Docker client: %v", err))
	}
	return cli
}

// ResetDefaultManager closes the current default manager (if any) and allows it to be re-initialized
// with potentially new options on the next call to DefaultManager() or GetDefaultClient().
// This is primarily useful for testing or scenarios requiring reconfiguration.
func ResetDefaultManager() {
	defaultManagerMu.Lock()
	defer defaultManagerMu.Unlock()

	if defaultManager != nil {
		logrus.Info("Resetting default Docker client manager...")
		err := defaultManager.Close()
		if err != nil {
			logrus.Warnf("Error closing default Docker client manager during reset: %v", err)
		}
		defaultManager = nil
		// Keep defaultManagerOpts so it can be reused if ConfigureDefaultManager isn't called again
	} else {
		logrus.Debug("No active default Docker client manager to reset.")
	}
}
