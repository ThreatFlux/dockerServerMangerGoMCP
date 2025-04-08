package exec

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container" // Added import alias
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/sirupsen/logrus"
)

// StartOptions defines options for starting an exec instance
type StartOptions struct {
	Timeout    time.Duration
	Input      io.Reader
	RawOutput  bool
	DetachKeys string
	Logger     *logrus.Logger
	// Fields from ExecConfig needed for start/attach logic
	AttachStdin  bool
	AttachStdout bool
	AttachStderr bool
	Tty          bool
}

// OutputWriter defines an interface for writing to stdout and stderr
type OutputWriter interface {
	Write(p []byte) (n int, err error)
	WriteErr(p []byte) (n int, err error)
	Close() error
}

// StdWriter is a basic implementation of OutputWriter that writes to io.Writers
type StdWriter struct {
	stdout io.Writer
	stderr io.Writer
}

// Write writes to stdout
func (w *StdWriter) Write(p []byte) (int, error) {
	return w.stdout.Write(p)
}

// WriteErr writes to stderr
func (w *StdWriter) WriteErr(p []byte) (int, error) {
	return w.stderr.Write(p)
}

// Close is a no-op for StdWriter
func (w *StdWriter) Close() error {
	return nil
}

// execReadCloser wraps the bufio.Reader and the HijackedResponse to implement io.ReadCloser
type execReadCloser struct {
	*bufio.Reader
	types.HijackedResponse
}

// Close closes the underlying connection.
func (erc *execReadCloser) Close() error {
	return erc.HijackedResponse.Conn.Close()
}

// Start starts an exec instance and returns an io.ReadCloser for the output stream
func Start(ctx context.Context, client client.APIClient, execID string, options StartOptions) (io.ReadCloser, error) {
	if execID == "" {
		return nil, fmt.Errorf("empty exec ID")
	}
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
	}
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Inspect exec instance to ensure it exists and gets its config
	execInspect, err := client.ContainerExecInspect(ctx, execID)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrExecNotFound, execID)
		}
		return nil, fmt.Errorf("failed to inspect exec instance: %w", err)
	}

	if execInspect.Running {
		logger.WithFields(logrus.Fields{"exec_id": execID}).Warn("Exec instance is already running")
	}

	// Determine if we need to attach based on options passed from create config
	hasStdio := options.AttachStdin || options.AttachStdout || options.AttachStderr

	// Create exec start config using options
	startConfig := containertypes.ExecStartOptions{ // Use containertypes.ExecStartOptions
		Detach: !hasStdio,
		Tty:    options.Tty,
	}

	// Handle attach if needed
	if hasStdio {
		resp, err := client.ContainerExecAttach(ctx, execID, startConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to attach to exec instance: %w", err)
		}

		err = client.ContainerExecStart(ctx, execID, startConfig)
		if err != nil {
			resp.Close()
			return nil, fmt.Errorf("failed to start exec instance: %w", err)
		}

		// Handle stdin if attached
		if options.Input != nil && options.AttachStdin { // Use options field
			go func() {
				defer resp.CloseWrite()
				_, copyErr := io.Copy(resp.Conn, options.Input)
				if copyErr != nil {
					logger.WithError(copyErr).WithField("exec_id", execID).Warn("Error copying stdin to exec")
				}
				logger.WithField("exec_id", execID).Debug("Finished copying stdin")
			}()
		}

		logger.WithFields(logrus.Fields{"exec_id": execID}).Debug("Started exec instance with stdio attachment")
		return &execReadCloser{Reader: resp.Reader, HijackedResponse: resp}, nil
	}

	// For detached mode, just start the exec instance
	err = client.ContainerExecStart(ctx, execID, startConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to start exec instance in detached mode: %w", err)
	}
	logger.WithFields(logrus.Fields{"exec_id": execID}).Debug("Started exec instance in detached mode")
	return io.NopCloser(bytes.NewReader(nil)), nil
}

// StartAndWait starts an exec instance and waits for it to complete
func StartAndWait(ctx context.Context, client client.APIClient, execID string, options StartOptions) (int, []byte, []byte, error) {
	reader, err := Start(ctx, client, execID, options)
	if err != nil {
		return -1, nil, nil, err
	}
	if reader != nil {
		defer reader.Close()
	}

	var stdout, stderr bytes.Buffer
	var waitErr error

	if rc, ok := reader.(*execReadCloser); ok && rc != nil {
		if options.RawOutput {
			_, waitErr = io.Copy(&stdout, rc)
		} else {
			_, waitErr = stdcopy.StdCopy(&stdout, &stderr, rc)
		}
		if waitErr != nil && !errors.Is(waitErr, io.EOF) && !errors.Is(waitErr, net.ErrClosed) {
			return -1, stdout.Bytes(), stderr.Bytes(), fmt.Errorf("error reading exec output: %w", waitErr)
		}
	} else if reader != nil {
		_, readErr := io.Copy(io.Discard, reader)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			logrus.WithError(readErr).Warn("Unexpected error reading from NopCloser in StartAndWait")
		}
	}

	exitCode, err := waitForExit(ctx, client, execID, options.Timeout)
	if err != nil {
		return -1, stdout.Bytes(), stderr.Bytes(), fmt.Errorf("error waiting for exec to complete: %w", err)
	}

	return exitCode, stdout.Bytes(), stderr.Bytes(), nil
}

// StartWithStdCopy starts an exec instance and copies its output to the provided writers
func StartWithStdCopy(ctx context.Context, client client.APIClient, execID string, options StartOptions, output OutputWriter) error {
	reader, err := Start(ctx, client, execID, options)
	if err != nil {
		return err
	}
	if reader == nil {
		return nil
	}
	defer reader.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	var copyErr error

	go func() {
		defer wg.Done()
		if options.RawOutput {
			_, copyErr = io.Copy(output, reader)
		} else {
			_, copyErr = customStdCopy(output, reader)
		}
	}()

	wg.Wait()

	if copyErr != nil && !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, net.ErrClosed) {
		return fmt.Errorf("error copying exec output: %w", copyErr)
	}
	return nil
}

// waitForExit waits for an exec instance to exit and returns its exit code
func waitForExit(ctx context.Context, client client.APIClient, execID string, timeout time.Duration) (int, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-ticker.C:
			inspect, err := client.ContainerExecInspect(ctx, execID)
			if err != nil {
				if errdefs.IsNotFound(err) { // Use errdefs.IsNotFound
					return -1, fmt.Errorf("%w: %s", ErrExecNotFound, execID)
				}
				return -1, fmt.Errorf("failed to inspect exec instance while waiting: %w", err)
			}
			if !inspect.Running {
				return inspect.ExitCode, nil
			}
		}
	}
}

// customStdCopy is a simplified version of stdcopy.StdCopy
// that uses our OutputWriter interface
func customStdCopy(output OutputWriter, src io.Reader) (written int64, err error) {
	hdr := make([]byte, 8)
	for {
		n, err := io.ReadFull(src, hdr)
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			return written, nil
		}
		if err != nil {
			return written, err
		}
		if n < 8 {
			return written, fmt.Errorf("short header read: %d bytes", n)
		}

		frameSize := int64(hdr[4])<<24 | int64(hdr[5])<<16 | int64(hdr[6])<<8 | int64(hdr[7])
		var dst io.Writer
		switch hdr[0] {
		case 1: // stdout
			dst = output
		case 2: // stderr
			dst = &stderrWrapper{output}
		default: // stdin or system stream (discard)
			dst = io.Discard
		}

		nr, err := io.CopyN(dst, src, frameSize)
		written += nr
		if err != nil {
			return written, err
		}
	}
}

// stderrWrapper wraps OutputWriter to redirect Write calls to WriteErr
type stderrWrapper struct {
	OutputWriter
}

func (w *stderrWrapper) Write(p []byte) (int, error) {
	return w.OutputWriter.WriteErr(p)
}
