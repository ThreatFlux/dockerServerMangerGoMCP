package utils

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Throttle provides a mechanism to limit the rate of operations
type Throttle struct {
	limit      int           // Maximum number of operations per interval
	interval   time.Duration // Time interval for the rate limit
	mu         sync.Mutex    // Mutex for thread safety
	tokens     int           // Current number of available tokens
	lastRefill time.Time     // Time of the last token refill
}

var (
	// ErrThrottleContextCanceled indicates the context was canceled while waiting
	ErrThrottleContextCanceled = errors.New("context canceled while waiting for throttle")

	// ErrThrottleInvalidParams indicates invalid parameters for the throttle
	ErrThrottleInvalidParams = errors.New("invalid throttle parameters: limit must be > 0 and interval must be > 0")
)

// NewThrottle creates a new rate limiter with the specified limit per interval
// limit: maximum number of operations per interval
// interval: the time interval for the rate limit
func NewThrottle(limit int, interval time.Duration) *Throttle {
	if limit <= 0 || interval <= 0 {
		// Provide a safe default if invalid parameters are provided
		limit = 100
		interval = time.Second
	}

	return &Throttle{
		limit:      limit,
		interval:   interval,
		tokens:     limit, // Start with full tokens
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available or the context is canceled
// It returns nil if a token was acquired, or an error if the context was canceled
func (t *Throttle) Wait(ctx context.Context) error {
	for {
		waitTime, ok, err := t.tryAcquire()
		if err != nil {
			return err
		}
		if ok {
			return nil // Token acquired
		}

		// Need to wait for tokens to be available
		select {
		case <-ctx.Done():
			return ErrThrottleContextCanceled
		case <-time.After(waitTime):
			// Continue and try again
		}
	}
}

// tryAcquire attempts to acquire a token
// Returns:
// - a time.Duration to wait if no token is available
// - a bool indicating if a token was acquired
// - an error if something went wrong
func (t *Throttle) tryAcquire() (time.Duration, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Verify throttle parameters
	if t.limit <= 0 || t.interval <= 0 {
		return 0, false, ErrThrottleInvalidParams
	}

	now := time.Now()
	elapsed := now.Sub(t.lastRefill)

	// Refill tokens based on elapsed time
	if elapsed >= t.interval {
		// If more than one interval has passed, reset to full
		t.tokens = t.limit
		t.lastRefill = now
	} else {
		// Add tokens based on the elapsed fraction of the interval
		newTokens := int(float64(elapsed) / float64(t.interval) * float64(t.limit))
		if newTokens > 0 {
			t.tokens = min(t.limit, t.tokens+newTokens)
			t.lastRefill = t.lastRefill.Add(elapsed)
		}
	}

	// Check if we have tokens available
	if t.tokens > 0 {
		t.tokens--
		return 0, true, nil
	}

	// Calculate wait time until next token is available
	timePerToken := t.interval / time.Duration(t.limit)
	waitTime := timePerToken - elapsed%timePerToken
	return waitTime, false, nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
