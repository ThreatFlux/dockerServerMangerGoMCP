package utils

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewThrottle(t *testing.T) {
	// Test with valid parameters
	throttle := NewThrottle(100, time.Second)
	assert.Equal(t, 100, throttle.limit)
	assert.Equal(t, time.Second, throttle.interval)
	assert.Equal(t, 100, throttle.tokens)
	assert.NotEqual(t, time.Time{}, throttle.lastRefill)

	// Test with invalid parameters (should use safe defaults)
	invalidThrottle := NewThrottle(0, -time.Second)
	assert.Equal(t, 100, invalidThrottle.limit)
	assert.Equal(t, time.Second, invalidThrottle.interval)
}

func TestThrottleWait(t *testing.T) {
	// Create a throttle with 2 operations per 100ms
	throttle := NewThrottle(2, 100*time.Millisecond)
	ctx := context.Background()

	// First two operations should not block
	start := time.Now()
	for i := 0; i < 2; i++ {
		err := throttle.Wait(ctx)
		assert.NoError(t, err)
	}
	firstDuration := time.Since(start)
	assert.Less(t, firstDuration, 50*time.Millisecond, "First two operations should not be throttled")

	// Third operation should block until token is available
	start = time.Now()
	err := throttle.Wait(ctx)
	assert.NoError(t, err)
	blockDuration := time.Since(start)
	assert.GreaterOrEqual(t, blockDuration, 50*time.Millisecond, "Third operation should be throttled")
}

func TestThrottleContextCancellation(t *testing.T) {
	// Create a throttle with 1 operation per second
	throttle := NewThrottle(1, time.Second)

	// Use up the token
	ctx := context.Background()
	err := throttle.Wait(ctx)
	assert.NoError(t, err)

	// Create a context with short timeout
	ctxTimeout, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	// Wait should return context canceled error
	err = throttle.Wait(ctxTimeout)
	assert.Equal(t, ErrThrottleContextCanceled, err)
}

func TestThrottleRefill(t *testing.T) {
	// Create a throttle with 10 operations per 100ms
	throttle := NewThrottle(10, 100*time.Millisecond)
	ctx := context.Background()

	// Use all tokens
	for i := 0; i < 10; i++ {
		err := throttle.Wait(ctx)
		assert.NoError(t, err)
	}

	// Wait for refill (partial)
	time.Sleep(50 * time.Millisecond)

	// Should have approximately 5 tokens refilled
	start := time.Now()
	for i := 0; i < 5; i++ {
		err := throttle.Wait(ctx)
		assert.NoError(t, err)
	}
	duration := time.Since(start)
	assert.Less(t, duration, 50*time.Millisecond, "Should have refilled tokens")

	// 6th operation should block
	start = time.Now()
	err := throttle.Wait(ctx)
	assert.NoError(t, err)
	blockDuration := time.Since(start)
	assert.GreaterOrEqual(t, blockDuration, 20*time.Millisecond, "Should block after using refilled tokens")
}

func TestThrottleInvalidParams(t *testing.T) {
	// Create throttle with valid params
	throttle := NewThrottle(10, 100*time.Millisecond)
	ctx := context.Background()

	// Should work normally
	err := throttle.Wait(ctx)
	assert.NoError(t, err)

	// Manually change to invalid params
	throttle.limit = 0
	throttle.interval = 0

	// Should return error
	_, ok, err := throttle.tryAcquire()
	assert.False(t, ok)
	assert.Equal(t, ErrThrottleInvalidParams, err)
}
