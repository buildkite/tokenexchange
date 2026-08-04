package tokenexchange

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	// DefaultRefreshGrace is how far before expiry a [CachedSource]
	// proactively refreshes its token.
	DefaultRefreshGrace = 60 * time.Second

	refreshRetryInitial = time.Second
	refreshRetryMax     = 30 * time.Second
)

// Source provides Buildkite API tokens on demand. [Exchanger] and [CachedSource]
// both implement it.
type Source interface {
	// Token returns a valid token, minting a new one if necessary. It must be
	// safe for concurrent use.
	Token(ctx context.Context) (*Token, error)
}

// CachedSource wraps a [Source] and caches the minted token, only calling the
// underlying source when the cached token is missing or about to expire within
// the refresh grace window.
//
// It is safe for concurrent use: the Buildkite docs recommend caching and
// reusing tokens rather than exchanging one per request.
type CachedSource struct {
	source Source
	grace  time.Duration

	// Logger, if non-nil, reports refresh failures and recovery. It also
	// receives a one-time Warn when a freshly minted token has a lifetime
	// shorter than the refresh grace window. Defaults to nil (no logging).
	Logger *slog.Logger

	mu              sync.Mutex
	current         *Token
	retryAt         time.Time
	refreshFailures int
	warnOnce        sync.Once
	now             func() time.Time
}

// NewCachedSource returns a CachedSource that wraps source using
// [DefaultRefreshGrace].
func NewCachedSource(source Source) *CachedSource {
	return NewCachedSourceGrace(source, DefaultRefreshGrace)
}

// NewCachedSourceGrace returns a CachedSource that refreshes its token once it
// is within grace of expiry. A grace of zero refreshes only after expiry.
func NewCachedSourceGrace(source Source, grace time.Duration) *CachedSource {
	if grace < 0 {
		grace = 0
	}
	return &CachedSource{source: source, grace: grace}
}

// Token returns the cached token if it is still valid, otherwise it mints and
// caches a fresh one. If a proactive refresh fails, the existing token is
// returned while it remains unexpired and refreshes are retried with backoff.
// Concurrent callers are serialized.
func (c *CachedSource) Token(ctx context.Context) (*Token, error) {
	if c == nil {
		return nil, fmt.Errorf("tokenexchange: CachedSource is nil")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clock()
	if c.current.validAt(now, c.grace) {
		return c.current, nil
	}
	if c.current.validAt(now, 0) && now.Before(c.retryAt) {
		return c.current, nil
	}

	if c.source == nil {
		return nil, fmt.Errorf("tokenexchange: CachedSource source is nil")
	}

	tok, err := c.source.Token(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		now = c.clock()
		if c.current.validAt(now, 0) {
			c.deferRefresh(now, err)
			return c.current, nil
		}
		return nil, err
	}

	failedAttempts := c.refreshFailures
	c.current = tok
	c.retryAt = time.Time{}
	c.refreshFailures = 0
	c.warnIfThrashing(tok, c.clock())
	if c.Logger != nil && failedAttempts > 0 {
		c.Logger.Info("tokenexchange: token refresh recovered",
			"failed_attempts", failedAttempts,
		)
	}
	return tok, nil
}

func (c *CachedSource) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *CachedSource) deferRefresh(now time.Time, refreshErr error) {
	c.refreshFailures++
	delay := refreshRetryBackoff(c.refreshFailures)
	c.retryAt = now.Add(delay)
	if c.retryAt.After(c.current.expiresAt) {
		c.retryAt = c.current.expiresAt
	}

	if c.Logger != nil {
		c.Logger.Warn("tokenexchange: token refresh failed; using cached token",
			"error", refreshErr,
			"token_expires_at", c.current.expiresAt,
			"retry_at", c.retryAt,
		)
	}
}

func refreshRetryBackoff(failures int) time.Duration {
	delay := refreshRetryInitial
	for i := 1; i < failures && delay < refreshRetryMax; i++ {
		delay *= 2
	}
	if delay > refreshRetryMax {
		return refreshRetryMax
	}
	return delay
}

// warnIfThrashing logs a single warning if the minted token's lifetime is no
// longer than the grace window, which would cause a refresh on every call.
func (c *CachedSource) warnIfThrashing(tok *Token, now time.Time) {
	if c.Logger == nil || c.grace <= 0 {
		return
	}
	lifetime := tok.expiresAt.Sub(now)
	if lifetime > c.grace {
		return
	}
	c.warnOnce.Do(func() {
		c.Logger.Warn("tokenexchange: minted token lifetime is shorter than the cache refresh grace; caching is ineffective and every request will mint a new token",
			"token_lifetime", lifetime.Round(time.Second),
			"refresh_grace", c.grace,
		)
	})
}
