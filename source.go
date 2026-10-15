package tokenexchange

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	// DefaultRefreshGrace is the maximum time before expiry at which a
	// [CachedSource] proactively refreshes its token.
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

// InvalidatingSource is a Source that can discard a token rejected by an API.
// Implementations must ignore a stale token if a newer token is already current.
type InvalidatingSource interface {
	Source
	InvalidateToken(token *Token)
}

type refreshCall struct {
	done         chan struct{}
	token        *Token
	err          error
	retryWaiters bool
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

	// Logger, if non-nil, reports refresh failures and recovery.
	// Defaults to nil (no logging).
	Logger *slog.Logger

	mu              sync.Mutex
	current         *Token
	refreshGrace    time.Duration
	retryAt         time.Time
	refreshErr      error
	refreshFailures int
	refreshing      *refreshCall
	now             func() time.Time
}

// NewCachedSource returns a CachedSource that wraps source using
// [DefaultRefreshGrace].
func NewCachedSource(source Source) *CachedSource {
	return NewCachedSourceGrace(source, DefaultRefreshGrace)
}

// NewCachedSourceGrace returns a CachedSource that refreshes its token once it
// is within grace of expiry. The effective grace is capped at half the token's
// remaining lifetime when cached, so short-lived tokens can still be reused.
// A grace of zero refreshes only after expiry; negative values are treated as zero.
func NewCachedSourceGrace(source Source, grace time.Duration) *CachedSource {
	if grace < 0 {
		grace = 0
	}
	return &CachedSource{source: source, grace: grace}
}

// InvalidateToken implements [InvalidatingSource]. It removes token from the
// cache if it is still current; a stale token does not invalidate a newer one.
// It is safe for concurrent use.
func (c *CachedSource) InvalidateToken(tok *Token) {
	if c == nil || tok == nil {
		return
	}

	c.mu.Lock()
	if c.current != tok {
		c.mu.Unlock()
		return
	}
	c.current = nil
	c.retryAt = time.Time{}
	c.refreshErr = nil
	c.refreshFailures = 0
	source := c.source
	c.mu.Unlock()

	if invalidator, ok := source.(InvalidatingSource); ok {
		invalidator.InvalidateToken(tok)
	}
}

// Token returns the cached token if it is still valid, otherwise it mints and
// caches a fresh one. If a proactive refresh fails, the existing token is
// returned while it remains unexpired and refreshes are retried with backoff.
// Without an unexpired token, the last refresh error is returned during backoff.
// Concurrent refreshes are coalesced. Callers continue using an unexpired token
// while a refresh is in progress; callers waiting for a required refresh can
// stop waiting by canceling their context.
func (c *CachedSource) Token(ctx context.Context) (*Token, error) {
	if c == nil {
		return nil, fmt.Errorf("tokenexchange: CachedSource is nil")
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		now := c.clock()
		if c.current.validAt(now, c.refreshGrace) {
			tok := c.current
			c.mu.Unlock()
			return tok, nil
		}
		if now.Before(c.retryAt) {
			if c.current.validAt(now, 0) {
				tok := c.current
				c.mu.Unlock()
				return tok, nil
			}
			err := c.refreshErr
			c.mu.Unlock()
			return nil, err
		}

		if call := c.refreshing; call != nil {
			if c.current.validAt(now, 0) {
				tok := c.current
				c.mu.Unlock()
				return tok, nil
			}
			c.mu.Unlock()

			select {
			case <-call.done:
				if call.retryWaiters {
					continue
				}
				return call.token, call.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		if c.source == nil {
			c.mu.Unlock()
			return nil, fmt.Errorf("tokenexchange: CachedSource source is nil")
		}

		call := &refreshCall{done: make(chan struct{})}
		c.refreshing = call
		source := c.source
		c.mu.Unlock()
		defer func() {
			c.mu.Lock()
			if c.refreshing == call {
				// Source.Token panicked. Preserve the panic for the initiating
				// caller, but unblock other callers so the cache can recover.
				call.retryWaiters = true
				c.refreshing = nil
				close(call.done)
			}
			c.mu.Unlock()
		}()

		tok, err := source.Token(ctx)

		c.mu.Lock()
		func() {
			defer c.mu.Unlock()
			call.token, call.err, call.retryWaiters = c.finishRefresh(ctx, tok, err)
			c.refreshing = nil
			close(call.done)
		}()
		return call.token, call.err
	}
}

// finishRefresh updates cache state after a refresh. The caller must hold c.mu.
func (c *CachedSource) finishRefresh(ctx context.Context, tok *Token, err error) (*Token, error, bool) {
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// The refresh belonged to this caller's context. Other callers that
			// needed a token should retry rather than inherit its cancellation.
			return nil, ctxErr, true
		}

		now := c.clock()
		c.deferRefresh(now, err)
		if c.current.validAt(now, 0) {
			return c.current, nil, false
		}
		return nil, err, false
	}

	failedAttempts := c.refreshFailures
	c.current = tok
	c.refreshGrace = min(c.grace, tok.expiresAt.Sub(c.clock())/2)
	c.retryAt = time.Time{}
	c.refreshErr = nil
	c.refreshFailures = 0
	if c.Logger != nil && failedAttempts > 0 {
		c.Logger.Info("tokenexchange: token refresh recovered",
			"failed_attempts", failedAttempts,
		)
	}
	return tok, nil, false
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
	c.refreshErr = refreshErr

	if c.Logger != nil {
		c.Logger.Warn("tokenexchange: token refresh failed",
			"error", refreshErr,
			"using_cached_token", c.current.validAt(now, 0),
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
