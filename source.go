package tokenexchange

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// DefaultRefreshGrace is how far before expiry a [CachedSource] proactively
// refreshes its token.
const DefaultRefreshGrace = 60 * time.Second

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

	// Logger, if non-nil, receives a one-time Warn when a freshly minted token
	// has a lifetime shorter than the refresh grace window. In that situation
	// every call refreshes (the token is always considered stale), which
	// defeats caching and risks exhausting token-request rate limits. The fix
	// is a longer token TTL or a smaller grace. Defaults to nil (no logging).
	Logger *slog.Logger

	mu       sync.Mutex
	current  *Token
	warnOnce sync.Once
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
// caches a fresh one. Concurrent callers are serialized.
func (c *CachedSource) Token(ctx context.Context) (*Token, error) {
	if c == nil {
		return nil, fmt.Errorf("tokenexchange: CachedSource is nil")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.current.valid(c.grace) {
		return c.current, nil
	}

	if c.source == nil {
		return nil, fmt.Errorf("tokenexchange: CachedSource source is nil")
	}

	tok, err := c.source.Token(ctx)
	if err != nil {
		return nil, err
	}
	c.current = tok
	c.warnIfThrashing(tok)
	return tok, nil
}

// warnIfThrashing logs a single warning if the minted token's lifetime is no
// longer than the grace window, which would cause a refresh on every call.
func (c *CachedSource) warnIfThrashing(tok *Token) {
	if c.Logger == nil || c.grace <= 0 {
		return
	}
	lifetime := time.Until(tok.expiresAt)
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
