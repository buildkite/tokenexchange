package tokenexchange

import "time"

// Token is a minted Buildkite API access token and its absolute expiry.
//
// Tokens are produced by an [Exchanger] and are safe to read concurrently;
// they are immutable once returned.
type Token struct {
	accessToken string
	tokenType   string
	scopes      []string
	expiresAt   time.Time
}

// AccessToken returns the bearer token value (prefixed "bktx_").
func (t *Token) AccessToken() string { return t.accessToken }

// Type returns the token type (always "Bearer" for Buildkite token exchange).
func (t *Token) Type() string {
	if t.tokenType == "" {
		return "Bearer"
	}
	return t.tokenType
}

// Scopes returns the scopes granted to the token.
func (t *Token) Scopes() []string { return append([]string(nil), t.scopes...) }

// Expiry returns the absolute time at which the token expires.
func (t *Token) Expiry() time.Time { return t.expiresAt }

// valid reports whether the token exists and will not expire within grace.
// It does not verify the cryptographic validity of the token contents.
func (t *Token) valid(grace time.Duration) bool {
	if t == nil || t.accessToken == "" {
		return false
	}
	return time.Now().Add(grace).Before(t.expiresAt)
}
