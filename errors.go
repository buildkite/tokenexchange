package tokenexchange

import "fmt"

// TokenError is an RFC 6749 §5.2 error response returned by the token endpoint.
//
// Callers can inspect the machine-readable [TokenError.Code] to react to
// specific failures, for example retrying with a fresh jti on "invalid_client"
// with a "JWT has already been used" description.
type TokenError struct {
	// Code is the OAuth error code, for example "invalid_client",
	// "invalid_scope", "invalid_target", or "unsupported_grant_type".
	Code string
	// Description is the optional human-readable error_description.
	Description string
	// StatusCode is the HTTP status code of the response.
	StatusCode int
}

func (e *TokenError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("tokenexchange: %s: %s (HTTP %d)", e.Code, e.Description, e.StatusCode)
	}
	return fmt.Sprintf("tokenexchange: %s (HTTP %d)", e.Code, e.StatusCode)
}

// Common OAuth error codes returned by the Buildkite token endpoint. Use these
// with [TokenError.Code] to branch on specific failures.
const (
	ErrCodeInvalidClient    = "invalid_client"
	ErrCodeInvalidRequest   = "invalid_request"
	ErrCodeInvalidScope     = "invalid_scope"
	ErrCodeInvalidTarget    = "invalid_target"
	ErrCodeUnsupportedGrant = "unsupported_grant_type"
)
