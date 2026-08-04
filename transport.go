package tokenexchange

import (
	"fmt"
	"net/http"
	"strings"
)

// Transport is an [http.RoundTripper] that authenticates outgoing requests to
// allowed origins with a token obtained from Source.
//
// It is the primary integration point with API clients: pass a client built
// from a Transport to anything that accepts an [*http.Client]. For example,
// github.com/buildkite/go-buildkite's WithHTTPClient option, a GraphQL client,
// or Package Registries.
type Transport struct {
	// Source supplies tokens. Typically a [*CachedSource] wrapping an
	// [*Exchanger]. Required.
	Source Source

	// Base is the underlying RoundTripper. Defaults to http.DefaultTransport.
	Base http.RoundTripper

	// AllowedOrigins limits where tokens are attached. Each entry must be an
	// origin of the form "scheme://host", including a port when required. If
	// empty, the official Buildkite REST, GraphQL, and Package Registries HTTPS
	// origins are allowed. Requests to other origins, including cross-origin
	// redirects, are sent through Base without a token.
	AllowedOrigins []string
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *Transport) allowsOrigin(req *http.Request) bool {
	origin := req.URL.Scheme + "://" + req.URL.Host
	if len(t.AllowedOrigins) == 0 {
		switch {
		case strings.EqualFold(origin, "https://api.buildkite.com"):
			return true
		case strings.EqualFold(origin, "https://graphql.buildkite.com"):
			return true
		case strings.EqualFold(origin, "https://packages.buildkite.com"):
			return true
		default:
			return false
		}
	}

	for _, allowed := range t.AllowedOrigins {
		if strings.EqualFold(origin, allowed) {
			return true
		}
	}
	return false
}

// RoundTrip implements [http.RoundTripper]. It fetches a token using the
// request's context, then attaches it as a Bearer credential on a clone of the
// request so the caller's original is never mutated. Requests outside
// [Transport.AllowedOrigins] are delegated without obtaining or attaching a
// token.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.allowsOrigin(req) {
		return t.base().RoundTrip(req)
	}

	if t.Source == nil {
		closeRequestBody(req)
		return nil, fmt.Errorf("tokenexchange: Transport.Source is nil")
	}

	tok, err := t.Source.Token(req.Context())
	if err != nil {
		closeRequestBody(req)
		return nil, fmt.Errorf("tokenexchange: obtaining token: %w", err)
	}

	r := req.Clone(req.Context())
	r.Header.Set("Authorization", tok.Type()+" "+tok.AccessToken())

	// Per the http.RoundTripper contract, the request body must be closed,
	// including on error paths. Once delegated, the base RoundTripper owns it.
	return t.base().RoundTrip(r)
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// NewClient returns an [*http.Client] that authenticates requests to allowed
// origins with tokens from source. It is a convenience wrapper around
// [Transport]. If allowedOrigins is empty, the official Buildkite REST,
// GraphQL, and Package Registries HTTPS origins are allowed. Supplying origins
// replaces those defaults.
//
// Pass the result to any API client that accepts an *http.Client:
//
//	bk, _ := buildkite.NewOpts(buildkite.WithHTTPClient(
//		tokenexchange.NewClient(tokenexchange.NewCachedSource(ex)),
//	))
func NewClient(source Source, allowedOrigins ...string) *http.Client {
	return &http.Client{Transport: &Transport{
		Source:         source,
		AllowedOrigins: allowedOrigins,
	}}
}
