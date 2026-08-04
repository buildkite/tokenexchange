// Package tokenexchange mints short-lived Buildkite API access tokens using
// the OAuth 2.0 Token Exchange grant (RFC 8693).
//
// An application signs a JWT assertion (RFC 7523) with its private key and
// exchanges it at the Buildkite token endpoint for a scoped, short-lived API
// token (prefixed "bktx_") that acts on behalf of a user in the organization.
// See https://buildkite.com/docs/apis/oauth-token-exchange.
//
// The package is deliberately independent of any particular Buildkite API
// client. Its integration currency is an [http.RoundTripper] ([Transport]) and
// an [*http.Client] ([NewClient]) that inject the minted token as a Bearer
// credential. That client can drive the REST API (for example via
// github.com/buildkite/go-buildkite's WithHTTPClient option), the GraphQL API,
// Package Registries, or raw HTTP calls to explicitly allowed origins:
//
//	signer, _ := tokenexchange.LoadPrivateKey("private_key.pem")
//
//	ex := &tokenexchange.Exchanger{
//		ClientID:   "0123456789abcdef0123",
//		OrgSlug:    "my-org",
//		UserEmail:  "user@example.com",
//		KeyID:      "my-key-1",
//		Scopes:     []string{"read_pipelines", "read_builds"},
//		PrivateKey: signer,
//	}
//
//	httpClient := tokenexchange.NewClient(tokenexchange.NewCachedSource(ex))
//	// httpClient now authenticates requests to the official Buildkite API
//	// origins with a freshly-minted, transparently-cached bktx_ token.
package tokenexchange

const (
	// DefaultEndpoint is the Buildkite OAuth token endpoint.
	DefaultEndpoint = "https://buildkite.com/oauth/token"

	grantTypeTokenExchange       = "urn:ietf:params:oauth:grant-type:token-exchange"
	clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	subjectTokenTypeUserEmail    = "urn:buildkite:params:oauth:token-type:user-email"
	issuedTokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
)
