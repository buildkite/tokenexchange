# tokenexchange

A small, dependency-light Go library for [Buildkite OAuth Token Exchange][docs] (RFC 8693). It signs a JWT assertion (RFC 7523) with your application's private key, exchanges it at the Buildkite token endpoint for a short-lived, scoped API token (prefixed `bktx_`), and hands you an `*http.Client` that authenticates requests to allowed Buildkite API origins on behalf of a user.

The package is intentionally **independent of any Buildkite API client**. Its integration currency is an `http.RoundTripper` (`Transport`) and an `*http.Client` (`NewClient`). That means you can use it:

- standalone against the **GraphQL API**, **Package Registries**, or raw HTTP calls to allowed origins, and
- with official packages, such as [`go-buildkite`][go-buildkite] via its `WithHTTPClient` option, for the  REST API, without forcing a dependency on `go-buildkite` (or on this library) in either direction

## Install

```bash
go get github.com/buildkite/tokenexchange
```

## Setup

To use Token Exchange you need a Token Exchange application configured in Buildkite, which requires your public key in [JWKS][jwks] format. See the [Buildkite docs][docs] for the full configuration (grantable scopes, default scopes, allowed IPs, max TTL).

**1. Generate a key pair** (RSA or ECDSA P-256):

```bash
# RSA (2048-bit)
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem

# or ECDSA (P-256)
openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem
```

**2. Convert the public key to JWKS** using the bundled
[`examples/jwks`](examples/jwks) tool, then register the output with your
Buildkite application:

```bash
# From the public key, or straight from the private key (public is derived):
go run ./examples/jwks -key public_key.pem -kid my-key-1
```

The `-kid` you choose must match the `KeyID` you set on the `Exchanger` so Buildkite can select the right key. Keep `private_key.pem` with your application; only the JWKS (public key) is registered with Buildkite.

## Usage

```go
signer, err := tokenexchange.LoadPrivateKey("private_key.pem")
if err != nil {
	log.Fatal(err)
}

ex := &tokenexchange.Exchanger{
	ClientID:   "0123456789abcdef0123", // Token Exchange application client ID
	OrgSlug:    "my-org",               // organization slug from the URL
	UserEmail:  "user@example.com",     // user to act as
	KeyID:      "my-key-1",             // JWK "kid" (recommended)
	Scopes:     []string{"read_pipelines", "read_builds"},
	PrivateKey: signer,
}

// Wrap in a CachedSource so tokens are reused until close to expiry,
// as recommended by the Buildkite docs. Safe for concurrent use.
src := tokenexchange.NewCachedSource(ex)

// An *http.Client scoped to the official Buildkite API origins.
httpClient := tokenexchange.NewClient(src)
```

### With go-buildkite (REST)

```go
client, err := buildkite.NewOpts(
	buildkite.WithHTTPClient(httpClient),
)
```

Do **not** also pass `buildkite.WithTokenAuth(...)` — the transport supplies the `Authorization` header itself.

### Standalone (GraphQL, registries, raw HTTP)

```go
// The same client works for GraphQL or any other Buildkite HTTP API.
body := strings.NewReader(`{"query":"{ viewer { user { name } } }"}`)
req, _ := http.NewRequest(http.MethodPost, "https://graphql.buildkite.com/v1", body)
req.Header.Set("Content-Type", "application/json")

resp, err := httpClient.Do(req) // Authorization: Bearer bktx_... added automatically
```

### Destination scoping

To prevent credentials leaking through client reuse or cross-origin redirects,
`Transport` only attaches tokens to these HTTPS origins by default:

- `https://api.buildkite.com`
- `https://graphql.buildkite.com`
- `https://packages.buildkite.com`

Requests to any other origin are still sent, but without obtaining or attaching
a token. This allows redirects to presigned storage URLs to work without
forwarding the Buildkite credential.

For a custom API origin, pass it to `NewClient`. Supplying one or more origins
replaces the defaults:

```go
httpClient := tokenexchange.NewClient(src, "https://buildkite.example.com")
```

Origins must have the form `scheme://host`, including a port when required.
When constructing `Transport` directly, configure the equivalent
`AllowedOrigins` field.

## Caching and short token TTLs

`CachedSource` reuses a token until it is within a grace window of expiry (`DefaultRefreshGrace`, 60s). If you request a token TTL shorter than the grace window (for example `expires_in=30s`), the cached token is always considered stale and **every call mints a new token**, defeating caching.

This is a valid configuration, not an error — so the library does not reject it. Instead, attach an `*slog.Logger` and `CachedSource` warns once if it detects the situation:

```go
src := tokenexchange.NewCachedSource(ex)
src.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
// WARN tokenexchange: minted token lifetime is shorter than the cache refresh
// grace; caching is ineffective ... token_lifetime=30s refresh_grace=1m0s
```

Use a longer token TTL, or a smaller grace via `NewCachedSourceGrace`.

If a proactive refresh fails while the cached token is still unexpired,
`CachedSource` continues returning that token and retries refresh with
exponential backoff from 1 second up to 30 seconds, capped at token expiry.
Expired tokens and caller cancellation errors are never masked. When a logger
is configured, refresh fallback and recovery are logged.

## Examples

- [`examples/jwks`](examples/jwks) — convert a PEM public/private key into a
  JWKS for registering your application (see [Setup](#setup)).
- [`examples/mint`](examples/mint) — a runnable end-to-end token exchange that
  makes authenticated REST calls:

```bash
go run ./examples/mint \
  -client-id CLIENT_ID -private-key key.pem \
  -org my-org -user-email dev@example.com \
  /v2/organizations/my-org/pipelines
```

## API

| Type / func | Purpose |
|-------------|---------|
| `Exchanger` | Signs the JWT assertion and performs the exchange. Implements `Source`. |
| `Source` | `Token(ctx) (*Token, error)` — anything that supplies tokens. |
| `CachedSource` | Caches a token and refreshes within a grace window. Concurrency-safe. Optional `Logger` warns on cache-thrash. |
| `Transport` | Origin-scoped `http.RoundTripper` that injects `Authorization: Bearer`. |
| `NewClient(Source, ...allowedOrigins)` | Convenience `*http.Client` built from a `Transport`; defaults to official Buildkite API origins. |
| `LoadPrivateKey` / `ParsePrivateKey` | Parse PKCS#1, PKCS#8, or SEC1 EC PEM keys. |
| `TokenError` | Typed RFC 6749 §5.2 error (`Code`, `Description`, `StatusCode`). |

Supported signing algorithms: **RS256** (RSA) and **ES256** (ECDSA P-256).

## Error handling

Failed exchanges return a `*TokenError` you can branch on:

```go
tok, err := src.Token(ctx)
var te *tokenexchange.TokenError
if errors.As(err, &te) && te.Code == tokenexchange.ErrCodeInvalidScope {
	// requested scopes exceed the app's grantable scopes
}
```

[docs]: https://buildkite.com/docs/apis/oauth-token-exchange
[go-buildkite]: https://github.com/buildkite/go-buildkite
[jwks]: https://datatracker.ietf.org/doc/html/rfc7517
