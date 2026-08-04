# tokenexchange

`tokenexchange` is a small Go library for [Buildkite OAuth Token Exchange][docs]. It signs an assertion, exchanges it for a short-lived Buildkite API token, and adds that token to HTTP requests.

It works with plain `net/http` and does not depend on a Buildkite API client.

## Install

```bash
go get github.com/buildkite/tokenexchange
```

## Before you start

Create a Token Exchange app in Buildkite and register your public key as a JWKS. The [Buildkite docs][docs] cover scopes, IP restrictions, and token lifetimes. This library handles the exchange at runtime; it does not create or configure the app.

The [`examples/jwks`](examples/jwks) command can convert a PEM public or private key into a JWKS:

```bash
go run ./examples/jwks -key public_key.pem -kid my-key-1
```

Keep the private key with your application. The key ID must match the `KeyID` used below.

## Usage

```go
signer, err := tokenexchange.LoadPrivateKey("private_key.pem")
if err != nil {
	log.Fatal(err)
}

ex := &tokenexchange.Exchanger{
	ClientID:   "0123456789abcdef0123",
	OrgSlug:    "my-org",
	UserEmail:  "user@example.com", // Or set UserUUID instead.
	KeyID:      "my-key-1",
	Scopes:     []string{"read_pipelines", "read_builds"},
	PrivateKey: signer,
}

// Cache and reuse tokens rather than exchanging one for every request.
src := tokenexchange.NewCachedSource(ex)
httpClient := tokenexchange.NewClient(src)
```

Set exactly one of `UserEmail` or `UserUUID`. The organization members REST API returns each user's UUID as `id`.

Use `httpClient` directly for REST, GraphQL, Package Registries, or other HTTP requests. To use it with [`go-buildkite`][go-buildkite]:

```go
client, err := buildkite.NewOpts(
	buildkite.WithHTTPClient(httpClient),
)
```

Do not also use `buildkite.WithTokenAuth`; this client already sets the `Authorization` header.

## Where tokens are sent

By default, `NewClient` only authenticates requests to:

- `https://api.buildkite.com`
- `https://graphql.buildkite.com`
- `https://packages.buildkite.com`

Other requests are sent without a token. This prevents a token from leaking through client reuse or a cross-origin redirect.

Pass custom origins to `NewClient` when needed. They replace the defaults:

```go
httpClient := tokenexchange.NewClient(src, "https://buildkite.example.com")
```

Origins must use the form `scheme://host`, including a port when required.

## Caching and refresh

Calling `Exchanger.Token` always performs a network request. `CachedSource` keeps the token in memory, coalesces concurrent refreshes, and refreshes before expiry as recommended by Buildkite.

The default refresh grace is 60 seconds. For shorter token lifetimes, use `NewCachedSourceGrace`; otherwise every lookup may attempt a refresh. You can also attach an `*slog.Logger` to `CachedSource` to see refresh failures and recovery.

If a proactive refresh fails, an unexpired token remains available while refreshes are retried with backoff. A `401 Unauthorized` response invalidates the cached token for the next request. The failed request is not retried.

`Source` connects the exchanger, cache, and transport. It represents a source of tokens minted through Buildkite Token Exchange; `Exchanger` and `CachedSource` both implement it.

## Errors

OAuth errors are returned as `*TokenError`. Network and malformed-response errors are returned as wrapped Go errors.

```go
_, err := src.Token(ctx)
var te *tokenexchange.TokenError
if errors.As(err, &te) && te.Code == tokenexchange.ErrCodeInvalidScope {
	// The requested scopes exceed the app's grantable scopes.
}
```

## Examples

- [`examples/jwks`](examples/jwks) converts a PEM key into a JWKS
- [`examples/mint`](examples/mint) performs an exchange and makes an authenticated REST request

[docs]: https://buildkite.com/docs/apis/oauth-token-exchange
[go-buildkite]: https://github.com/buildkite/go-buildkite
