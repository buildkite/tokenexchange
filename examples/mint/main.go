// Command mint demonstrates Buildkite OAuth Token Exchange (RFC 8693) using the
// github.com/buildkite/tokenexchange library.
//
// It builds a cached token source from a signed JWT assertion, then makes one
// or more authenticated Buildkite REST API requests. The library also supports
// the GraphQL API, Package Registries, and explicitly allowed custom origins,
// and its client can be handed to go-buildkite via buildkite.WithHTTPClient.
//
// Usage:
//
//	go run ./examples/mint \
//	  -client-id CLIENT_ID -private-key key.pem -org my-org -user-email dev@example.com \
//	  /v2/organizations/my-org/pipelines /v2/organizations/my-org/builds
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/buildkite/tokenexchange"
)

func main() {
	var (
		clientID       = flag.String("client-id", "", "Token Exchange application client ID (required)")
		privateKeyFile = flag.String("private-key", "", "path to RSA or EC private key PEM (required)")
		orgSlug        = flag.String("org", "", "Buildkite organization slug (required)")
		userEmail      = flag.String("user-email", "", "Buildkite user email to act as (required unless -user-uuid is set)")
		userUUID       = flag.String("user-uuid", "", "Buildkite user UUID to act as (required unless -user-email is set)")
		kid            = flag.String("kid", "", "JWT key ID (kid) header; should match the kid in your JWKS")
		scopes         = flag.String("scopes", "read_pipelines read_builds", "space-delimited scopes (empty uses app defaults)")
		tokenEndpoint  = flag.String("token-endpoint", tokenexchange.DefaultEndpoint, "OAuth token endpoint")
		apiBase        = flag.String("api", "https://api.buildkite.com", "Buildkite REST API base URL")
		expiresIn      = flag.Duration("expires-in", 0, "requested token TTL, e.g. 30m (0 uses the app maximum)")
	)
	flag.Parse()

	if *clientID == "" || *privateKeyFile == "" || *orgSlug == "" {
		flag.Usage()
		os.Exit(1)
	}
	if (*userEmail == "" && *userUUID == "") || (*userEmail != "" && *userUUID != "") {
		flag.Usage()
		os.Exit(1)
	}

	signer, err := tokenexchange.LoadPrivateKey(*privateKeyFile)
	if err != nil {
		log.Fatalf("loading private key: %v", err)
	}

	var scopeList []string
	if s := strings.Fields(*scopes); len(s) > 0 {
		scopeList = s
	}

	// Exchanger signs the JWT assertion and exchanges it for a bktx_ token.
	exchanger := &tokenexchange.Exchanger{
		ClientID:   *clientID,
		OrgSlug:    *orgSlug,
		UserEmail:  *userEmail,
		UserUUID:   *userUUID,
		KeyID:      *kid,
		Scopes:     scopeList,
		ExpiresIn:  *expiresIn,
		Endpoint:   *tokenEndpoint,
		PrivateKey: signer,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}

	// CachedSource reuses tokens, including short-lived ones. The Logger reports
	// refresh failures and recovery.
	source := tokenexchange.NewCachedSource(exchanger)
	source.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Verify we can mint a token before making API calls.
	log.Print("[oauth] exchanging JWT assertion for access token")
	tok, err := source.Token(context.Background())
	if err != nil {
		log.Fatalf("[oauth] token exchange failed: %v", err)
	}
	log.Printf("[oauth] minted token (scopes=%s, expires in %s)",
		strings.Join(tok.Scopes(), " "), time.Until(tok.Expiry()).Round(time.Second))

	apiBaseURL, err := url.Parse(*apiBase)
	if err != nil || apiBaseURL.Scheme == "" || apiBaseURL.Host == "" {
		log.Fatalf("invalid API base URL %q", *apiBase)
	}

	// One authenticated client, scoped to the configured REST API origin.
	client := tokenexchange.NewClient(source, apiBaseURL.Scheme+"://"+apiBaseURL.Host)
	client.Timeout = 30 * time.Second

	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{
			fmt.Sprintf("/v2/organizations/%s/pipelines", *orgSlug),
		}
	}

	for i, p := range paths {
		apiURL, err := url.JoinPath(*apiBase, p)
		if err != nil {
			log.Fatalf("[api %d/%d] invalid URL: %v", i+1, len(paths), err)
		}
		log.Printf("[api %d/%d] GET %s", i+1, len(paths), apiURL)

		resp, err := client.Get(apiURL)
		if err != nil {
			log.Fatalf("[api %d/%d] request failed: %v", i+1, len(paths), err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			log.Fatalf("[api %d/%d] reading body failed: %v", i+1, len(paths), err)
		}
		log.Printf("[api %d/%d] %s (%s)", i+1, len(paths), resp.Status, summarize(body))

		if resp.StatusCode >= http.StatusBadRequest {
			os.Exit(1)
		}
	}
}

// summarize reports the item count for JSON arrays plus the byte size.
func summarize(body []byte) string {
	var arr []json.RawMessage
	if json.Unmarshal(body, &arr) == nil {
		return fmt.Sprintf("%d items, %d B", len(arr), len(body))
	}
	return fmt.Sprintf("%d B", len(body))
}
