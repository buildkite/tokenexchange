// Command mcp_gateway demonstrates a single-user MCP proxy with token exchange.
// It uses a demo bearer secret, not corporate IdP authentication. See README.md.
package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/buildkite/tokenexchange"
)

func main() {
	clientID := flag.String("client-id", "", "Token Exchange application client ID (required)")
	keyFile := flag.String("private-key", "", "path to RSA or EC private key PEM (required)")
	org := flag.String("org", "", "Buildkite organization slug (required)")
	email := flag.String("user-email", "", "verified Buildkite email (set this or -user-uuid)")
	uuid := flag.String("user-uuid", "", "Buildkite user UUID (set this or -user-email)")
	kid := flag.String("kid", "", "JWT key ID matching your registered JWKS")
	scopes := flag.String("scopes", "read_user read_pipelines read_builds", "space-delimited read scopes for your tools")
	flag.Parse()

	secret := os.Getenv("GATEWAY_TOKEN")
	if secret == "" || *clientID == "" || *keyFile == "" || *org == "" || (*email == "") == (*uuid == "") {
		log.Fatal("set GATEWAY_TOKEN, -client-id, -private-key, -org, and exactly one of -user-email or -user-uuid")
	}
	if len(strings.Fields(*scopes)) == 0 {
		log.Fatal("-scopes must explicitly request the read scopes needed by your tools")
	}
	signer, err := tokenexchange.LoadPrivateKey(*keyFile)
	if err != nil {
		log.Fatal(err)
	}

	// This source always acts as one configured user. A multi-user gateway must
	// map validated corporate identities to separate, fixed exchangers/caches.
	source := tokenexchange.NewCachedSource(&tokenexchange.Exchanger{
		ClientID: *clientID, OrgSlug: *org, UserEmail: *email, UserUUID: *uuid,
		PrivateKey: signer, KeyID: *kid, Scopes: strings.Fields(*scopes),
		ExpiresIn: 5 * time.Minute,
	})
	target := &url.URL{Scheme: "https", Host: "mcp.buildkite.com", Path: "/direct/readonly"}
	mux := http.NewServeMux()
	mux.Handle("/mcp", gateway(secret, source, target))
	server := &http.Server{
		Addr: "127.0.0.1:8080", Handler: mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       time.Minute,
	}
	log.Print("single-user demo gateway listening on 127.0.0.1:8080/mcp")
	log.Fatal(server.ListenAndServe())
}

func gateway(secret string, source tokenexchange.Source, target *url.URL) http.Handler {
	client := tokenexchange.NewClient(source, target.Scheme+"://"+target.Host)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(target)
			p.Out.URL.Path = target.Path
			p.Out.URL.RawPath = ""
			p.Out.URL.RawQuery = ""
			// Replace the demo credential; never send it or client cookies upstream.
			p.Out.Header.Del("Authorization")
			p.Out.Header.Del("Cookie")
			// The gateway, not its caller, chooses toolset/read-only routing.
			p.Out.Header.Del("X-Buildkite-Readonly")
			p.Out.Header.Del("X-Buildkite-Toolsets")
		},
		Transport:     client.Transport,
		FlushInterval: -1, // Forward streaming MCP responses immediately.
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			// Do not expose exchange errors or endpoint response bodies to callers.
			http.Error(w, "Upstream request failed", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header.Values("Authorization")
		if len(headers) != 1 || subtle.ConstantTimeCompare([]byte(headers[0]), []byte("Bearer "+secret)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-gateway"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}
