package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/buildkite/tokenexchange"
)

func TestGateway(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var exchanges, upstreamCalls atomic.Int32
	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("subject_token") != "alice@example.com" || r.Form.Get("audience") != "test-org" {
			t.Error("exchange used the wrong configured identity or organization")
		}
		if r.Form.Get("client_assertion") == "" {
			t.Error("exchange omitted the signed assertion")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"bktx_upstream_only","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","expires_in":300}`)
	}))
	defer tokens.Close()

	const requestBody = `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`
	const responseBody = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[]}}\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer bktx_upstream_only" {
			t.Error("upstream did not receive the minted Buildkite credential")
		}
		for _, header := range []string{"Cookie", "X-Buildkite-Readonly", "X-Buildkite-Toolsets"} {
			if r.Header.Get(header) != "" {
				t.Errorf("upstream received caller header %s", header)
			}
		}
		if r.Method != http.MethodPost || r.URL.RequestURI() != "/direct/readonly" {
			t.Errorf("unexpected upstream route: %s %s", r.Method, r.URL.RequestURI())
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != requestBody || r.Header.Get("Mcp-Protocol-Version") != "2025-03-26" {
			t.Errorf("MCP request was not preserved: body=%q, error=%v", body, err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, responseBody)
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL + "/direct/readonly")
	if err != nil {
		t.Fatal(err)
	}
	source := tokenexchange.NewCachedSource(&tokenexchange.Exchanger{
		ClientID: "test-client", OrgSlug: "test-org", UserEmail: "alice@example.com",
		PrivateKey: key, Endpoint: tokens.URL, Scopes: []string{"read_builds"},
	})
	server := httptest.NewServer(gateway("demo-secret", source, target))
	defer server.Close()

	for _, credentials := range [][]string{nil, {"Bearer wrong"}, {"Bearer demo-secret", "Bearer wrong"}, {"Bearer demo-secret"}, {"Bearer demo-secret"}} {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/mcp?organization=other", strings.NewReader(requestBody))
		if err != nil {
			t.Fatal(err)
		}
		for _, credential := range credentials {
			req.Header.Add("Authorization", credential)
		}
		req.Header.Set("Cookie", "corporate_session=do_not_forward")
		req.Header.Set("X-Buildkite-Readonly", "false")
		req.Header.Set("X-Buildkite-Toolsets", "builds")
		req.Header.Set("Mcp-Protocol-Version", "2025-03-26")
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(credentials) != 1 || credentials[0] != "Bearer demo-secret" {
			if resp.StatusCode != http.StatusUnauthorized || exchanges.Load() != 0 || upstreamCalls.Load() != 0 {
				t.Fatal("unauthenticated request was not rejected before exchange/proxying")
			}
			continue
		}
		if resp.StatusCode != http.StatusOK || string(body) != responseBody || resp.Header.Get("Content-Type") != "text/event-stream" {
			t.Fatalf("MCP response was not preserved: status=%d body=%q", resp.StatusCode, body)
		}
	}
	if exchanges.Load() != 1 || upstreamCalls.Load() != 2 {
		t.Fatalf("two MCP requests should reuse one token: exchanges=%d upstream=%d", exchanges.Load(), upstreamCalls.Load())
	}
}
