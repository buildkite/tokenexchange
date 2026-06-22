package tokenexchange

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

// fakeEndpoint returns an httptest.Server that validates the exchange request
// and the signed assertion, then responds with a token.
func fakeEndpoint(t *testing.T, key *rsa.PrivateKey, expiresIn int) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)

		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))

		if got := form.Get("grant_type"); got != grantTypeTokenExchange {
			t.Errorf("grant_type = %q", got)
		}
		if got := form.Get("subject_token_type"); got != subjectTokenTypeUserEmail {
			t.Errorf("subject_token_type = %q", got)
		}
		if got := form.Get("subject_token"); got != "user@example.com" {
			t.Errorf("subject_token = %q", got)
		}
		if got := form.Get("audience"); got != "my-org" {
			t.Errorf("audience = %q", got)
		}

		// Verify the client assertion signature and claims.
		tok, err := jwt.Parse(form.Get("client_assertion"), func(*jwt.Token) (any, error) {
			return &key.PublicKey, nil
		}, jwt.WithValidMethods([]string{"RS256"}))
		if err != nil {
			t.Errorf("parsing assertion: %v", err)
		} else {
			claims := tok.Claims.(jwt.MapClaims)
			if claims["iss"] != "client-id" || claims["sub"] != "client-id" {
				t.Errorf("iss/sub = %v/%v", claims["iss"], claims["sub"])
			}
			if claims["jti"] == nil || claims["jti"] == "" {
				t.Errorf("missing jti")
			}
		}
		if kid := tok.Header["kid"]; kid != "key-1" {
			t.Errorf("kid header = %v", kid)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenEndpointResponse{
			AccessToken:     "bktx_secret",
			IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
			TokenType:       "Bearer",
			ExpiresIn:       expiresIn,
			Scope:           "read_pipelines read_builds",
		}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func newExchanger(key *rsa.PrivateKey, endpoint string) *Exchanger {
	return &Exchanger{
		ClientID:   "client-id",
		OrgSlug:    "my-org",
		UserEmail:  "user@example.com",
		KeyID:      "key-1",
		Scopes:     []string{"read_pipelines", "read_builds"},
		PrivateKey: key,
		Endpoint:   endpoint,
	}
}

func TestExchangerToken(t *testing.T) {
	key := testKey(t)
	srv, _ := fakeEndpoint(t, key, 3600)

	tok, err := newExchanger(key, srv.URL).Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken() != "bktx_secret" {
		t.Errorf("AccessToken = %q", tok.AccessToken())
	}
	if tok.Type() != "Bearer" {
		t.Errorf("Type = %q", tok.Type())
	}
	if got := strings.Join(tok.Scopes(), " "); got != "read_pipelines read_builds" {
		t.Errorf("Scopes = %q", got)
	}
	if d := time.Until(tok.Expiry()); d < 50*time.Minute || d > time.Hour {
		t.Errorf("Expiry in %v, want ~1h", d)
	}
}

func TestValidateRequiredFields(t *testing.T) {
	_, err := (&Exchanger{OrgSlug: "x", UserEmail: "y", PrivateKey: testKey(t)}).Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ClientID") {
		t.Fatalf("want ClientID validation error, got %v", err)
	}
}

func TestTokenScopesReturnsCopy(t *testing.T) {
	tok := &Token{scopes: []string{"read_pipelines", "read_builds"}}

	scopes := tok.Scopes()
	scopes[0] = "mutated"

	if got := strings.Join(tok.Scopes(), " "); got != "read_pipelines read_builds" {
		t.Errorf("Scopes = %q, want original scopes", got)
	}
}

func TestTokenErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(tokenEndpointError{
			Error:       ErrCodeInvalidScope,
			Description: "Requested scopes exceed grantable scopes",
		}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}))
	defer srv.Close()

	_, err := newExchanger(testKey(t), srv.URL).Token(context.Background())
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("want *TokenError, got %T: %v", err, err)
	}
	if te.Code != ErrCodeInvalidScope || te.StatusCode != http.StatusBadRequest {
		t.Errorf("TokenError = %+v", te)
	}
}

func TestCachedSourceReusesToken(t *testing.T) {
	key := testKey(t)
	srv, calls := fakeEndpoint(t, key, 3600)
	src := NewCachedSource(newExchanger(key, srv.URL))

	for i := 0; i < 3; i++ {
		if _, err := src.Token(context.Background()); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("endpoint called %d times, want 1 (cached)", got)
	}
}

func TestCachedSourceRefreshesWithinGrace(t *testing.T) {
	key := testKey(t)
	// 30s TTL with a 60s grace window => always considered stale => refetch.
	srv, calls := fakeEndpoint(t, key, 30)
	src := NewCachedSourceGrace(newExchanger(key, srv.URL), 60*time.Second)

	for i := 0; i < 2; i++ {
		if _, err := src.Token(context.Background()); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Errorf("endpoint called %d times, want 2 (always within grace)", got)
	}
}

func TestCachedSourceWarnsOnShortTTL(t *testing.T) {
	key := testKey(t)
	// 30s TTL with a 60s grace => token is always stale => cache thrash.
	srv, _ := fakeEndpoint(t, key, 30)

	var buf bytes.Buffer
	src := NewCachedSourceGrace(newExchanger(key, srv.URL), 60*time.Second)
	src.Logger = slog.New(slog.NewTextHandler(&buf, nil))

	for i := 0; i < 3; i++ {
		if _, err := src.Token(context.Background()); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}

	if n := strings.Count(buf.String(), "caching is ineffective"); n != 1 {
		t.Errorf("warning logged %d times, want exactly 1; log=%q", n, buf.String())
	}
}

func TestCachedSourceNoWarnOnHealthyTTL(t *testing.T) {
	key := testKey(t)
	srv, _ := fakeEndpoint(t, key, 3600)

	var buf bytes.Buffer
	src := NewCachedSource(newExchanger(key, srv.URL))
	src.Logger = slog.New(slog.NewTextHandler(&buf, nil))

	if _, err := src.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected log output: %q", buf.String())
	}
}

func TestCachedSourceNilSourceReturnsError(t *testing.T) {
	_, err := NewCachedSource(nil).Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "CachedSource source is nil") {
		t.Fatalf("want nil source error, got %v", err)
	}
}

func TestNilCachedSourceReturnsError(t *testing.T) {
	var src *CachedSource
	_, err := src.Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "CachedSource is nil") {
		t.Fatalf("want nil CachedSource error, got %v", err)
	}
}

func TestTransportInjectsBearer(t *testing.T) {
	key := testKey(t)
	exSrv, _ := fakeEndpoint(t, key, 3600)

	var gotAuth string
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer apiSrv.Close()

	client := NewClient(NewCachedSource(newExchanger(key, exSrv.URL)))
	resp, err := client.Get(apiSrv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()

	if gotAuth != "Bearer bktx_secret" {
		t.Errorf("Authorization = %q", gotAuth)
	}
}

func TestExpiresInParameter(t *testing.T) {
	key := testKey(t)
	var gotExpiresIn string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		gotExpiresIn = form.Get("expires_in")
		if err := json.NewEncoder(w).Encode(tokenEndpointResponse{AccessToken: "bktx_x", TokenType: "Bearer", ExpiresIn: 600}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}))
	defer srv.Close()

	ex := newExchanger(key, srv.URL)
	ex.ExpiresIn = 10 * time.Minute
	if _, err := ex.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if gotExpiresIn != "600" {
		t.Errorf("expires_in = %q, want 600", gotExpiresIn)
	}
}
