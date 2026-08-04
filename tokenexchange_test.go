package tokenexchange

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
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

func testECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	return key
}

func privateKeyPKCS8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling PKCS#8 private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

type staticSource struct {
	calls int32
}

func (s *staticSource) Token(context.Context) (*Token, error) {
	atomic.AddInt32(&s.calls, 1)
	return &Token{accessToken: "bktx_secret", tokenType: "Bearer"}, nil
}

type sourceFunc func(context.Context) (*Token, error)

func (f sourceFunc) Token(ctx context.Context) (*Token, error) {
	return f(ctx)
}

type tokenResult struct {
	token *Token
	err   error
}

type countingReader struct {
	bytesRead int
}

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.bytesRead += len(p)
	return len(p), nil
}

type errorReader struct {
	err error
}

func (r *errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type trackingBody struct {
	closed bool
}

func (*trackingBody) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}

type signalingContext struct {
	context.Context
	entered chan<- struct{}
}

func (c signalingContext) Done() <-chan struct{} {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	return c.Context.Done()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// fakeEndpoint returns an httptest.Server that validates the exchange request
// and the signed assertion, then responds with a token.
func fakeEndpoint(t *testing.T, key crypto.Signer, expiresIn int) (*httptest.Server, *int32) {
	t.Helper()
	var algorithm string
	switch key.(type) {
	case *rsa.PrivateKey:
		algorithm = "RS256"
	case *ecdsa.PrivateKey:
		algorithm = "ES256"
	default:
		t.Fatalf("unsupported test key type %T", key)
	}

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
			return key.Public(), nil
		}, jwt.WithValidMethods([]string{algorithm}))
		if err != nil {
			t.Errorf("parsing assertion: %v", err)
		} else {
			if got := tok.Method.Alg(); got != algorithm {
				t.Errorf("signing algorithm = %q, want %q", got, algorithm)
			}
			claims := tok.Claims.(jwt.MapClaims)
			if claims["iss"] != "client-id" || claims["sub"] != "client-id" {
				t.Errorf("iss/sub = %v/%v", claims["iss"], claims["sub"])
			}
			if claims["jti"] == nil || claims["jti"] == "" {
				t.Errorf("missing jti")
			}
			if kid := tok.Header["kid"]; kid != "key-1" {
				t.Errorf("kid header = %v", kid)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenEndpointResponse{
			AccessToken:     "bktx_secret",
			IssuedTokenType: issuedTokenTypeAccessToken,
			TokenType:       "Bearer",
			ExpiresIn:       int64(expiresIn),
			Scope:           "read_pipelines read_builds",
		}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func newExchanger(key crypto.Signer, endpoint string) *Exchanger {
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
	tests := []struct {
		name string
		key  crypto.Signer
	}{
		{name: "RS256", key: testKey(t)},
		{name: "ES256", key: testECKey(t, elliptic.P256())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := fakeEndpoint(t, tt.key, 3600)

			tok, err := newExchanger(tt.key, srv.URL).Token(context.Background())
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
		})
	}
}

func TestExchangerAssertionDefaults(t *testing.T) {
	now := time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)
	ex := newExchanger(testKey(t), "")
	ex.now = func() time.Time { return now }
	ex.randRead = func(p []byte) (int, error) {
		for i := range p {
			p[i] = 0xab
		}
		return len(p), nil
	}

	assertion, err := ex.signAssertion()
	if err != nil {
		t.Fatalf("signAssertion: %v", err)
	}
	parsed, err := jwt.Parse(assertion, func(*jwt.Token) (any, error) {
		return ex.PrivateKey.Public(), nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
	if err != nil {
		t.Fatalf("parsing assertion: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if got := claims["aud"]; got != DefaultEndpoint {
		t.Errorf("aud = %v, want %q", got, DefaultEndpoint)
	}
	if got := claims["iat"]; got != float64(now.Unix()) {
		t.Errorf("iat = %v, want %d", got, now.Unix())
	}
	if got := claims["exp"]; got != float64(now.Add(assertionTTL).Unix()) {
		t.Errorf("exp = %v, want %d", got, now.Add(assertionTTL).Unix())
	}
	if got := claims["jti"]; got != strings.Repeat("ab", 16) {
		t.Errorf("jti = %v, want deterministic value", got)
	}
}

func TestExchangerAssertionRandomError(t *testing.T) {
	randomErr := errors.New("random source unavailable")
	ex := newExchanger(testKey(t), "https://token.example.test")
	ex.randRead = func([]byte) (int, error) { return 0, randomErr }

	_, err := ex.Token(context.Background())
	if !errors.Is(err, randomErr) || !strings.Contains(err.Error(), "signing assertion: generating jti") {
		t.Fatalf("Token error = %v, want wrapped random source error", err)
	}
}

func TestParsePrivateKey(t *testing.T) {
	rsaKey := testKey(t)
	ecKey := testECKey(t, elliptic.P256())
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshaling SEC 1 private key: %v", err)
	}

	tests := []struct {
		name   string
		pem    []byte
		signer crypto.Signer
	}{
		{
			name:   "RSA PKCS#1",
			pem:    pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}),
			signer: rsaKey,
		},
		{name: "RSA PKCS#8", pem: privateKeyPKCS8PEM(t, rsaKey), signer: rsaKey},
		{
			name:   "ECDSA SEC 1",
			pem:    pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}),
			signer: ecKey,
		},
		{name: "ECDSA PKCS#8", pem: privateKeyPKCS8PEM(t, ecKey), signer: ecKey},
		{name: "Ed25519 PKCS#8", pem: privateKeyPKCS8PEM(t, edKey), signer: edKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePrivateKey(tt.pem)
			if err != nil {
				t.Fatalf("ParsePrivateKey: %v", err)
			}
			if reflect.TypeOf(got) != reflect.TypeOf(tt.signer) {
				t.Errorf("signer type = %T, want %T", got, tt.signer)
			}
			if !reflect.DeepEqual(got.Public(), tt.signer.Public()) {
				t.Errorf("public key does not match original")
			}
		})
	}
}

func TestLoadPrivateKey(t *testing.T) {
	key := testKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "private.pem")
	if err := os.WriteFile(path, privateKeyPKCS8PEM(t, key), 0o600); err != nil {
		t.Fatalf("writing private key: %v", err)
	}

	got, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if !reflect.DeepEqual(got.Public(), key.Public()) {
		t.Errorf("public key does not match original")
	}

	if _, err := LoadPrivateKey(filepath.Join(dir, "missing.pem")); err == nil || !strings.Contains(err.Error(), "reading private key") {
		t.Fatalf("missing file error = %v, want reading private key error", err)
	}
}

func TestParsePrivateKeyErrors(t *testing.T) {
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating X25519 key: %v", err)
	}

	tests := []struct {
		name    string
		pem     []byte
		wantErr string
	}{
		{name: "no PEM block", pem: []byte("not PEM"), wantErr: "no PEM block found"},
		{
			name:    "invalid DER",
			pem:     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")}),
			wantErr: "unable to parse private key",
		},
		{
			name:    "PKCS#8 non-signer",
			pem:     privateKeyPKCS8PEM(t, x25519Key),
			wantErr: "does not implement crypto.Signer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParsePrivateKey(tt.pem); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ParsePrivateKey error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestExchangerRejectsUnsupportedPrivateKeys(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	tests := []struct {
		name    string
		key     crypto.Signer
		wantErr string
	}{
		{name: "ECDSA P-384", key: testECKey(t, elliptic.P384()), wantErr: "only P-256 ECDSA keys are supported"},
		{name: "Ed25519", key: edKey, wantErr: "unsupported key type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newExchanger(tt.key, "https://token.example.test").Token(context.Background()); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Token error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRequiredFields(t *testing.T) {
	key := testKey(t)
	tests := []struct {
		name  string
		field string
		clear func(*Exchanger)
	}{
		{name: "ClientID", field: "ClientID", clear: func(ex *Exchanger) { ex.ClientID = "" }},
		{name: "OrgSlug", field: "OrgSlug", clear: func(ex *Exchanger) { ex.OrgSlug = "" }},
		{name: "UserEmail", field: "UserEmail", clear: func(ex *Exchanger) { ex.UserEmail = "" }},
		{name: "PrivateKey", field: "PrivateKey", clear: func(ex *Exchanger) { ex.PrivateKey = nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := newExchanger(key, "https://token.example.test")
			tt.clear(ex)
			if _, err := ex.Token(context.Background()); err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("Token error = %v, want %s validation error", err, tt.field)
			}
		})
	}
}

func TestValidateExpiresIn(t *testing.T) {
	key := testKey(t)
	tests := []struct {
		name      string
		expiresIn time.Duration
		wantErr   string
	}{
		{name: "negative", expiresIn: -time.Second, wantErr: "ExpiresIn must not be negative"},
		{name: "sub-second", expiresIn: 500 * time.Millisecond, wantErr: "ExpiresIn must be at least 1s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := newExchanger(key, "https://token.example.test")
			ex.ExpiresIn = tt.expiresIn
			if _, err := ex.Token(context.Background()); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Token error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestTokenErrorFormatting(t *testing.T) {
	tests := []struct {
		name string
		err  *TokenError
		want string
	}{
		{
			name: "with description",
			err:  &TokenError{Code: ErrCodeInvalidScope, Description: "scope denied", StatusCode: http.StatusBadRequest},
			want: "tokenexchange: invalid_scope: scope denied (HTTP 400)",
		},
		{
			name: "without description",
			err:  &TokenError{Code: ErrCodeInvalidClient, StatusCode: http.StatusUnauthorized},
			want: "tokenexchange: invalid_client (HTTP 401)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
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

func TestTokenResponseBodyLimit(t *testing.T) {
	body := &countingReader{}
	ex := newExchanger(testKey(t), "https://token.example.test")
	ex.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(body),
			Request:    req,
		}, nil
	})}

	_, err := ex.Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "token response body exceeds 65536 bytes") {
		t.Fatalf("Token error = %v, want response body limit error", err)
	}
	if got, want := body.bytesRead, maxTokenResponseBodyLen+1; got != want {
		t.Errorf("read %d response bytes, want %d", got, want)
	}
}

func TestTokenExchangeFailures(t *testing.T) {
	key := testKey(t)
	responseClient := func(status int, body io.ReadCloser) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: status,
				Header:     make(http.Header),
				Body:       body,
				Request:    req,
			}, nil
		})}
	}

	t.Run("building request", func(t *testing.T) {
		_, err := newExchanger(key, "://invalid").Token(context.Background())
		if err == nil || !strings.Contains(err.Error(), "building request") {
			t.Fatalf("Token error = %v, want building request error", err)
		}
	})

	t.Run("performing request", func(t *testing.T) {
		requestErr := errors.New("request failed")
		ex := newExchanger(key, "https://token.example.test")
		ex.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, requestErr
		})}
		if _, err := ex.Token(context.Background()); !errors.Is(err, requestErr) || !strings.Contains(err.Error(), "token request") {
			t.Fatalf("Token error = %v, want wrapped request error", err)
		}
	})

	t.Run("reading response", func(t *testing.T) {
		readErr := errors.New("response read failed")
		ex := newExchanger(key, "https://token.example.test")
		ex.HTTPClient = responseClient(http.StatusOK, io.NopCloser(&errorReader{err: readErr}))
		if _, err := ex.Token(context.Background()); !errors.Is(err, readErr) || !strings.Contains(err.Error(), "reading token response") {
			t.Fatalf("Token error = %v, want wrapped response read error", err)
		}
	})

	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{
			name:    "unexpected response",
			status:  http.StatusTeapot,
			body:    "not an OAuth error",
			wantErr: "unexpected response HTTP 418: not an OAuth error",
		},
		{
			name:    "long unexpected response",
			status:  http.StatusInternalServerError,
			body:    strings.Repeat("x", httpBodyPreviewLen+1),
			wantErr: strings.Repeat("x", httpBodyPreviewLen) + "…",
		},
		{
			name:    "malformed success response",
			status:  http.StatusOK,
			body:    "{",
			wantErr: "parsing token response",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := newExchanger(key, "https://token.example.test")
			ex.HTTPClient = responseClient(tt.status, io.NopCloser(strings.NewReader(tt.body)))
			if _, err := ex.Token(context.Background()); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Token error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestTokenResponseValidation(t *testing.T) {
	valid := tokenEndpointResponse{
		AccessToken:     "bktx_secret",
		IssuedTokenType: issuedTokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       3600,
	}
	emptyAccessToken := valid
	emptyAccessToken.AccessToken = ""
	missingIssuedType := valid
	missingIssuedType.IssuedTokenType = ""
	unexpectedIssuedType := valid
	unexpectedIssuedType.IssuedTokenType = "urn:ietf:params:oauth:token-type:refresh_token"
	missingTokenType := valid
	missingTokenType.TokenType = ""
	unexpectedTokenType := valid
	unexpectedTokenType.TokenType = "MAC"
	zeroExpiry := valid
	zeroExpiry.ExpiresIn = 0
	negativeExpiry := valid
	negativeExpiry.ExpiresIn = -1
	overflowingExpiry := valid
	overflowingExpiry.ExpiresIn = maxTokenExpiresInSeconds + 1
	lowercaseBearer := valid
	lowercaseBearer.TokenType = "bearer"

	tests := []struct {
		name     string
		response tokenEndpointResponse
		wantErr  string
	}{
		{name: "empty access token", response: emptyAccessToken, wantErr: "empty access_token"},
		{name: "missing issued token type", response: missingIssuedType, wantErr: `unexpected issued_token_type ""`},
		{name: "unexpected issued token type", response: unexpectedIssuedType, wantErr: "unexpected issued_token_type"},
		{name: "missing token type", response: missingTokenType, wantErr: `unexpected token_type ""`},
		{name: "unexpected token type", response: unexpectedTokenType, wantErr: `unexpected token_type "MAC"`},
		{name: "zero expiry", response: zeroExpiry, wantErr: "invalid expires_in 0"},
		{name: "negative expiry", response: negativeExpiry, wantErr: "invalid expires_in -1"},
		{name: "overflowing expiry", response: overflowingExpiry, wantErr: "exceeding the supported maximum"},
		{name: "case-insensitive bearer", response: lowercaseBearer},
	}

	key := testKey(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewEncoder(w).Encode(tt.response); err != nil {
					t.Errorf("encoding response: %v", err)
				}
			}))
			defer srv.Close()

			tok, err := newExchanger(key, srv.URL).Token(context.Background())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Token error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Token: %v", err)
			}
			if tok.Type() != "Bearer" {
				t.Errorf("Type = %q, want normalized Bearer", tok.Type())
			}
		})
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

func TestCachedSourceInvalidatesOnlyCurrentToken(t *testing.T) {
	oldToken := &Token{accessToken: "bktx_old", expiresAt: time.Now().Add(time.Hour)}
	newToken := &Token{accessToken: "bktx_new", expiresAt: time.Now().Add(time.Hour)}
	var calls int32
	inner := NewCachedSource(sourceFunc(func(context.Context) (*Token, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return oldToken, nil
		}
		return newToken, nil
	}))
	src := NewCachedSource(inner)

	var nilSource *CachedSource
	nilSource.InvalidateToken(oldToken)
	src.InvalidateToken(nil)

	if tok, err := src.Token(context.Background()); err != nil || tok != oldToken {
		t.Fatalf("initial Token = (%v, %v), want old token", tok, err)
	}
	src.InvalidateToken(oldToken)
	if tok, err := src.Token(context.Background()); err != nil || tok != newToken {
		t.Fatalf("Token after invalidation = (%v, %v), want new token", tok, err)
	}

	src.InvalidateToken(oldToken)
	if tok, err := src.Token(context.Background()); err != nil || tok != newToken {
		t.Fatalf("Token after stale invalidation = (%v, %v), want new token", tok, err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("source called %d times, want 2", got)
	}
}

func TestNewCachedSourceGraceTreatsNegativeAsZero(t *testing.T) {
	src := NewCachedSourceGrace(&staticSource{}, -time.Second)
	if src.grace != 0 {
		t.Errorf("grace = %s, want zero", src.grace)
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

func TestCachedSourceUsesUnexpiredTokenDuringRefreshBackoff(t *testing.T) {
	now := time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)
	oldToken := &Token{accessToken: "bktx_old", expiresAt: now.Add(30 * time.Second)}
	newToken := &Token{accessToken: "bktx_new", expiresAt: now.Add(time.Hour)}
	refreshErr := errors.New("token endpoint unavailable")
	var calls int32
	source := sourceFunc(func(context.Context) (*Token, error) {
		switch atomic.AddInt32(&calls, 1) {
		case 1:
			return oldToken, nil
		case 2, 3:
			return nil, refreshErr
		default:
			return newToken, nil
		}
	})

	var logs bytes.Buffer
	src := NewCachedSourceGrace(source, time.Minute)
	src.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	src.now = func() time.Time { return now }

	if tok, err := src.Token(context.Background()); err != nil || tok != oldToken {
		t.Fatalf("initial Token = (%v, %v), want old token", tok, err)
	}
	if tok, err := src.Token(context.Background()); err != nil || tok != oldToken {
		t.Fatalf("failed refresh Token = (%v, %v), want old token", tok, err)
	}
	if tok, err := src.Token(context.Background()); err != nil || tok != oldToken {
		t.Fatalf("backoff Token = (%v, %v), want old token", tok, err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("source called %d times during first backoff, want 2", got)
	}

	now = now.Add(time.Second)
	if tok, err := src.Token(context.Background()); err != nil || tok != oldToken {
		t.Fatalf("second failed refresh Token = (%v, %v), want old token", tok, err)
	}
	now = now.Add(time.Second)
	if tok, err := src.Token(context.Background()); err != nil || tok != oldToken {
		t.Fatalf("second backoff Token = (%v, %v), want old token", tok, err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("source called %d times during second backoff, want 3", got)
	}

	now = now.Add(time.Second)
	if tok, err := src.Token(context.Background()); err != nil || tok != newToken {
		t.Fatalf("recovered Token = (%v, %v), want new token", tok, err)
	}
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Errorf("source called %d times, want 4", got)
	}
	if got := strings.Count(logs.String(), "token refresh failed; using cached token"); got != 2 {
		t.Errorf("refresh failure logged %d times, want 2; log=%q", got, logs.String())
	}
	if got := strings.Count(logs.String(), "token refresh recovered"); got != 1 {
		t.Errorf("refresh recovery logged %d times, want 1; log=%q", got, logs.String())
	}
}

func TestRefreshRetryBackoff(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{failures: 1, want: time.Second},
		{failures: 2, want: 2 * time.Second},
		{failures: 5, want: 16 * time.Second},
		{failures: 6, want: 30 * time.Second},
		{failures: 100, want: 30 * time.Second},
	}
	for _, tt := range tests {
		if got := refreshRetryBackoff(tt.failures); got != tt.want {
			t.Errorf("refreshRetryBackoff(%d) = %s, want %s", tt.failures, got, tt.want)
		}
	}
}

func TestCachedSourceCapsRefreshBackoffAtExpiry(t *testing.T) {
	now := time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)
	oldToken := &Token{accessToken: "bktx_old", expiresAt: now.Add(500 * time.Millisecond)}
	refreshErr := errors.New("token endpoint unavailable")
	var calls int32
	source := sourceFunc(func(context.Context) (*Token, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return oldToken, nil
		}
		return nil, refreshErr
	})
	src := NewCachedSourceGrace(source, time.Minute)
	src.now = func() time.Time { return now }

	if _, err := src.Token(context.Background()); err != nil {
		t.Fatalf("initial Token: %v", err)
	}
	if tok, err := src.Token(context.Background()); err != nil || tok != oldToken {
		t.Fatalf("failed refresh Token = (%v, %v), want old token", tok, err)
	}
	if !src.retryAt.Equal(oldToken.expiresAt) {
		t.Errorf("retryAt = %s, want token expiry %s", src.retryAt, oldToken.expiresAt)
	}
}

func TestCachedSourceReturnsRefreshErrorAfterExpiry(t *testing.T) {
	now := time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)
	oldToken := &Token{accessToken: "bktx_old", expiresAt: now.Add(time.Second)}
	refreshErr := errors.New("token endpoint unavailable")
	var calls int32
	source := sourceFunc(func(context.Context) (*Token, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return oldToken, nil
		}
		now = now.Add(time.Second)
		return nil, refreshErr
	})
	src := NewCachedSourceGrace(source, time.Minute)
	src.now = func() time.Time { return now }

	if _, err := src.Token(context.Background()); err != nil {
		t.Fatalf("initial Token: %v", err)
	}
	if _, err := src.Token(context.Background()); !errors.Is(err, refreshErr) {
		t.Fatalf("Token error = %v, want %v", err, refreshErr)
	}
}

func TestCachedSourceDoesNotMaskCanceledRefresh(t *testing.T) {
	now := time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)
	oldToken := &Token{accessToken: "bktx_old", expiresAt: now.Add(30 * time.Second)}
	var calls int32
	source := sourceFunc(func(ctx context.Context) (*Token, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return oldToken, nil
		}
		return nil, ctx.Err()
	})
	src := NewCachedSourceGrace(source, time.Minute)
	src.now = func() time.Time { return now }

	if _, err := src.Token(context.Background()); err != nil {
		t.Fatalf("initial Token: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Token(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Token error = %v, want context.Canceled", err)
	}
}

func TestCachedSourceServesUnexpiredTokenDuringRefresh(t *testing.T) {
	now := time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)
	oldToken := &Token{accessToken: "bktx_old", expiresAt: now.Add(30 * time.Second)}
	refreshErr := errors.New("token endpoint unavailable")
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var calls int32
	source := sourceFunc(func(context.Context) (*Token, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return oldToken, nil
		}
		close(refreshStarted)
		<-releaseRefresh
		return nil, refreshErr
	})
	src := NewCachedSourceGrace(source, time.Minute)
	src.now = func() time.Time { return now }

	if _, err := src.Token(context.Background()); err != nil {
		t.Fatalf("initial Token: %v", err)
	}

	refreshResult := make(chan tokenResult, 1)
	go func() {
		tok, err := src.Token(context.Background())
		refreshResult <- tokenResult{token: tok, err: err}
	}()
	<-refreshStarted

	cachedResult := make(chan tokenResult, 1)
	go func() {
		tok, err := src.Token(context.Background())
		cachedResult <- tokenResult{token: tok, err: err}
	}()
	select {
	case result := <-cachedResult:
		if result.err != nil || result.token != oldToken {
			t.Fatalf("Token during refresh = (%v, %v), want old token", result.token, result.err)
		}
	case <-time.After(time.Second):
		close(releaseRefresh)
		<-refreshResult
		t.Fatal("Token blocked behind proactive refresh")
	}

	close(releaseRefresh)
	result := <-refreshResult
	if result.err != nil || result.token != oldToken {
		t.Fatalf("failed refresh Token = (%v, %v), want old token", result.token, result.err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("source called %d times, want one initial mint and one failed refresh", got)
	}
}

func TestCachedSourceWaitingForRefreshHonorsContext(t *testing.T) {
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	tok := &Token{accessToken: "bktx_new", expiresAt: time.Now().Add(time.Hour)}
	var calls int32
	source := sourceFunc(func(context.Context) (*Token, error) {
		atomic.AddInt32(&calls, 1)
		close(refreshStarted)
		<-releaseRefresh
		return tok, nil
	})
	src := NewCachedSource(source)

	refreshResult := make(chan tokenResult, 1)
	go func() {
		got, err := src.Token(context.Background())
		refreshResult <- tokenResult{token: got, err: err}
	}()
	<-refreshStarted

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Token(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting Token error = %v, want context.Canceled", err)
	}

	close(releaseRefresh)
	result := <-refreshResult
	if result.err != nil || result.token != tok {
		t.Fatalf("refresh Token = (%v, %v), want new token", result.token, result.err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("source called %d times, want 1", got)
	}
}

func TestCachedSourceRetriesAfterRefreshCallerCanceled(t *testing.T) {
	firstRefreshStarted := make(chan struct{})
	newToken := &Token{accessToken: "bktx_new", expiresAt: time.Now().Add(time.Hour)}
	var calls int32
	source := sourceFunc(func(ctx context.Context) (*Token, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(firstRefreshStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return newToken, nil
	})
	src := NewCachedSource(source)

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan tokenResult, 1)
	go func() {
		tok, err := src.Token(firstCtx)
		firstResult <- tokenResult{token: tok, err: err}
	}()
	<-firstRefreshStarted

	secondBaseCtx, cancelSecond := context.WithTimeout(context.Background(), time.Second)
	defer cancelSecond()
	secondEntered := make(chan struct{}, 1)
	secondCtx := signalingContext{Context: secondBaseCtx, entered: secondEntered}
	secondResult := make(chan tokenResult, 1)
	go func() {
		tok, err := src.Token(secondCtx)
		secondResult <- tokenResult{token: tok, err: err}
	}()

	<-secondEntered
	cancelFirst()
	if result := <-firstResult; !errors.Is(result.err, context.Canceled) {
		t.Fatalf("first Token error = %v, want context.Canceled", result.err)
	}
	result := <-secondResult
	if result.err != nil || result.token != newToken {
		t.Fatalf("second Token = (%v, %v), want new token", result.token, result.err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("source called %d times, want canceled and successful refreshes", got)
	}
}

func TestCachedSourceSharesRefreshResult(t *testing.T) {
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	tok := &Token{accessToken: "bktx_new", expiresAt: time.Now().Add(time.Hour)}
	var calls int32
	source := sourceFunc(func(context.Context) (*Token, error) {
		atomic.AddInt32(&calls, 1)
		close(refreshStarted)
		<-releaseRefresh
		return tok, nil
	})
	src := NewCachedSource(source)

	firstResult := make(chan tokenResult, 1)
	go func() {
		got, err := src.Token(context.Background())
		firstResult <- tokenResult{token: got, err: err}
	}()
	<-refreshStarted

	secondBaseCtx, cancelSecond := context.WithTimeout(context.Background(), time.Second)
	defer cancelSecond()
	secondEntered := make(chan struct{}, 1)
	secondCtx := signalingContext{Context: secondBaseCtx, entered: secondEntered}
	secondResult := make(chan tokenResult, 1)
	go func() {
		got, err := src.Token(secondCtx)
		secondResult <- tokenResult{token: got, err: err}
	}()
	<-secondEntered
	close(releaseRefresh)

	for i, resultCh := range []<-chan tokenResult{firstResult, secondResult} {
		result := <-resultCh
		if result.err != nil || result.token != tok {
			t.Errorf("Token caller %d = (%v, %v), want new token", i+1, result.token, result.err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("source called %d times, want 1", got)
	}
}

func TestCachedSourceRecoversAfterSourcePanic(t *testing.T) {
	tok := &Token{accessToken: "bktx_new", expiresAt: time.Now().Add(time.Hour)}
	var calls int32
	source := sourceFunc(func(context.Context) (*Token, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			panic("source panic")
		}
		return tok, nil
	})
	src := NewCachedSource(source)

	func() {
		defer func() {
			if recovered := recover(); recovered != "source panic" {
				t.Errorf("recovered %v, want source panic", recovered)
			}
		}()
		_, _ = src.Token(context.Background())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := src.Token(ctx)
	if err != nil || got != tok {
		t.Fatalf("Token after panic = (%v, %v), want new token", got, err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("source called %d times, want panic and successful refreshes", got)
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

	client := NewClient(NewCachedSource(newExchanger(key, exSrv.URL)), apiSrv.URL)
	resp, err := client.Get(apiSrv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()

	if gotAuth != "Bearer bktx_secret" {
		t.Errorf("Authorization = %q", gotAuth)
	}
}

func TestTransportAuthenticationErrorsCloseRequestBody(t *testing.T) {
	sourceErr := errors.New("source failed")
	tests := []struct {
		name    string
		source  Source
		wantErr string
	}{
		{name: "nil source", wantErr: "Transport.Source is nil"},
		{
			name: "source error",
			source: sourceFunc(func(context.Context) (*Token, error) {
				return nil, sourceErr
			}),
			wantErr: "obtaining token: source failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &trackingBody{}
			req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v2/jobs", body)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			transport := &Transport{
				Source:         tt.source,
				AllowedOrigins: []string{"https://api.example.com"},
				Base: roundTripFunc(func(*http.Request) (*http.Response, error) {
					t.Fatal("base transport should not be called")
					return nil, nil
				}),
			}

			if _, err := transport.RoundTrip(req); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("RoundTrip error = %v, want containing %q", err, tt.wantErr)
			}
			if !body.closed {
				t.Error("request body was not closed")
			}
		})
	}
}

func TestTransportInvalidatesCachedTokenAfterUnauthorized(t *testing.T) {
	oldToken := &Token{accessToken: "bktx_old", expiresAt: time.Now().Add(time.Hour)}
	newToken := &Token{accessToken: "bktx_new", expiresAt: time.Now().Add(time.Hour)}
	var sourceCalls int32
	source := NewCachedSource(sourceFunc(func(context.Context) (*Token, error) {
		if atomic.AddInt32(&sourceCalls, 1) == 1 {
			return oldToken, nil
		}
		return newToken, nil
	}))

	var requestCalls int32
	var gotAuth []string
	transport := &Transport{
		Source:         source,
		AllowedOrigins: []string{"https://api.example.com"},
		Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gotAuth = append(gotAuth, req.Header.Get("Authorization"))
			status := http.StatusOK
			if atomic.AddInt32(&requestCalls, 1) == 1 {
				status = http.StatusUnauthorized
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		}),
	}

	for i, wantStatus := range []int{http.StatusUnauthorized, http.StatusOK} {
		req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v2/user", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i+1, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != wantStatus {
			t.Errorf("response %d status = %d, want %d", i+1, resp.StatusCode, wantStatus)
		}
		if i == 0 && atomic.LoadInt32(&requestCalls) != 1 {
			t.Fatal("unauthorized request was retried")
		}
	}

	if got := strings.Join(gotAuth, ","); got != "Bearer bktx_old,Bearer bktx_new" {
		t.Errorf("Authorization headers = %q", got)
	}
	if got := atomic.LoadInt32(&sourceCalls); got != 2 {
		t.Errorf("source called %d times, want 2", got)
	}
}

func TestTransportScopesBearerToAllowedOrigins(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		allowedOrigins []string
		wantAuth       string
		wantCalls      int32
	}{
		{
			name:      "REST API",
			url:       "https://api.buildkite.com/v2/user",
			wantAuth:  "Bearer bktx_secret",
			wantCalls: 1,
		},
		{
			name:      "GraphQL API",
			url:       "https://graphql.buildkite.com/v1",
			wantAuth:  "Bearer bktx_secret",
			wantCalls: 1,
		},
		{
			name:      "Package Registries",
			url:       "https://packages.buildkite.com/my-org/my-registry/files/file-1.0.0.tgz",
			wantAuth:  "Bearer bktx_secret",
			wantCalls: 1,
		},
		{
			name: "HTTP downgrade",
			url:  "http://api.buildkite.com/v2/user",
		},
		{
			name: "unrelated origin",
			url:  "https://example.com",
		},
		{
			name:           "custom origin",
			url:            "https://buildkite.example.com/v2/user",
			allowedOrigins: []string{"https://buildkite.example.com"},
			wantAuth:       "Bearer bktx_secret",
			wantCalls:      1,
		},
		{
			name:           "custom origins replace defaults",
			url:            "https://api.buildkite.com/v2/user",
			allowedOrigins: []string{"https://buildkite.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &staticSource{}
			var gotAuth string
			transport := &Transport{
				Source:         source,
				AllowedOrigins: tt.allowedOrigins,
				Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					gotAuth = req.Header.Get("Authorization")
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader("")),
						Request:    req,
					}, nil
				}),
			}

			req, err := http.NewRequest(http.MethodGet, tt.url, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			_ = resp.Body.Close()

			if gotAuth != tt.wantAuth {
				t.Errorf("Authorization = %q, want %q", gotAuth, tt.wantAuth)
			}
			if got := atomic.LoadInt32(&source.calls); got != tt.wantCalls {
				t.Errorf("source called %d times, want %d", got, tt.wantCalls)
			}
		})
	}
}

func TestTransportDoesNotAuthenticateCrossOriginRedirect(t *testing.T) {
	source := &staticSource{}
	var redirectedAuth string
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer redirected.Close()

	var originAuth string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originAuth = r.Header.Get("Authorization")
		http.Redirect(w, r, redirected.URL, http.StatusFound)
	}))
	defer origin.Close()

	client := NewClient(source, origin.URL)
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()

	if originAuth != "Bearer bktx_secret" {
		t.Errorf("origin Authorization = %q", originAuth)
	}
	if redirectedAuth != "" {
		t.Errorf("redirected Authorization = %q, want no credential", redirectedAuth)
	}
	if got := atomic.LoadInt32(&source.calls); got != 1 {
		t.Errorf("source called %d times, want 1", got)
	}
}

func TestExpiresInParameter(t *testing.T) {
	key := testKey(t)
	var gotExpiresIn string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		gotExpiresIn = form.Get("expires_in")
		if err := json.NewEncoder(w).Encode(tokenEndpointResponse{
			AccessToken:     "bktx_x",
			IssuedTokenType: issuedTokenTypeAccessToken,
			TokenType:       "Bearer",
			ExpiresIn:       600,
		}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}))
	defer srv.Close()

	ex := newExchanger(key, srv.URL)
	ex.ExpiresIn = 1500 * time.Millisecond
	if _, err := ex.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if gotExpiresIn != "1" {
		t.Errorf("expires_in = %q, want 1", gotExpiresIn)
	}
}
