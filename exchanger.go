package tokenexchange

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// assertionTTL is how long the signed JWT assertion is valid. The Buildkite
// docs require exp to be within 5 minutes of iat.
const assertionTTL = 5 * time.Minute

// httpBodyPreviewLen bounds how much of an unexpected response body is included
// in an error message.
const httpBodyPreviewLen = 256

// maxTokenResponseBodyLen bounds memory used when reading a token endpoint
// response. OAuth token and error responses are expected to be small JSON
// documents.
const maxTokenResponseBodyLen = 64 << 10

// maxTokenExpiresInSeconds is the largest whole-second lifetime that can be
// represented by time.Duration without overflow.
const maxTokenExpiresInSeconds int64 = (1<<63 - 1) / int64(time.Second)

// Exchanger mints Buildkite API tokens by signing a JWT assertion (RFC 7523)
// and exchanging it via the OAuth 2.0 Token Exchange grant (RFC 8693).
//
// An Exchanger performs a network round-trip on every call to [Exchanger.Token].
// Wrap it in a [CachedSource] (or build a client with [NewClient]) so tokens are
// cached and reused until close to expiry, as recommended by the Buildkite docs.
type Exchanger struct {
	// ClientID is the Token Exchange application's client ID. It is used as
	// both the iss and sub claims of the signed assertion. Required.
	ClientID string

	// OrgSlug is the Buildkite organization slug (from the URL, not the
	// display name). It is sent as the request "audience" parameter. Required.
	OrgSlug string

	// UserEmail is the email of the Buildkite user to act as. It is sent as
	// the "subject_token". The user must be an active organization member with
	// a verified email. Required.
	UserEmail string

	// PrivateKey signs the JWT assertion. Must be an *rsa.PrivateKey (RS256) or
	// a P-256 *ecdsa.PrivateKey (ES256). Required.
	PrivateKey crypto.Signer

	// KeyID is the JWK "kid" placed in the JWT header so Buildkite can select
	// the matching key in your JWKS. Optional but recommended.
	KeyID string

	// Scopes is the list of scopes requested for the minted token. If empty,
	// the application's default scopes are used.
	Scopes []string

	// ExpiresIn optionally requests a token TTL, capped by the application's
	// maximum. If zero, the application's maximum TTL is used.
	ExpiresIn time.Duration

	// Endpoint is the token endpoint URL. Defaults to [DefaultEndpoint]. It is
	// also used as the JWT "aud" claim.
	Endpoint string

	// HTTPClient performs the token request. Defaults to http.DefaultClient.
	HTTPClient *http.Client

	// now returns the current time; overridable in tests. Defaults to time.Now.
	now func() time.Time
	// newJTI generates the JWT ID; overridable in tests. Defaults to a random
	// 128-bit hex string.
	newJTI func() (string, error)
}

func (e *Exchanger) endpoint() string {
	if e.Endpoint != "" {
		return e.Endpoint
	}
	return DefaultEndpoint
}

func (e *Exchanger) httpClient() *http.Client {
	if e.HTTPClient != nil {
		return e.HTTPClient
	}
	return http.DefaultClient
}

func (e *Exchanger) clock() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now()
}

func (e *Exchanger) validate() error {
	switch {
	case e.ClientID == "":
		return fmt.Errorf("tokenexchange: ClientID is required")
	case e.OrgSlug == "":
		return fmt.Errorf("tokenexchange: OrgSlug is required")
	case e.UserEmail == "":
		return fmt.Errorf("tokenexchange: UserEmail is required")
	case e.PrivateKey == nil:
		return fmt.Errorf("tokenexchange: PrivateKey is required")
	}
	return nil
}

// Token signs an assertion and exchanges it for a freshly minted token. It
// performs a network request on every call; see [CachedSource] for caching.
//
// On an OAuth error response the returned error is a *[TokenError].
func (e *Exchanger) Token(ctx context.Context) (*Token, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}

	assertion, err := e.signAssertion()
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: signing assertion: %w", err)
	}

	return e.exchange(ctx, assertion)
}

func (e *Exchanger) signAssertion() (string, error) {
	jti, err := e.generateJTI()
	if err != nil {
		return "", fmt.Errorf("generating jti: %w", err)
	}

	now := e.clock()
	claims := jwt.MapClaims{
		"iss": e.ClientID,
		"sub": e.ClientID,
		"aud": e.endpoint(),
		"iat": now.Unix(),
		"exp": now.Add(assertionTTL).Unix(),
		"jti": jti,
	}

	var method jwt.SigningMethod
	switch k := e.PrivateKey.(type) {
	case *rsa.PrivateKey:
		method = jwt.SigningMethodRS256
	case *ecdsa.PrivateKey:
		if k.Curve.Params().BitSize != 256 {
			return "", fmt.Errorf("only P-256 ECDSA keys are supported (got P-%d)", k.Curve.Params().BitSize)
		}
		method = jwt.SigningMethodES256
	default:
		return "", fmt.Errorf("unsupported key type %T (want *rsa.PrivateKey or *ecdsa.PrivateKey)", e.PrivateKey)
	}

	t := jwt.NewWithClaims(method, claims)
	if e.KeyID != "" {
		t.Header["kid"] = e.KeyID
	}
	return t.SignedString(e.PrivateKey)
}

func (e *Exchanger) generateJTI() (string, error) {
	if e.newJTI != nil {
		return e.newJTI()
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

type tokenEndpointResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

type tokenEndpointError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func (e *Exchanger) exchange(ctx context.Context, assertion string) (*Token, error) {
	params := url.Values{
		"grant_type":            {grantTypeTokenExchange},
		"client_assertion_type": {clientAssertionTypeJWTBearer},
		"client_assertion":      {assertion},
		"subject_token":         {e.UserEmail},
		"subject_token_type":    {subjectTokenTypeUserEmail},
		"audience":              {e.OrgSlug},
	}
	if len(e.Scopes) > 0 {
		params.Set("scope", strings.Join(e.Scopes, " "))
	}
	if e.ExpiresIn > 0 {
		params.Set("expires_in", fmt.Sprintf("%d", int(e.ExpiresIn.Seconds())))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint(), strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := e.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: token request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBodyLen+1))
	if err != nil {
		return nil, fmt.Errorf("tokenexchange: reading token response: %w", err)
	}
	if len(body) > maxTokenResponseBodyLen {
		return nil, fmt.Errorf("tokenexchange: token response body exceeds %d bytes (HTTP %d)", maxTokenResponseBodyLen, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		var oauthErr tokenEndpointError
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
			return nil, &TokenError{
				Code:        oauthErr.Error,
				Description: oauthErr.Description,
				StatusCode:  resp.StatusCode,
			}
		}
		preview := string(body)
		if len(preview) > httpBodyPreviewLen {
			preview = preview[:httpBodyPreviewLen] + "…"
		}
		return nil, fmt.Errorf("tokenexchange: unexpected response HTTP %d: %s", resp.StatusCode, preview)
	}

	var tr tokenEndpointResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("tokenexchange: parsing token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("tokenexchange: token endpoint returned empty access_token")
	}
	if tr.IssuedTokenType != issuedTokenTypeAccessToken {
		return nil, fmt.Errorf("tokenexchange: token endpoint returned unexpected issued_token_type %q", tr.IssuedTokenType)
	}
	if !strings.EqualFold(tr.TokenType, "Bearer") {
		return nil, fmt.Errorf("tokenexchange: token endpoint returned unexpected token_type %q", tr.TokenType)
	}
	if tr.ExpiresIn <= 0 {
		return nil, fmt.Errorf("tokenexchange: token endpoint returned invalid expires_in %d", tr.ExpiresIn)
	}
	if tr.ExpiresIn > maxTokenExpiresInSeconds {
		return nil, fmt.Errorf("tokenexchange: token endpoint returned expires_in %d exceeding the supported maximum", tr.ExpiresIn)
	}

	tok := &Token{
		accessToken: tr.AccessToken,
		tokenType:   "Bearer",
		expiresAt:   e.clock().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}
	if tr.Scope != "" {
		tok.scopes = strings.Fields(tr.Scope)
	}
	return tok, nil
}
