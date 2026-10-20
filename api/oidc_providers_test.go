package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alexhokl/auth-server/db"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

const oidcTestNonce = "expected-nonce"
const oidcTestKeyID = "test-key"
const oidcTestGoogleClientID = "google-client-id"

const oidcTestOktaIssuer = "https://acme.okta.com/oauth2/default"
const oidcTestMicrosoftTenantID = "11111111-2222-3333-4444-555555555555"

var oidcTestRSAKeys = sync.OnceValue(func() [2]*rsa.PrivateKey {
	var keys [2]*rsa.PrivateKey
	for i := range keys {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		keys[i] = key
	}
	return keys
})

// oidcTestSigningKey is the key a fake provider signs ID tokens with.
func oidcTestSigningKey() *rsa.PrivateKey {
	return oidcTestRSAKeys()[0]
}

// oidcTestRSAKey returns a key other than the signing key.
func oidcTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	return oidcTestRSAKeys()[1]
}

// oidcRoundTripper serves requests with a handler instead of the network.
type oidcRoundTripper struct {
	handler http.Handler
}

func (rt *oidcRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	rt.handler.ServeHTTP(w, r)
	return w.Result(), nil
}

// oidcFakeProvider is a fake external provider which serves discovery, keys,
// tokens and GitHub emails.
type oidcFakeProvider struct {
	issuer   string
	tokenURL string
	jwksURL  string
	// key is the published key, which is the signing key unless replaced
	key             *rsa.PrivateKey
	tokenStatusCode int
	idToken         string
	githubEmails    interface{}
	githubStatus    int

	mu            sync.Mutex
	tokenRequests []url.Values
}

func oidcTestIDTokenClaims(issuer string, audience string, email string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":            issuer,
		"aud":            audience,
		"sub":            "1234567890",
		"email":          email,
		"email_verified": true,
		"nonce":          oidcTestNonce,
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
}

func oidcNewFakeProvider(t *testing.T, issuer string, tokenURL string, jwksURL string, claims jwt.MapClaims) *oidcFakeProvider {
	t.Helper()
	fake := &oidcFakeProvider{
		issuer:          issuer,
		tokenURL:        tokenURL,
		jwksURL:         jwksURL,
		key:             oidcTestSigningKey(),
		tokenStatusCode: http.StatusOK,
		githubStatus:    http.StatusOK,
	}
	if claims != nil {
		fake.setIDToken(t, claims)
	}
	return fake
}

func (g *oidcFakeProvider) setIDToken(t *testing.T, claims jwt.MapClaims) {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = oidcTestKeyID
	idToken, err := token.SignedString(oidcTestSigningKey())
	assert.NoError(t, err)
	g.idToken = idToken
}

// oidcNewFakeGoogle returns a fake Google which issues an ID token of the
// given email.
func oidcNewFakeGoogle(t *testing.T, email string) *oidcFakeProvider {
	t.Helper()
	return oidcNewFakeProvider(
		t,
		googleIssuer,
		google.Endpoint.TokenURL,
		"https://www.googleapis.com/oauth2/v3/certs",
		oidcTestIDTokenClaims(googleIssuer, oidcTestGoogleClientID, email),
	)
}

func oidcNewFakeApple(t *testing.T, email string) *oidcFakeProvider {
	t.Helper()
	return oidcNewFakeProvider(
		t,
		appleIssuer,
		appleEndpoint.TokenURL,
		"https://appleid.apple.com/auth/keys",
		oidcTestIDTokenClaims(appleIssuer, "com.example.signin", email),
	)
}

func oidcNewFakeOkta(t *testing.T, email string) *oidcFakeProvider {
	t.Helper()
	return oidcNewFakeProvider(
		t,
		oidcTestOktaIssuer,
		oidcTestOktaIssuer+"/v1/token",
		oidcTestOktaIssuer+"/v1/keys",
		oidcTestIDTokenClaims(oidcTestOktaIssuer, "okta-client-id", email),
	)
}

// oidcNewFakeMicrosoft returns a fake Microsoft of an application of the
// given tenant which issues an ID token of a user of tenant tid.
func oidcNewFakeMicrosoft(t *testing.T, tenant string, tid string, email string) *oidcFakeProvider {
	t.Helper()
	claims := oidcTestIDTokenClaims(
		"https://login.microsoftonline.com/"+tid+"/v2.0",
		"microsoft-client-id",
		email,
	)
	delete(claims, "email_verified")
	claims["tid"] = tid
	return oidcNewFakeProvider(
		t,
		"",
		"https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/token",
		"https://login.microsoftonline.com/"+tenant+"/discovery/v2.0/keys",
		claims,
	)
}

func oidcNewFakeGitHub(t *testing.T, emails interface{}) *oidcFakeProvider {
	t.Helper()
	fake := oidcNewFakeProvider(t, "", github.Endpoint.TokenURL, "", nil)
	fake.githubEmails = emails
	return fake
}

func (g *oidcFakeProvider) lastTokenRequest() url.Values {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.tokenRequests) == 0 {
		return nil
	}
	return g.tokenRequests[len(g.tokenRequests)-1]
}

func (g *oidcFakeProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	requestURL := r.URL.Scheme + "://" + r.URL.Host + r.URL.Path
	switch {
	case g.issuer != "" && requestURL == g.issuer+"/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                g.issuer,
			"authorization_endpoint":                g.issuer + "/v1/authorize",
			"token_endpoint":                        g.tokenURL,
			"jwks_uri":                              g.jwksURL,
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case g.jwksURL != "" && requestURL == g.jwksURL:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": oidcTestKeyID,
					"n":   base64.RawURLEncoding.EncodeToString(g.key.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(g.key.E)).Bytes()),
				},
			},
		})
	case requestURL == g.tokenURL:
		_ = r.ParseForm()
		g.mu.Lock()
		g.tokenRequests = append(g.tokenRequests, r.PostForm)
		g.mu.Unlock()
		if g.tokenStatusCode != http.StatusOK {
			w.WriteHeader(g.tokenStatusCode)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		response := map[string]interface{}{
			"access_token": "access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		if g.idToken != "" {
			response["id_token"] = g.idToken
		}
		_ = json.NewEncoder(w).Encode(response)
	case g.githubEmails != nil && requestURL == githubEmailsURL:
		if r.Header.Get("Authorization") != "Bearer access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if g.githubStatus != http.StatusOK {
			w.WriteHeader(g.githubStatus)
			return
		}
		if raw, ok := g.githubEmails.(string); ok {
			_, _ = w.Write([]byte(raw))
			return
		}
		_ = json.NewEncoder(w).Encode(g.githubEmails)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func oidcFakeContext(fake http.Handler) context.Context {
	client := &http.Client{Transport: &oidcRoundTripper{handler: fake}}
	return context.WithValue(context.Background(), oauth2.HTTPClient, client)
}

// oidcCallbackRequest returns a Google callback request which reaches the
// fake instead of the network.
func oidcCallbackRequest(fake *oidcFakeProvider) *http.Request {
	return oidcProviderCallbackRequest(fake, "google")
}

func oidcProviderCallbackRequest(fake *oidcFakeProvider, name string) *http.Request {
	req, _ := http.NewRequestWithContext(oidcFakeContext(fake), http.MethodGet, "/signin/"+name+"/callback?state=expected-state&code=auth-code", nil)
	return req
}

// oidcFormCallbackRequest returns a callback request posted as a form
// (response_mode=form_post).
func oidcFormCallbackRequest(fake *oidcFakeProvider, name string) *http.Request {
	form := url.Values{}
	form.Set("state", "expected-state")
	form.Set("code", "auth-code")
	form.Set("user", `{"name":{"firstName":"Alex","lastName":"Ho"}}`)
	req, _ := http.NewRequestWithContext(oidcFakeContext(fake), http.MethodPost, "/signin/"+name+"/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func oidcTestApplePEMKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	assert.NoError(t, err)
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func oidcTestClients(t *testing.T) map[OIDCProvider]*db.OidcClient {
	t.Helper()
	_, applePEM := oidcTestApplePEMKey(t)
	return map[OIDCProvider]*db.OidcClient{
		Google: {
			Name:         string(Google),
			ClientID:     oidcTestGoogleClientID,
			ClientSecret: "google-client-secret",
			RedirectURI:  "https://test.com/signin/google/callback",
			ButtonName:   "Sign in with Google",
		},
		GitHub: {
			Name:         string(GitHub),
			ClientID:     "github-client-id",
			ClientSecret: "github-client-secret",
			RedirectURI:  "https://test.com/signin/github/callback",
			ButtonName:   "Sign in with GitHub",
		},
		Apple: {
			Name:         string(Apple),
			ClientID:     "com.example.signin",
			ClientSecret: applePEM,
			RedirectURI:  "https://test.com/signin/apple/callback",
			ButtonName:   "Sign in with Apple",
			TeamID:       "TEAM123",
			KeyID:        "KEY456",
		},
		Okta: {
			Name:         string(Okta),
			ClientID:     "okta-client-id",
			ClientSecret: "okta-client-secret",
			RedirectURI:  "https://test.com/signin/okta/callback",
			ButtonName:   "Sign in with Okta",
			Issuer:       oidcTestOktaIssuer,
		},
		Microsoft: {
			Name:         string(Microsoft),
			ClientID:     "microsoft-client-id",
			ClientSecret: "microsoft-client-secret",
			RedirectURI:  "https://test.com/signin/microsoft/callback",
			ButtonName:   "Sign in with Microsoft",
			Issuer:       "https://login.microsoftonline.com/common/v2.0",
		},
	}
}

func oidcTestClientRowsOf(client *db.OidcClient) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"name", "client_id", "client_secret", "redirect_uri", "button_name", "issuer", "team_id", "key_id"}).
		AddRow(client.Name, client.ClientID, client.ClientSecret, client.RedirectURI, client.ButtonName, client.Issuer, client.TeamID, client.KeyID)
}

func oidcTokenWithIDToken(idToken string) *oauth2.Token {
	return (&oauth2.Token{AccessToken: "access-token"}).WithExtra(map[string]interface{}{
		"id_token": idToken,
	})
}

// getOAuthConfig Tests

func TestGetOAuthConfig_Providers(t *testing.T) {
	clients := oidcTestClients(t)
	tests := []struct {
		provider OIDCProvider
		authURL  string
		tokenURL string
		scopes   []string
	}{
		{Google, google.Endpoint.AuthURL, google.Endpoint.TokenURL, []string{"openid", "profile", "email"}},
		{GitHub, github.Endpoint.AuthURL, github.Endpoint.TokenURL, []string{"read:user", "user:email"}},
		{Apple, "https://appleid.apple.com/auth/authorize", "https://appleid.apple.com/auth/token", []string{"name", "email"}},
		{Okta, oidcTestOktaIssuer + "/v1/authorize", oidcTestOktaIssuer + "/v1/token", []string{"openid", "profile", "email"}},
		{
			Microsoft,
			"https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			"https://login.microsoftonline.com/common/oauth2/v2.0/token",
			[]string{"openid", "profile", "email"},
		},
	}
	for _, test := range tests {
		t.Run(string(test.provider), func(t *testing.T) {
			client := clients[test.provider]
			ctx := oidcFakeContext(oidcNewFakeOkta(t, "alex@test.com"))

			config, provider, err := getOAuthConfig(ctx, client)

			assert.NoError(t, err)
			assert.NotNil(t, provider)
			assert.Equal(t, test.authURL, config.Endpoint.AuthURL)
			assert.Equal(t, test.tokenURL, config.Endpoint.TokenURL)
			assert.Equal(t, test.scopes, config.Scopes)
			assert.Equal(t, client.ClientID, config.ClientID)
			assert.Equal(t, client.ClientSecret, config.ClientSecret)
			assert.Equal(t, client.RedirectURI, config.RedirectURL)
		})
	}
}

func TestGetOAuthConfig_UnsupportedProvider(t *testing.T) {
	for _, name := range []string{"some-provider", "facebook"} {
		t.Run(name, func(t *testing.T) {
			config, provider, err := getOAuthConfig(context.Background(), &db.OidcClient{Name: name})

			assert.Error(t, err)
			assert.Nil(t, config)
			assert.Nil(t, provider)
			assert.Contains(t, err.Error(), name)
		})
	}
}

func TestGetOAuthConfig_OktaDiscoveryFailure_ReturnsError(t *testing.T) {
	ctx := oidcFakeContext(http.NotFoundHandler())

	_, _, err := getOAuthConfig(ctx, oidcTestClients(t)[Okta])

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to discover Okta issuer")
}

func TestGetOAuthConfig_MicrosoftInvalidIssuer_ReturnsError(t *testing.T) {
	client := oidcTestClients(t)[Microsoft]
	client.Issuer = "https://login.microsoftonline.com/contoso.com/v2.0"

	_, _, err := getOAuthConfig(context.Background(), client)

	assert.Error(t, err)
}

// validateOIDCClient Tests

func TestValidateOIDCClient(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(clients map[OIDCProvider]*db.OidcClient) *db.OidcClient
		isValid bool
	}{
		{"google", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient { return c[Google] }, true},
		{"github", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient { return c[GitHub] }, true},
		{"apple", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient { return c[Apple] }, true},
		{"okta", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient { return c[Okta] }, true},
		{"microsoft common", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient { return c[Microsoft] }, true},
		{"microsoft tenant ID", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient {
			c[Microsoft].Issuer = "https://login.microsoftonline.com/" + oidcTestMicrosoftTenantID + "/v2.0"
			return c[Microsoft]
		}, true},
		{"unsupported provider", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient {
			return &db.OidcClient{Name: "facebook"}
		}, false},
		{"apple without team ID", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient {
			c[Apple].TeamID = ""
			return c[Apple]
		}, false},
		{"apple without key ID", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient {
			c[Apple].KeyID = ""
			return c[Apple]
		}, false},
		{"apple with invalid private key", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient {
			c[Apple].ClientSecret = "secret"
			return c[Apple]
		}, false},
		{"okta without issuer", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient {
			c[Okta].Issuer = ""
			return c[Okta]
		}, false},
		{"okta with http issuer", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient {
			c[Okta].Issuer = "http://acme.okta.com"
			return c[Okta]
		}, false},
		{"microsoft without issuer", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient {
			c[Microsoft].Issuer = ""
			return c[Microsoft]
		}, false},
		{"microsoft with domain tenant", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient {
			c[Microsoft].Issuer = "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
			return c[Microsoft]
		}, false},
		{"microsoft with other host", func(c map[OIDCProvider]*db.OidcClient) *db.OidcClient {
			c[Microsoft].Issuer = "https://evil.example.com/common/v2.0"
			return c[Microsoft]
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateOIDCClient(test.modify(oidcTestClients(t)))

			if test.isValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// flexibleBool Tests

func TestFlexibleBool_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
		isValid  bool
	}{
		{`true`, true, true},
		{`false`, false, true},
		{`"true"`, true, true},
		{`"false"`, false, true},
		{`null`, false, true},
		{`"yes"`, false, false},
		{`1`, false, false},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			var value flexibleBool
			err := json.Unmarshal([]byte(test.input), &value)

			if test.isValid {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, bool(value))
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// getEmailFromIDToken Tests

func TestGetEmailFromIDToken_Google_ReturnsEmail(t *testing.T) {
	fake := oidcNewFakeGoogle(t, "alex@test.com")

	email, err := getEmailFromIDToken(oidcFakeContext(fake), googleIssuer, oidcTestClients(t)[Google], oidcTokenWithIDToken(fake.idToken), oidcTestNonce)

	assert.NoError(t, err)
	assert.Equal(t, "alex@test.com", email)
}

func TestGetEmailFromIDToken_Rejections(t *testing.T) {
	tests := []struct {
		name          string
		modify        func(claims jwt.MapClaims)
		clientID      string
		nonce         string
		errorContains string
	}{
		{"other audience", nil, "other-client-id", oidcTestNonce, "unable to verify ID token"},
		{"nonce mismatch", nil, oidcTestGoogleClientID, "other-nonce", "nonce"},
		{"no nonce in session", nil, oidcTestGoogleClientID, "", "nonce"},
		{"no nonce in ID token", func(c jwt.MapClaims) { delete(c, "nonce") }, oidcTestGoogleClientID, oidcTestNonce, "nonce"},
		{"email not verified", func(c jwt.MapClaims) { c["email_verified"] = false }, oidcTestGoogleClientID, oidcTestNonce, "not verified"},
		{"email verified missing", func(c jwt.MapClaims) { delete(c, "email_verified") }, oidcTestGoogleClientID, oidcTestNonce, "not verified"},
		{"no email", func(c jwt.MapClaims) { delete(c, "email") }, oidcTestGoogleClientID, oidcTestNonce, "no email"},
		{"other issuer", func(c jwt.MapClaims) { c["iss"] = "https://evil.example.com" }, oidcTestGoogleClientID, oidcTestNonce, "unable to verify ID token"},
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, oidcTestGoogleClientID, oidcTestNonce, "unable to verify ID token"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := oidcNewFakeGoogle(t, "alex@test.com")
			claims := oidcTestIDTokenClaims(googleIssuer, oidcTestGoogleClientID, "alex@test.com")
			if test.modify != nil {
				test.modify(claims)
			}
			fake.setIDToken(t, claims)
			client := oidcTestClients(t)[Google]
			client.ClientID = test.clientID

			email, err := getEmailFromIDToken(oidcFakeContext(fake), googleIssuer, client, oidcTokenWithIDToken(fake.idToken), test.nonce)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), test.errorContains)
			assert.Empty(t, email)
		})
	}
}

func TestGetEmailFromIDToken_NoIDToken_ReturnsError(t *testing.T) {
	fake := oidcNewFakeGoogle(t, "alex@test.com")

	_, err := getEmailFromIDToken(oidcFakeContext(fake), googleIssuer, oidcTestClients(t)[Google], &oauth2.Token{AccessToken: "access-token"}, oidcTestNonce)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to get ID token")
}

func TestGetEmailFromIDToken_DiscoveryFailure_ReturnsError(t *testing.T) {
	ctx := oidcFakeContext(http.NotFoundHandler())

	_, err := getEmailFromIDToken(ctx, googleIssuer, oidcTestClients(t)[Google], oidcTokenWithIDToken("id-token"), oidcTestNonce)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to get ID token provider")
}

func TestGetEmailFromIDToken_AppleEmailVerifiedAsString(t *testing.T) {
	for _, test := range []struct {
		value   string
		isValid bool
	}{{"true", true}, {"false", false}} {
		t.Run(test.value, func(t *testing.T) {
			fake := oidcNewFakeApple(t, "alex@privaterelay.appleid.com")
			claims := oidcTestIDTokenClaims(appleIssuer, "com.example.signin", "alex@privaterelay.appleid.com")
			claims["email_verified"] = test.value
			fake.setIDToken(t, claims)

			email, err := getEmailFromIDToken(oidcFakeContext(fake), appleIssuer, oidcTestClients(t)[Apple], oidcTokenWithIDToken(fake.idToken), oidcTestNonce)

			if test.isValid {
				assert.NoError(t, err)
				assert.Equal(t, "alex@privaterelay.appleid.com", email)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// getGitHubEmail Tests

type oidcGitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func oidcGetGitHubEmail(t *testing.T, fake *oidcFakeProvider) (string, error) {
	t.Helper()
	ctx := oidcFakeContext(fake)
	config, provider, err := getOAuthConfig(ctx, oidcTestClients(t)[GitHub])
	assert.NoError(t, err)
	return provider.email(ctx, oidcTestClients(t)[GitHub], config, &oauth2.Token{AccessToken: "access-token", TokenType: "Bearer"}, "")
}

func TestGetGitHubEmail_PrimaryVerified_ReturnsEmail(t *testing.T) {
	fake := oidcNewFakeGitHub(t, []oidcGitHubEmail{
		{Email: "other@test.com", Primary: false, Verified: true},
		{Email: "alex@test.com", Primary: true, Verified: true},
	})

	email, err := oidcGetGitHubEmail(t, fake)

	assert.NoError(t, err)
	assert.Equal(t, "alex@test.com", email)
}

func TestGetGitHubEmail_PrimaryNotVerified_ReturnsError(t *testing.T) {
	fake := oidcNewFakeGitHub(t, []oidcGitHubEmail{
		{Email: "alex@test.com", Primary: true, Verified: false},
		{Email: "other@test.com", Primary: false, Verified: true},
	})

	email, err := oidcGetGitHubEmail(t, fake)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no verified primary email")
	assert.Empty(t, email)
}

func TestGetGitHubEmail_ErrorStatus_ReturnsError(t *testing.T) {
	fake := oidcNewFakeGitHub(t, []oidcGitHubEmail{})
	fake.githubStatus = http.StatusForbidden

	_, err := oidcGetGitHubEmail(t, fake)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 403")
}

func TestGetGitHubEmail_InvalidResponse_ReturnsError(t *testing.T) {
	fake := oidcNewFakeGitHub(t, "not json")

	_, err := oidcGetGitHubEmail(t, fake)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse emails")
}

func TestGetGitHubEmail_RequestFailure_ReturnsError(t *testing.T) {
	client := &http.Client{Transport: &oidcFailingRoundTripper{}}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	config, provider, err := getOAuthConfig(ctx, oidcTestClients(t)[GitHub])
	assert.NoError(t, err)

	_, err = provider.email(ctx, oidcTestClients(t)[GitHub], config, &oauth2.Token{AccessToken: "access-token"}, "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to get emails from GitHub")
}

type oidcFailingRoundTripper struct{}

func (oidcFailingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, context.DeadlineExceeded
}

// getMicrosoftEmail Tests

func oidcMicrosoftClient(t *testing.T, tenant string) *db.OidcClient {
	t.Helper()
	client := oidcTestClients(t)[Microsoft]
	client.Issuer = "https://login.microsoftonline.com/" + tenant + "/v2.0"
	return client
}

func TestGetMicrosoftEmail(t *testing.T) {
	tests := []struct {
		name    string
		tenant  string
		tid     string
		modify  func(claims jwt.MapClaims)
		isValid bool
	}{
		{"common, personal account", "common", microsoftConsumersTenantID, nil, true},
		{"consumers, personal account", "consumers", microsoftConsumersTenantID, nil, true},
		{"common, organisation with verified domain owner", "common", oidcTestMicrosoftTenantID, func(c jwt.MapClaims) { c["xms_edov"] = true }, true},
		{"common, organisation with verified domain owner as string", "common", oidcTestMicrosoftTenantID, func(c jwt.MapClaims) { c["xms_edov"] = "true" }, true},
		{"tenant, organisation with verified domain owner", oidcTestMicrosoftTenantID, oidcTestMicrosoftTenantID, func(c jwt.MapClaims) { c["xms_edov"] = true }, true},
		{"common, organisation without verified domain owner", "common", oidcTestMicrosoftTenantID, nil, false},
		{"common, organisation with unverified domain owner", "common", oidcTestMicrosoftTenantID, func(c jwt.MapClaims) { c["xms_edov"] = false }, false},
		{"organizations, personal account", "organizations", microsoftConsumersTenantID, nil, false},
		{"organizations, organisation", "organizations", oidcTestMicrosoftTenantID, func(c jwt.MapClaims) { c["xms_edov"] = true }, true},
		{"consumers, organisation", "consumers", oidcTestMicrosoftTenantID, func(c jwt.MapClaims) { c["xms_edov"] = true }, false},
		{"tenant, other tenant", oidcTestMicrosoftTenantID, microsoftConsumersTenantID, nil, false},
		{"issuer of other tenant", "common", oidcTestMicrosoftTenantID, func(c jwt.MapClaims) {
			c["xms_edov"] = true
			c["iss"] = "https://login.microsoftonline.com/" + microsoftConsumersTenantID + "/v2.0"
		}, false},
		{"no tenant", "common", microsoftConsumersTenantID, func(c jwt.MapClaims) { delete(c, "tid") }, false},
		{"no email", "common", microsoftConsumersTenantID, func(c jwt.MapClaims) { delete(c, "email") }, false},
		{"nonce mismatch", "common", microsoftConsumersTenantID, func(c jwt.MapClaims) { c["nonce"] = "other" }, false},
		{"other audience", "common", microsoftConsumersTenantID, func(c jwt.MapClaims) { c["aud"] = "other" }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := oidcNewFakeMicrosoft(t, test.tenant, test.tid, "alex@test.com")
			claims := oidcTestIDTokenClaims("https://login.microsoftonline.com/"+test.tid+"/v2.0", "microsoft-client-id", "alex@test.com")
			delete(claims, "email_verified")
			claims["tid"] = test.tid
			if test.modify != nil {
				test.modify(claims)
			}
			fake.setIDToken(t, claims)

			email, err := getMicrosoftEmail(oidcFakeContext(fake), oidcMicrosoftClient(t, test.tenant), nil, oidcTokenWithIDToken(fake.idToken), oidcTestNonce)

			if test.isValid {
				assert.NoError(t, err)
				assert.Equal(t, "alex@test.com", email)
			} else {
				assert.Error(t, err)
				assert.Empty(t, email)
			}
		})
	}
}

func TestGetMicrosoftEmail_InvalidIssuer_ReturnsError(t *testing.T) {
	_, err := getMicrosoftEmail(context.Background(), &db.OidcClient{Issuer: "https://evil.example.com"}, nil, oidcTokenWithIDToken("id-token"), oidcTestNonce)

	assert.Error(t, err)
}

// RedirectToOIDCEndpoint Tests of providers

func oidcStartRedirect(t *testing.T, client *db.OidcClient, ctx context.Context) (*httptest.ResponseRecorder, *oidcSession) {
	t.Helper()
	router, _, mock := getTestRouter()
	router.GET("/:action/:oidc_name/start", RedirectToOIDCEndpoint)
	var session *oidcSession
	router.GET("/__oidc_read_session", func(c *gin.Context) {
		session, _ = getOIDCSession(c)
	})

	oidcExpectGetClient(mock, client.Name).WillReturnRows(oidcTestClientRowsOf(client))

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/signin/"+client.Name+"/start", nil)
	router.ServeHTTP(w, req)
	assert.NoError(t, mock.ExpectationsWereMet())

	readReq, _ := http.NewRequest(http.MethodGet, "/__oidc_read_session", nil)
	for _, cookie := range w.Result().Cookies() {
		readReq.AddCookie(cookie)
	}
	router.ServeHTTP(httptest.NewRecorder(), readReq)
	return w, session
}

func TestRedirectToOIDCEndpoint_Providers_ReturnsFound(t *testing.T) {
	tests := []struct {
		provider     OIDCProvider
		host         string
		path         string
		scope        string
		usesNonce    bool
		usesPKCE     bool
		responseMode string
	}{
		{GitHub, "github.com", "/login/oauth/authorize", "read:user user:email", false, true, ""},
		{Apple, "appleid.apple.com", "/auth/authorize", "name email", true, false, "form_post"},
		{Okta, "acme.okta.com", "/oauth2/default/v1/authorize", "openid profile email", true, true, ""},
		{Microsoft, "login.microsoftonline.com", "/common/oauth2/v2.0/authorize", "openid profile email", true, true, ""},
	}
	for _, test := range tests {
		t.Run(string(test.provider), func(t *testing.T) {
			client := oidcTestClients(t)[test.provider]
			ctx := oidcFakeContext(oidcNewFakeOkta(t, "alex@test.com"))

			w, session := oidcStartRedirect(t, client, ctx)

			assert.Equal(t, http.StatusFound, w.Code)
			location, err := url.Parse(w.Header().Get("Location"))
			assert.NoError(t, err)
			assert.Equal(t, test.host, location.Host)
			assert.Equal(t, test.path, location.Path)
			query := location.Query()
			assert.Equal(t, client.ClientID, query.Get("client_id"))
			assert.Equal(t, client.RedirectURI, query.Get("redirect_uri"))
			assert.Equal(t, test.scope, query.Get("scope"))
			assert.Equal(t, test.responseMode, query.Get("response_mode"))
			assert.Empty(t, query.Get("access_type"))
			assert.NotNil(t, session)
			assert.Equal(t, query.Get("state"), session.State)
			if test.usesNonce {
				assert.NotEmpty(t, query.Get("nonce"))
				assert.Equal(t, query.Get("nonce"), session.Nonce)
			} else {
				assert.Empty(t, query.Get("nonce"))
				assert.Empty(t, session.Nonce)
			}
			if test.usesPKCE {
				assert.Equal(t, pkceChallengeMethod, query.Get("code_challenge_method"))
				assert.Equal(t, session.PKCECodeChallenge, query.Get("code_challenge"))
				assert.NotEmpty(t, session.PKCECodeVerifier)
			} else {
				assert.Empty(t, query.Get("code_challenge"))
				assert.Empty(t, session.PKCECodeVerifier)
			}
		})
	}
}

func TestRedirectToOIDCEndpoint_OktaDiscoveryFailure_ReturnsInternalServerError(t *testing.T) {
	w, _ := oidcStartRedirect(t, oidcTestClients(t)[Okta], oidcFakeContext(http.NotFoundHandler()))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// OIDCCallback Tests of providers

func TestOIDCCallback_GitHub_SignsIn(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)
	oidcExpectGetClient(mock, "github").WillReturnRows(oidcTestClientRowsOf(oidcTestClients(t)[GitHub]))
	oidcExpectGetUser(mock, "alex@test.com", true)
	fake := oidcNewFakeGitHub(t, []oidcGitHubEmail{{Email: "alex@test.com", Primary: true, Verified: true}})

	req := oidcProviderCallbackRequest(fake, "github")
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/authorize", w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Equal(t, "alex@test.com", oidcReadAuthenticatedEmail(router, req.Cookies()))
	tokenRequest := fake.lastTokenRequest()
	assert.Equal(t, "verifier", tokenRequest.Get("code_verifier"))
	assert.Equal(t, "auth-code", tokenRequest.Get("code"))
}

func TestOIDCCallback_AppleFormPost_SignsIn(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/signin/:oidc_name/callback", OIDCCallback)
	key, applePEM := oidcTestApplePEMKey(t)
	client := oidcTestClients(t)[Apple]
	client.ClientSecret = applePEM
	oidcExpectGetClient(mock, "apple").WillReturnRows(oidcTestClientRowsOf(client))
	oidcExpectGetUser(mock, "alex@test.com", true)
	fake := oidcNewFakeApple(t, "alex@test.com")

	req := oidcFormCallbackRequest(fake, "apple")
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Equal(t, "alex@test.com", oidcReadAuthenticatedEmail(router, req.Cookies()))

	tokenRequest := fake.lastTokenRequest()
	assert.Equal(t, "auth-code", tokenRequest.Get("code"))
	assert.Empty(t, tokenRequest.Get("code_verifier"))
	assert.Equal(t, "com.example.signin", tokenRequest.Get("client_id"))
	// the client secret is a JWT signed with the private key of the team
	claims := &jwt.RegisteredClaims{}
	secret, err := jwt.ParseWithClaims(tokenRequest.Get("client_secret"), claims, func(*jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	assert.NoError(t, err)
	assert.True(t, secret.Valid)
	assert.Equal(t, "KEY456", secret.Header["kid"])
	assert.Equal(t, "TEAM123", claims.Issuer)
	assert.Equal(t, "com.example.signin", claims.Subject)
}

func TestOIDCCallback_AppleInvalidPrivateKey_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/signin/:oidc_name/callback", OIDCCallback)
	client := oidcTestClients(t)[Apple]
	client.ClientSecret = "not a key"
	oidcExpectGetClient(mock, "apple").WillReturnRows(oidcTestClientRowsOf(client))
	fake := oidcNewFakeApple(t, "alex@test.com")

	req := oidcFormCallbackRequest(fake, "apple")
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Nil(t, fake.lastTokenRequest())
}

func TestOIDCCallback_Okta_SignsIn(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)
	oidcExpectGetClient(mock, "okta").WillReturnRows(oidcTestClientRowsOf(oidcTestClients(t)[Okta]))
	oidcExpectGetUser(mock, "alex@test.com", true)
	fake := oidcNewFakeOkta(t, "alex@test.com")

	req := oidcProviderCallbackRequest(fake, "okta")
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Equal(t, "alex@test.com", oidcReadAuthenticatedEmail(router, req.Cookies()))
	assert.Equal(t, "verifier", fake.lastTokenRequest().Get("code_verifier"))
}

func TestOIDCCallback_Microsoft_SignsIn(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)
	oidcExpectGetClient(mock, "microsoft").WillReturnRows(oidcTestClientRowsOf(oidcTestClients(t)[Microsoft]))
	oidcExpectGetUser(mock, "alex@test.com", true)
	fake := oidcNewFakeMicrosoft(t, "common", microsoftConsumersTenantID, "alex@test.com")

	req := oidcProviderCallbackRequest(fake, "microsoft")
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Equal(t, "alex@test.com", oidcReadAuthenticatedEmail(router, req.Cookies()))
}

func TestOIDCCallback_MicrosoftUnverifiedOrganisationEmail_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)
	oidcExpectGetClient(mock, "microsoft").WillReturnRows(oidcTestClientRowsOf(oidcTestClients(t)[Microsoft]))
	fake := oidcNewFakeMicrosoft(t, "common", oidcTestMicrosoftTenantID, "alex@test.com")

	req := oidcProviderCallbackRequest(fake, "microsoft")
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	// the user is never looked up
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Empty(t, oidcReadAuthenticatedEmail(router, req.Cookies()))
}

func TestOIDCCallback_GoogleEmailNotVerified_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)
	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))
	fake := oidcNewFakeGoogle(t, "alex@test.com")
	claims := oidcTestIDTokenClaims(googleIssuer, oidcTestGoogleClientID, "alex@test.com")
	claims["email_verified"] = false
	fake.setIDToken(t, claims)

	req := oidcCallbackRequest(fake)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Empty(t, oidcReadAuthenticatedEmail(router, req.Cookies()))
}

func TestOIDCCallback_NonceMismatch_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)
	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))
	fake := oidcNewFakeGoogle(t, "alex@test.com")
	claims := oidcTestIDTokenClaims(googleIssuer, oidcTestGoogleClientID, "alex@test.com")
	claims["nonce"] = "replayed-nonce"
	fake.setIDToken(t, claims)

	req := oidcCallbackRequest(fake)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Empty(t, oidcReadAuthenticatedEmail(router, req.Cookies()))
}

func TestOIDCCallback_FormPostStateMismatch_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/signin/:oidc_name/callback", OIDCCallback)

	req := oidcFormCallbackRequest(oidcNewFakeApple(t, "alex@test.com"), "apple")
	w := serveInSession(t, router, oidcSessionValues(t, "other-state"), req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// CreateOIDCClient and UpdateOIDCClient validation Tests

func TestCreateOIDCClient_InvalidClients_ReturnsBadRequest(t *testing.T) {
	bodies := map[string]string{
		"unsupported provider": `{"name":"facebook","client_id":"id","client_secret":"secret","redirect_uri":"https://test.com/cb","button_name":"Facebook"}`,
		"okta without issuer":  `{"name":"okta","client_id":"id","client_secret":"secret","redirect_uri":"https://test.com/cb","button_name":"Okta"}`,
		"microsoft with domain tenant": `{"name":"microsoft","client_id":"id","client_secret":"secret","redirect_uri":"https://test.com/cb","button_name":"Microsoft",` +
			`"issuer":"https://login.microsoftonline.com/contoso.com/v2.0"}`,
		"apple with invalid private key": `{"name":"apple","client_id":"id","client_secret":"secret","redirect_uri":"https://test.com/cb","button_name":"Apple","team_id":"T","key_id":"K"}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			router, _, mock := getTestRouter()
			router.POST("/oidcclients", CreateOIDCClient)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPost, "/oidcclients", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			// nothing is inserted
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestCreateOIDCClient_Apple_ReturnsCreated(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/oidcclients", CreateOIDCClient)
	_, applePEM := oidcTestApplePEMKey(t)
	body, err := json.Marshal(OIDCClientCreateRequest{
		Name:         "apple",
		ClientID:     "com.example.signin",
		ClientSecret: applePEM,
		RedirectURI:  "https://test.com/signin/apple/callback",
		ButtonName:   "Sign in with Apple",
		TeamID:       "TEAM123",
		KeyID:        "KEY456",
	})
	assert.NoError(t, err)

	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO "oidc_clients"`).
		WithArgs("apple", "com.example.signin", applePEM, "https://test.com/signin/apple/callback", "Sign in with Apple", "", "TEAM123", "KEY456").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oidcclients", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	var client OIDCClientResponse
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &client))
	assert.Equal(t, "TEAM123", client.TeamID)
	assert.Equal(t, "KEY456", client.KeyID)
	assert.NotContains(t, w.Body.String(), "PRIVATE KEY")
}

func TestUpdateOIDCClient_InvalidIssuer_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PUT("/oidcclients/:name", UpdateOIDCClient)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/oidcclients/okta", strings.NewReader(`{"client_id":"id","client_secret":"secret","redirect_uri":"https://test.com/cb","button_name":"Okta","issuer":"not a url"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateOIDCClient_Okta_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PUT("/oidcclients/:name", UpdateOIDCClient)

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "oidc_clients" SET`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/oidcclients/okta", strings.NewReader(`{"client_id":"id","client_secret":"secret","redirect_uri":"https://test.com/cb","button_name":"Okta","issuer":"`+oidcTestOktaIssuer+`"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	var client OIDCClientResponse
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &client))
	assert.Equal(t, oidcTestOktaIssuer, client.Issuer)
}
