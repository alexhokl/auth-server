package jwthelper_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexhokl/auth-server/jwthelper"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

// Mock client implementation for testing
type mockClient struct {
	id          string
	secret      string
	domain      string
	isPublic    bool
	redirectURI string
}

func (c *mockClient) GetID() string     { return c.id }
func (c *mockClient) GetSecret() string { return c.secret }
func (c *mockClient) GetDomain() string { return c.domain }
func (c *mockClient) IsPublic() bool    { return c.isPublic }
func (c *mockClient) GetUserID() string { return "" }

// Mock token info implementation for testing
type mockTokenInfo struct {
	clientID         string
	userID           string
	accessCreateAt   time.Time
	accessExpiresIn  time.Duration
	refreshCreateAt  time.Time
	refreshExpiresIn time.Duration
	scope            string
}

func (t *mockTokenInfo) New() oauth2.TokenInfo                                    { return &mockTokenInfo{} }
func (t *mockTokenInfo) GetClientID() string                                      { return t.clientID }
func (t *mockTokenInfo) SetClientID(clientID string)                              { t.clientID = clientID }
func (t *mockTokenInfo) GetUserID() string                                        { return t.userID }
func (t *mockTokenInfo) SetUserID(userID string)                                  { t.userID = userID }
func (t *mockTokenInfo) GetRedirectURI() string                                   { return "" }
func (t *mockTokenInfo) SetRedirectURI(redirectURI string)                        {}
func (t *mockTokenInfo) GetScope() string                                         { return t.scope }
func (t *mockTokenInfo) SetScope(scope string)                                    { t.scope = scope }
func (t *mockTokenInfo) GetCode() string                                          { return "" }
func (t *mockTokenInfo) SetCode(code string)                                      {}
func (t *mockTokenInfo) GetCodeCreateAt() time.Time                               { return time.Time{} }
func (t *mockTokenInfo) SetCodeCreateAt(createAt time.Time)                       {}
func (t *mockTokenInfo) GetCodeExpiresIn() time.Duration                          { return 0 }
func (t *mockTokenInfo) SetCodeExpiresIn(exp time.Duration)                       {}
func (t *mockTokenInfo) GetCodeChallenge() string                                 { return "" }
func (t *mockTokenInfo) SetCodeChallenge(challenge string)                        {}
func (t *mockTokenInfo) GetCodeChallengeMethod() oauth2.CodeChallengeMethod       { return "" }
func (t *mockTokenInfo) SetCodeChallengeMethod(method oauth2.CodeChallengeMethod) {}
func (t *mockTokenInfo) GetAccess() string                                        { return "" }
func (t *mockTokenInfo) SetAccess(access string)                                  {}
func (t *mockTokenInfo) GetAccessCreateAt() time.Time                             { return t.accessCreateAt }
func (t *mockTokenInfo) SetAccessCreateAt(createAt time.Time)                     { t.accessCreateAt = createAt }
func (t *mockTokenInfo) GetAccessExpiresIn() time.Duration                        { return t.accessExpiresIn }
func (t *mockTokenInfo) SetAccessExpiresIn(exp time.Duration)                     { t.accessExpiresIn = exp }
func (t *mockTokenInfo) GetRefresh() string                                       { return "" }
func (t *mockTokenInfo) SetRefresh(refresh string)                                {}
func (t *mockTokenInfo) GetRefreshCreateAt() time.Time                            { return t.refreshCreateAt }
func (t *mockTokenInfo) SetRefreshCreateAt(createAt time.Time)                    { t.refreshCreateAt = createAt }
func (t *mockTokenInfo) GetRefreshExpiresIn() time.Duration                       { return t.refreshExpiresIn }
func (t *mockTokenInfo) SetRefreshExpiresIn(exp time.Duration)                    { t.refreshExpiresIn = exp }

func generateTestECDSAKey() *ecdsa.PrivateKey {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key
}

func TestNewEcKeyJWTGenerator(t *testing.T) {
	key := generateTestECDSAKey()

	generator := jwthelper.NewEcKeyJWTGenerator("test-kid", key, jwt.SigningMethodES256)

	assert.NotNil(t, generator)
}

func TestEcKeyJWTGenerator_Token_GeneratesValidAccessToken(t *testing.T) {
	key := generateTestECDSAKey()
	generator := jwthelper.NewEcKeyJWTGenerator("test-kid", key, jwt.SigningMethodES256)

	req := httptest.NewRequest(http.MethodGet, "https://auth.example.com/token", nil)

	client := &mockClient{
		id:     "test-client",
		secret: "secret",
	}

	tokenInfo := &mockTokenInfo{
		clientID:        "test-client",
		userID:          "user@test.com",
		accessCreateAt:  time.Now(),
		accessExpiresIn: time.Hour,
	}

	data := &oauth2.GenerateBasic{
		Client:    client,
		UserID:    "user@test.com",
		TokenInfo: tokenInfo,
		Request:   req,
	}

	access, refresh, err := generator.Token(context.Background(), data, false)

	assert.NoError(t, err)
	assert.NotEmpty(t, access)
	assert.Empty(t, refresh) // refresh should be empty when isGenRefresh is false

	// Verify the token can be parsed
	token, err := jwt.Parse(access, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)
}

func TestEcKeyJWTGenerator_Token_GeneratesRefreshToken(t *testing.T) {
	key := generateTestECDSAKey()
	generator := jwthelper.NewEcKeyJWTGenerator("test-kid", key, jwt.SigningMethodES256)

	req := httptest.NewRequest(http.MethodGet, "https://auth.example.com/token", nil)

	client := &mockClient{
		id:     "test-client",
		secret: "secret",
	}

	tokenInfo := &mockTokenInfo{
		clientID:        "test-client",
		userID:          "user@test.com",
		accessCreateAt:  time.Now(),
		accessExpiresIn: time.Hour,
	}

	data := &oauth2.GenerateBasic{
		Client:    client,
		UserID:    "user@test.com",
		TokenInfo: tokenInfo,
		Request:   req,
	}

	access, refresh, err := generator.Token(context.Background(), data, true)

	assert.NoError(t, err)
	assert.NotEmpty(t, access)
	assert.NotEmpty(t, refresh) // refresh should be generated when isGenRefresh is true
}

func TestEcKeyJWTGenerator_Token_ContainsCorrectClaims(t *testing.T) {
	key := generateTestECDSAKey()
	generator := jwthelper.NewEcKeyJWTGenerator("test-kid", key, jwt.SigningMethodES256)

	req := httptest.NewRequest(http.MethodGet, "http://auth.example.com/token", nil)

	client := &mockClient{
		id:     "test-client",
		secret: "secret",
	}

	createAt := time.Now()
	expiresIn := time.Hour

	tokenInfo := &mockTokenInfo{
		clientID:        "test-client",
		userID:          "user@test.com",
		accessCreateAt:  createAt,
		accessExpiresIn: expiresIn,
	}

	data := &oauth2.GenerateBasic{
		Client:    client,
		UserID:    "user@test.com",
		TokenInfo: tokenInfo,
		Request:   req,
	}

	access, _, err := generator.Token(context.Background(), data, false)

	assert.NoError(t, err)

	// Parse and verify claims
	token, err := jwt.ParseWithClaims(access, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	assert.NoError(t, err)

	claims, ok := token.Claims.(*jwt.StandardClaims)
	assert.True(t, ok)
	assert.Equal(t, "test-client", claims.Audience)
	assert.Equal(t, "user@test.com", claims.Subject)
	assert.Equal(t, "http://auth.example.com", claims.Issuer)
	assert.Equal(t, createAt.Unix(), claims.IssuedAt)
	assert.Equal(t, createAt.Add(expiresIn).Unix(), claims.ExpiresAt)
}

func TestEcKeyJWTGenerator_Token_IncludesKidInHeader(t *testing.T) {
	key := generateTestECDSAKey()
	kid := "my-key-id-123"
	generator := jwthelper.NewEcKeyJWTGenerator(kid, key, jwt.SigningMethodES256)

	req := httptest.NewRequest(http.MethodGet, "https://auth.example.com/token", nil)

	client := &mockClient{id: "test-client"}
	tokenInfo := &mockTokenInfo{
		accessCreateAt:  time.Now(),
		accessExpiresIn: time.Hour,
	}

	data := &oauth2.GenerateBasic{
		Client:    client,
		UserID:    "user@test.com",
		TokenInfo: tokenInfo,
		Request:   req,
	}

	access, _, err := generator.Token(context.Background(), data, false)

	assert.NoError(t, err)

	// Parse token without validation to check header
	token, _, _ := new(jwt.Parser).ParseUnverified(access, &jwt.StandardClaims{})
	assert.Equal(t, kid, token.Header["kid"])
}

func TestEcKeyJWTGenerator_Token_NoKidWhenEmpty(t *testing.T) {
	key := generateTestECDSAKey()
	generator := jwthelper.NewEcKeyJWTGenerator("", key, jwt.SigningMethodES256)

	req := httptest.NewRequest(http.MethodGet, "https://auth.example.com/token", nil)

	client := &mockClient{id: "test-client"}
	tokenInfo := &mockTokenInfo{
		accessCreateAt:  time.Now(),
		accessExpiresIn: time.Hour,
	}

	data := &oauth2.GenerateBasic{
		Client:    client,
		UserID:    "user@test.com",
		TokenInfo: tokenInfo,
		Request:   req,
	}

	access, _, err := generator.Token(context.Background(), data, false)

	assert.NoError(t, err)

	// Parse token without validation to check header
	token, _, _ := new(jwt.Parser).ParseUnverified(access, &jwt.StandardClaims{})
	_, hasKid := token.Header["kid"]
	assert.False(t, hasKid)
}

func TestEcKeyJWTGenerator_Token_DifferentCallsProduceDifferentRefreshTokens(t *testing.T) {
	key := generateTestECDSAKey()
	generator := jwthelper.NewEcKeyJWTGenerator("test-kid", key, jwt.SigningMethodES256)

	req := httptest.NewRequest(http.MethodGet, "https://auth.example.com/token", nil)

	client := &mockClient{id: "test-client"}
	tokenInfo := &mockTokenInfo{
		accessCreateAt:  time.Now(),
		accessExpiresIn: time.Hour,
	}

	data := &oauth2.GenerateBasic{
		Client:    client,
		UserID:    "user@test.com",
		TokenInfo: tokenInfo,
		Request:   req,
	}

	_, refresh1, _ := generator.Token(context.Background(), data, true)
	_, refresh2, _ := generator.Token(context.Background(), data, true)

	// Refresh tokens should be different due to UUID generation
	assert.NotEqual(t, refresh1, refresh2)
}

// Test with models.Client to ensure compatibility with go-oauth2 library
func TestEcKeyJWTGenerator_Token_WithModelsClient(t *testing.T) {
	key := generateTestECDSAKey()
	generator := jwthelper.NewEcKeyJWTGenerator("test-kid", key, jwt.SigningMethodES256)

	req := httptest.NewRequest(http.MethodGet, "https://auth.example.com/token", nil)

	// Use the actual models.Client from go-oauth2
	client := &models.Client{
		ID:     "real-client",
		Secret: "real-secret",
		Domain: "https://example.com",
		Public: false,
	}

	tokenInfo := &models.Token{
		ClientID:        "real-client",
		UserID:          "user@test.com",
		AccessCreateAt:  time.Now(),
		AccessExpiresIn: time.Hour,
	}

	data := &oauth2.GenerateBasic{
		Client:    client,
		UserID:    "user@test.com",
		TokenInfo: tokenInfo,
		Request:   req,
	}

	access, _, err := generator.Token(context.Background(), data, false)

	assert.NoError(t, err)
	assert.NotEmpty(t, access)
}
