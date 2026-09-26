package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	oauthErrors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// HandleInternalError Tests

func TestHandleInternalError_KnownErrorsAreBadRequest(t *testing.T) {
	knownErrors := []error{
		oauthErrors.ErrInvalidRedirectURI,
		oauthErrors.ErrInvalidAuthorizeCode,
		oauthErrors.ErrInvalidAccessToken,
		oauthErrors.ErrInvalidRefreshToken,
		oauthErrors.ErrExpiredAccessToken,
		oauthErrors.ErrExpiredRefreshToken,
		oauthErrors.ErrMissingCodeVerifier,
		oauthErrors.ErrMissingCodeChallenge,
		oauthErrors.ErrInvalidCodeChallenge,
	}

	for _, err := range knownErrors {
		t.Run(err.Error(), func(t *testing.T) {
			res := HandleInternalError(context.Background(), err)

			assert.NotNil(t, res)
			assert.Equal(t, http.StatusBadRequest, res.StatusCode)
			assert.Equal(t, err, res.Error)
			assert.Equal(t, err.Error(), res.Description)
		})
	}
}

func TestHandleInternalError_UnknownErrorIsInternalServerError(t *testing.T) {
	err := errors.New("some unexpected failure")

	res := HandleInternalError(context.Background(), err)

	assert.NotNil(t, res)
	assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
	assert.Equal(t, err, res.Error)
	assert.Equal(t, err.Error(), res.Description)
}

// OpenID configuration metadata Tests

func TestGetResponseTypes(t *testing.T) {
	assert.Equal(t, []string{"code", "token"}, getResponseTypes())
}

// The grant types advertised have to match those allowed by the OAuth server
// in server.GetRouter.
func TestGetGrantTypes(t *testing.T) {
	assert.Equal(
		t,
		[]string{"authorization_code", "client_credentials", "refresh_token"},
		getGrantTypes(),
	)
}

func TestGetTokenEndpointSupportedAuthMethods(t *testing.T) {
	assert.Equal(
		t,
		[]string{"client_secret_basic", "client_secret_post"},
		getTokenEndpointSupportedAuthMethods(),
	)
}

func TestGetCodeChallengeMethodsSupported(t *testing.T) {
	assert.Equal(t, []string{"S256"}, getCodeChallengeMethodsSupported())
}

// JSON web key set Tests

func getTestJSONWebKeySet(t *testing.T, keyID string, key *ecdsa.PrivateKey) JSONWebKeySet {
	t.Helper()

	router := gin.New()
	router.GET("/jwks", GetJSONWebKeySetHandler(keyID, key))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/jwks", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var set JSONWebKeySet
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &set))

	return set
}

func TestGetJSONWebKeySetHandler_DescribesKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	set := getTestJSONWebKeySet(t, "test-key-id", key)

	assert.Len(t, set.Keys, 1)
	assert.Equal(t, "EC", set.Keys[0].Kty)
	assert.Equal(t, "sig", set.Keys[0].Use)
	assert.Equal(t, "ES256", set.Keys[0].Alg)
	assert.Equal(t, "P-256", set.Keys[0].Crv)
}

// The key ID has to be published as tokens are signed with a key ID in their
// header.
func TestGetJSONWebKeySetHandler_ContainsKeyID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	set := getTestJSONWebKeySet(t, "test-key-id", key)

	assert.Len(t, set.Keys, 1)
	assert.Equal(t, "test-key-id", set.Keys[0].Kid)
}

func TestGetJSONWebKeySetHandler_CoordinatesMatchKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	set := getTestJSONWebKeySet(t, "test-key-id", key)
	assert.Len(t, set.Keys, 1)

	x, err := base64.RawURLEncoding.DecodeString(set.Keys[0].X)
	assert.NoError(t, err)
	assert.Equal(t, key.X.Bytes(), x)

	y, err := base64.RawURLEncoding.DecodeString(set.Keys[0].Y)
	assert.NoError(t, err)
	assert.Equal(t, key.Y.Bytes(), y)
}

// see https://www.rfc-editor.org/rfc/rfc7515#section-2 on the requirement of
// base64url encoding without padding
func TestGetJSONWebKeySetHandler_CoordinatesAreNotPadded(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	set := getTestJSONWebKeySet(t, "test-key-id", key)
	assert.Len(t, set.Keys, 1)

	assert.NotContains(t, set.Keys[0].X, "=")
	assert.NotContains(t, set.Keys[0].Y, "=")
	assert.NotContains(t, set.Keys[0].X, "+")
	assert.NotContains(t, set.Keys[0].X, "/")
}

// WebFinger Tests

func TestGetWebFingerConfiguration(t *testing.T) {
	viper.Set("webfinger_email", "alex@test.com")
	defer viper.Set("webfinger_email", "")

	router := gin.New()
	router.GET("/.well-known/webfinger", GetWebFingerConfiguration)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "http://auth.example.com/.well-known/webfinger", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, strings.HasPrefix(w.Header().Get("Content-Type"), ContentTypeJrdJSON))

	var config WebFingerConfiguration
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &config))

	assert.Equal(t, "acct:alex@test.com", config.Subject)
	assert.Len(t, config.Links, 1)
	assert.Equal(t, "http://openid.net/specs/connect/1.0/issuer", config.Links[0].Rel)
	assert.Equal(t, "http://auth.example.com", config.Links[0].Href)
}
