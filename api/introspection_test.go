package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alexhokl/auth-server/store"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/stretchr/testify/assert"
)

const introspectionTestResourceServerID = "resource-server"
const introspectionTestResourceServerSecret = "resource-secret"
const introspectionTestPublicClientID = "public"

// failingTokenStore is a token store which cannot be reached.
type failingTokenStore struct {
	authzTokenStore
}

func (s *failingTokenStore) GetByAccess(_ context.Context, _ string) (oauth2.TokenInfo, error) {
	return nil, errors.New("connection refused")
}

func (s *failingTokenStore) GetByRefresh(_ context.Context, _ string) (oauth2.TokenInfo, error) {
	return nil, errors.New("connection refused")
}

// introspectionTestRouter returns a router serving the authorization, token
// and introspection endpoints with the given token store.
func introspectionTestRouter(t *testing.T, tokenStore oauth2.TokenStore) *gin.Engine {
	t.Helper()
	srv := authzTestOAuthServer(t)
	manager := srv.Manager.(*manage.Manager)
	manager.MapClientStorage(&authzClientStore{
		clients: map[string]oauth2.ClientInfo{
			authzTestClientID: &models.Client{
				ID:     authzTestClientID,
				Secret: authzTestClientSecret,
				Domain: authzTestRedirectURI,
			},
			introspectionTestResourceServerID: &models.Client{
				ID:     introspectionTestResourceServerID,
				Secret: introspectionTestResourceServerSecret,
			},
			introspectionTestPublicClientID: &models.Client{
				ID:     introspectionTestPublicClientID,
				Secret: "public-secret",
				Public: true,
			},
		},
	})
	manager.MapTokenStorage(tokenStore)

	router := authzTestRouter(t, srv)
	router.POST("/introspect", GetIntrospectionHandler(srv))
	return router
}

func introspectionRequest(t *testing.T, router *gin.Engine, form url.Values, clientID string, clientSecret string) *httptest.ResponseRecorder {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, oidcTestIssuer+"/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func introspectToken(t *testing.T, router *gin.Engine, token string, hint string) IntrospectionResponse {
	t.Helper()
	form := url.Values{}
	form.Set("token", token)
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	w := introspectionRequest(t, router, form, introspectionTestResourceServerID, introspectionTestResourceServerSecret)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

	var response IntrospectionResponse
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	return response
}

func storeTestToken(t *testing.T, tokenStore oauth2.TokenStore, token *models.Token) {
	t.Helper()
	assert.NoError(t, tokenStore.Create(context.Background(), token))
}

// GetIntrospectionHandler Tests

func TestGetIntrospectionHandler_AccessTokenOfUser_ReturnsActive(t *testing.T) {
	router := introspectionTestRouter(t, &authzTokenStore{})
	token := oidcObtainTokens(t, router, "openid email", "")

	response := introspectToken(t, router, token["access_token"].(string), "")

	assert.True(t, response.Active)
	assert.Equal(t, "openid email", response.Scope)
	assert.Equal(t, authzTestClientID, response.ClientID)
	assert.Equal(t, oidcTestEmail, response.Username)
	assert.Equal(t, oidcTestEmail, response.Subject)
	assert.Equal(t, authzTestClientID, response.Audience)
	assert.Equal(t, oidcTestIssuer, response.Issuer)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.NotZero(t, response.IssuedAt)
	assert.Greater(t, response.ExpiresAt, response.IssuedAt)
}

func TestGetIntrospectionHandler_ClientCredentialsToken_ReturnsActiveWithoutUser(t *testing.T) {
	router := introspectionTestRouter(t, &authzTokenStore{})
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	token := oidcTokenRequest(t, router, form)

	response := introspectToken(t, router, token["access_token"].(string), "")

	assert.True(t, response.Active)
	assert.Equal(t, authzTestClientID, response.ClientID)
	assert.Empty(t, response.Username)
	assert.Empty(t, response.Subject)
}

func TestGetIntrospectionHandler_RefreshToken_ReturnsActive(t *testing.T) {
	for _, hint := range []string{"", tokenTypeHintAccessToken, tokenTypeHintRefreshToken} {
		t.Run(hint, func(t *testing.T) {
			router := introspectionTestRouter(t, &authzTokenStore{})
			token := oidcObtainTokens(t, router, "openid", "")

			response := introspectToken(t, router, token["refresh_token"].(string), hint)

			assert.True(t, response.Active)
			assert.Equal(t, tokenTypeHintRefreshToken, response.TokenType)
			assert.Equal(t, oidcTestEmail, response.Subject)
		})
	}
}

func TestGetIntrospectionHandler_AccessTokenWithRefreshHint_ReturnsActive(t *testing.T) {
	router := introspectionTestRouter(t, &authzTokenStore{})
	token := oidcObtainTokens(t, router, "openid", "")

	response := introspectToken(t, router, token["access_token"].(string), tokenTypeHintRefreshToken)

	assert.True(t, response.Active)
	assert.Equal(t, "Bearer", response.TokenType)
}

func TestGetIntrospectionHandler_TokenWithoutExpiry_OmitsExpiry(t *testing.T) {
	tokenStore := &authzTokenStore{}
	router := introspectionTestRouter(t, tokenStore)
	storeTestToken(t, tokenStore, &models.Token{
		ClientID:       authzTestClientID,
		Access:         "never-expires",
		AccessCreateAt: time.Now(),
	})

	response := introspectToken(t, router, "never-expires", "")

	assert.True(t, response.Active)
	assert.Zero(t, response.ExpiresAt)
}

func TestGetIntrospectionHandler_UnknownToken_ReturnsInactive(t *testing.T) {
	router := introspectionTestRouter(t, &authzTokenStore{})

	w := introspectionRequest(t, router, url.Values{"token": {"unknown"}}, introspectionTestResourceServerID, introspectionTestResourceServerSecret)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"active": false}`, w.Body.String())
}

func TestGetIntrospectionHandler_ExpiredAccessToken_ReturnsInactive(t *testing.T) {
	tokenStore := &authzTokenStore{}
	router := introspectionTestRouter(t, tokenStore)
	storeTestToken(t, tokenStore, &models.Token{
		ClientID:        authzTestClientID,
		UserID:          oidcTestEmail,
		Access:          "expired",
		AccessCreateAt:  time.Now().Add(-2 * time.Hour),
		AccessExpiresIn: time.Hour,
	})

	response := introspectToken(t, router, "expired", "")

	assert.False(t, response.Active)
}

func TestGetIntrospectionHandler_ExpiredRefreshToken_ReturnsInactive(t *testing.T) {
	tokenStore := &authzTokenStore{}
	router := introspectionTestRouter(t, tokenStore)
	storeTestToken(t, tokenStore, &models.Token{
		ClientID:         authzTestClientID,
		UserID:           oidcTestEmail,
		Refresh:          "expired",
		RefreshCreateAt:  time.Now().Add(-2 * time.Hour),
		RefreshExpiresIn: time.Hour,
	})

	response := introspectToken(t, router, "expired", tokenTypeHintRefreshToken)

	assert.False(t, response.Active)
}

func TestGetIntrospectionHandler_RevokedUser_ReturnsInactive(t *testing.T) {
	revokedAt := time.Now().Add(time.Minute)
	tests := []struct {
		name      string
		isEnabled bool
		revokedAt *time.Time
	}{
		{name: "disabled", isEnabled: false},
		{name: "disabled after issue and enabled again", isEnabled: true, revokedAt: &revokedAt},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbConn, mock := getTestDBConnection()
			router := introspectionTestRouter(t, store.NewTokenStore(dbConn, &authzTokenStore{}))
			// exchange of the authorization code
			expectActiveUser(mock, oidcTestEmail, true, nil)
			token := oidcObtainTokens(t, router, "openid", "")
			expectActiveUser(mock, oidcTestEmail, test.isEnabled, test.revokedAt)

			response := introspectToken(t, router, token["access_token"].(string), "")

			assert.False(t, response.Active)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestGetIntrospectionHandler_ActiveUser_ReturnsActive(t *testing.T) {
	dbConn, mock := getTestDBConnection()
	router := introspectionTestRouter(t, store.NewTokenStore(dbConn, &authzTokenStore{}))
	expectActiveUser(mock, oidcTestEmail, true, nil)
	token := oidcObtainTokens(t, router, "openid", "")
	expectActiveUser(mock, oidcTestEmail, true, nil)

	response := introspectToken(t, router, token["access_token"].(string), "")

	assert.True(t, response.Active)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetIntrospectionHandler_TokenStoreError_ReturnsInactive(t *testing.T) {
	router := introspectionTestRouter(t, &failingTokenStore{})

	response := introspectToken(t, router, "any", "")

	assert.False(t, response.Active)
}

func TestGetIntrospectionHandler_MissingToken_ReturnsBadRequest(t *testing.T) {
	router := introspectionTestRouter(t, &authzTokenStore{})

	w := introspectionRequest(t, router, url.Values{}, introspectionTestResourceServerID, introspectionTestResourceServerSecret)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error": "invalid_request"}`, w.Body.String())
}

func TestGetIntrospectionHandler_ClientAuthenticationFailure_ReturnsUnauthorized(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{name: "no client authentication"},
		{name: "unknown client", clientID: "unknown", clientSecret: "secret"},
		{name: "wrong secret", clientID: introspectionTestResourceServerID, clientSecret: "wrong"},
		{name: "empty secret", clientID: introspectionTestResourceServerID},
		{name: "public client", clientID: introspectionTestPublicClientID, clientSecret: "public-secret"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := introspectionTestRouter(t, &authzTokenStore{})

			w := introspectionRequest(t, router, url.Values{"token": {"any"}}, test.clientID, test.clientSecret)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Equal(t, `Basic realm="introspect"`, w.Header().Get("WWW-Authenticate"))
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			assert.JSONEq(t, `{"error": "invalid_client"}`, w.Body.String())
		})
	}
}

func TestGetIntrospectionHandler_ClientAuthenticationInForm_ReturnsOK(t *testing.T) {
	router := introspectionTestRouter(t, &authzTokenStore{})
	form := url.Values{}
	form.Set("token", "unknown")
	form.Set("client_id", introspectionTestResourceServerID)
	form.Set("client_secret", introspectionTestResourceServerSecret)

	w := introspectionRequest(t, router, form, "", "")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"active": false}`, w.Body.String())
}

func TestGetIntrospectionHandler_MalformedForm_ReturnsBadRequest(t *testing.T) {
	router := introspectionTestRouter(t, &authzTokenStore{})
	req, _ := http.NewRequest(http.MethodPost, oidcTestIssuer+"/introspect", strings.NewReader("token=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(introspectionTestResourceServerID, introspectionTestResourceServerSecret)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error": "invalid_request"}`, w.Body.String())
}
