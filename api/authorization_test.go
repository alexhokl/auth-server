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
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	oauthErrors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
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

// GetUserIdInAuthorizationRequest Tests

func TestGetUserIdInAuthorizationRequest_NotAuthenticated_ReturnsInvalidRequest(t *testing.T) {
	var userID string
	var err error
	runInSession(t, func(c *gin.Context) {
		userID, err = GetUserIdInAuthorizationRequest(c.Writer, c.Request)
	})

	assert.Equal(t, oauthErrors.ErrInvalidRequest, err)
	assert.Empty(t, userID)
}

func TestGetUserIdInAuthorizationRequest_EmailNotConfirmedBySignIn_ReturnsInvalidRequest(t *testing.T) {
	router := gin.New()
	var userID string
	var err error
	router.GET("/authorize", func(c *gin.Context) {
		userID, err = GetUserIdInAuthorizationRequest(c.Writer, c.Request)
	})

	req, _ := http.NewRequest(http.MethodGet, "/authorize", nil)
	serveInSession(t, router, map[string]interface{}{sessionEmailKey: "alex@test.com"}, req)

	assert.Equal(t, oauthErrors.ErrInvalidRequest, err)
	assert.Empty(t, userID)
}

func TestGetUserIdInAuthorizationRequest_Authenticated_ReturnsEmail(t *testing.T) {
	router := gin.New()
	var userID string
	var err error
	router.GET("/authorize", func(c *gin.Context) {
		userID, err = GetUserIdInAuthorizationRequest(c.Writer, c.Request)
	})

	req, _ := http.NewRequest(http.MethodGet, "/authorize", nil)
	serveInSession(t, router, authenticatedSession("alex@test.com"), req)

	assert.NoError(t, err)
	assert.Equal(t, "alex@test.com", userID)
}

// HandleClientInfoInTokenRequest Tests

func TestHandleClientInfoInTokenRequest_BasicAuth_ReturnsClientInfo(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "/token", nil)
	req.SetBasicAuth("cli", "secret")

	clientID, clientSecret, err := HandleClientInfoInTokenRequest(req)

	assert.NoError(t, err)
	assert.Equal(t, "cli", clientID)
	assert.Equal(t, "secret", clientSecret)
}

func TestHandleClientInfoInTokenRequest_FormValues_ReturnsClientInfo(t *testing.T) {
	form := url.Values{}
	form.Set("client_id", "cli")
	form.Set("client_secret", "secret")
	req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// the form has been parsed by the OAuth server before the handler is
	// called
	assert.NoError(t, req.ParseForm())

	clientID, clientSecret, err := HandleClientInfoInTokenRequest(req)

	assert.NoError(t, err)
	assert.Equal(t, "cli", clientID)
	assert.Equal(t, "secret", clientSecret)
}

func TestHandleClientInfoInTokenRequest_NoClientInfo_ReturnsError(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.NoError(t, req.ParseForm())

	clientID, clientSecret, err := HandleClientInfoInTokenRequest(req)

	assert.Equal(t, oauthErrors.ErrInvalidClient, err)
	assert.Empty(t, clientID)
	assert.Empty(t, clientSecret)
}

// GetAuthorizationRequestHandler and GetTokenRequestHandler Tests

const authzTestClientID = "cli"
const authzTestClientSecret = "secret"
const authzTestRedirectURI = "https://client.test.com/callback"

// authzClientStore is an in-memory client store.
type authzClientStore struct {
	clients map[string]oauth2.ClientInfo
}

func (s *authzClientStore) GetByID(_ context.Context, id string) (oauth2.ClientInfo, error) {
	return s.clients[id], nil
}

// authzTokenStore is an in-memory token store.
type authzTokenStore struct {
	mu     sync.Mutex
	tokens []oauth2.TokenInfo
}

func (s *authzTokenStore) Create(_ context.Context, info oauth2.TokenInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = append(s.tokens, info)
	return nil
}

func (s *authzTokenStore) find(match func(oauth2.TokenInfo) bool) oauth2.TokenInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, info := range s.tokens {
		if match(info) {
			return info
		}
	}
	return nil
}

func (s *authzTokenStore) remove(match func(oauth2.TokenInfo) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var remaining []oauth2.TokenInfo
	for _, info := range s.tokens {
		if !match(info) {
			remaining = append(remaining, info)
		}
	}
	s.tokens = remaining
	return nil
}

func (s *authzTokenStore) RemoveByCode(_ context.Context, code string) error {
	return s.remove(func(info oauth2.TokenInfo) bool { return info.GetCode() == code })
}

func (s *authzTokenStore) RemoveByAccess(_ context.Context, access string) error {
	return s.remove(func(info oauth2.TokenInfo) bool { return info.GetAccess() == access })
}

func (s *authzTokenStore) RemoveByRefresh(_ context.Context, refresh string) error {
	return s.remove(func(info oauth2.TokenInfo) bool { return info.GetRefresh() == refresh })
}

func (s *authzTokenStore) GetByCode(_ context.Context, code string) (oauth2.TokenInfo, error) {
	return s.find(func(info oauth2.TokenInfo) bool { return code != "" && info.GetCode() == code }), nil
}

func (s *authzTokenStore) GetByAccess(_ context.Context, access string) (oauth2.TokenInfo, error) {
	return s.find(func(info oauth2.TokenInfo) bool { return access != "" && info.GetAccess() == access }), nil
}

func (s *authzTokenStore) GetByRefresh(_ context.Context, refresh string) (oauth2.TokenInfo, error) {
	return s.find(func(info oauth2.TokenInfo) bool { return refresh != "" && info.GetRefresh() == refresh }), nil
}

// authzTestOAuthServer returns an OAuth server configured as in
// server.GetRouter but with in-memory stores.
func authzTestOAuthServer(t *testing.T) *server.Server {
	t.Helper()

	clientStore := &authzClientStore{
		clients: map[string]oauth2.ClientInfo{
			authzTestClientID: &models.Client{
				ID:     authzTestClientID,
				Secret: authzTestClientSecret,
				Domain: authzTestRedirectURI,
			},
		},
	}

	manager := manage.NewDefaultManager()
	manager.MapClientStorage(clientStore)
	manager.MapTokenStorage(&authzTokenStore{})

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(false)
	srv.SetAllowedResponseType(oauth2.Code, oauth2.Token)
	srv.SetAllowedGrantType(
		oauth2.AuthorizationCode,
		oauth2.ClientCredentials,
		oauth2.Refreshing,
	)
	srv.SetInternalErrorHandler(HandleInternalError)
	srv.SetPreRedirectErrorHandler(GetPreRedirectErrorHandler(srv))
	srv.SetUserAuthorizationHandler(GetUserIdInAuthorizationRequest)
	srv.SetClientInfoHandler(HandleClientInfoInTokenRequest)
	return srv
}

func authzTestRouter(t *testing.T, srv *server.Server) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/authorize", gin.WrapF(GetAuthorizationRequestHandler(srv)))
	router.POST("/token", gin.WrapF(GetTokenRequestHandler(srv)))
	router.GET("/token", gin.WrapF(GetTokenRequestHandler(srv)))
	return router
}

func authzAuthorizeQuery() url.Values {
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", authzTestClientID)
	query.Set("redirect_uri", authzTestRedirectURI)
	query.Set("state", "test-state")
	return query
}

func TestGetAuthorizationRequestHandler_MissingClientID_ReturnsBadRequest(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	query := authzAuthorizeQuery()
	query.Del("client_id")
	req, _ := http.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	w := serveInSession(t, router, authenticatedSession("alex@test.com"), req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), oauthErrors.ErrInvalidRequest.Error())
}

func TestGetAuthorizationRequestHandler_MissingResponseType_ReturnsBadRequest(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	query := authzAuthorizeQuery()
	query.Del("response_type")
	req, _ := http.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	w := serveInSession(t, router, authenticatedSession("alex@test.com"), req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), oauthErrors.ErrUnsupportedResponseType.Error())
}

func TestGetAuthorizationRequestHandler_UnsupportedResponseType_ReturnsBadRequest(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	query := authzAuthorizeQuery()
	query.Set("response_type", "id_token")
	req, _ := http.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	w := serveInSession(t, router, authenticatedSession("alex@test.com"), req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAuthorizationRequestHandler_NotAuthenticated_RedirectsWithError(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	req, _ := http.NewRequest(http.MethodGet, "/authorize?"+authzAuthorizeQuery().Encode(), nil)
	w := serveInSession(t, router, map[string]interface{}{}, req)

	assert.Equal(t, http.StatusFound, w.Code)
	location, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, "client.test.com", location.Host)
	assert.Equal(t, oauthErrors.ErrInvalidRequest.Error(), location.Query().Get("error"))
	assert.Equal(t, "test-state", location.Query().Get("state"))
	assert.Empty(t, location.Query().Get("code"))
}

func TestGetAuthorizationRequestHandler_MismatchedRedirectURI_ReturnsBadRequest(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	query := authzAuthorizeQuery()
	query.Set("redirect_uri", "https://evil.test.com/callback")
	req, _ := http.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	w := serveInSession(t, router, authenticatedSession("alex@test.com"), req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, w.Header().Get("Location"))
	assert.Contains(t, w.Body.String(), oauthErrors.ErrInvalidRedirectURI.Error())
}

func TestGetAuthorizationRequestHandler_NotAuthenticatedMismatchedRedirectURI_ReturnsBadRequest(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	query := authzAuthorizeQuery()
	query.Set("redirect_uri", "https://evil.test.com/callback")
	req, _ := http.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	w := serveInSession(t, router, map[string]interface{}{}, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, w.Header().Get("Location"))
}

func TestGetAuthorizationRequestHandler_UnknownClient_ReturnsBadRequest(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	query := authzAuthorizeQuery()
	query.Set("client_id", "unknown-client")
	req, _ := http.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	w := serveInSession(t, router, map[string]interface{}{}, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, w.Header().Get("Location"))
}

func TestGetAuthorizationRequestHandler_NotAuthenticatedWithoutRedirectURI_RedirectsToClientDomain(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	query := authzAuthorizeQuery()
	query.Del("redirect_uri")
	req, _ := http.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	w := serveInSession(t, router, map[string]interface{}{}, req)

	assert.Equal(t, http.StatusFound, w.Code)
	location, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, "client.test.com", location.Host)
	assert.Equal(t, oauthErrors.ErrInvalidRequest.Error(), location.Query().Get("error"))
}

func TestGetAuthorizationRequestHandler_Authenticated_RedirectsWithCode(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	req, _ := http.NewRequest(http.MethodGet, "/authorize?"+authzAuthorizeQuery().Encode(), nil)
	w := serveInSession(t, router, authenticatedSession("alex@test.com"), req)

	assert.Equal(t, http.StatusFound, w.Code)
	location, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, "client.test.com", location.Host)
	assert.Equal(t, "/callback", location.Path)
	assert.NotEmpty(t, location.Query().Get("code"))
	assert.Equal(t, "test-state", location.Query().Get("state"))
}

func authzTokenRequest(method string, form url.Values) *http.Request {
	req, _ := http.NewRequest(method, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestGetTokenRequestHandler_GetMethod_ReturnsBadRequest(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/token?grant_type=client_credentials", nil)
	req.SetBasicAuth(authzTestClientID, authzTestClientSecret)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), oauthErrors.ErrInvalidRequest.Error())
}

func TestGetTokenRequestHandler_MissingGrantType_ReturnsUnauthorized(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	req := authzTokenRequest(http.MethodPost, url.Values{})
	req.SetBasicAuth(authzTestClientID, authzTestClientSecret)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), oauthErrors.ErrUnsupportedGrantType.Error())
}

// The password grant is not enabled on the server.
func TestGetTokenRequestHandler_PasswordGrant_ReturnsForbidden(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "alex@test.com")
	form.Set("password", "password")
	req := authzTokenRequest(http.MethodPost, form)
	req.SetBasicAuth(authzTestClientID, authzTestClientSecret)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.NotContains(t, w.Body.String(), "access_token")
}

func TestGetTokenRequestHandler_NoClientInfo_ReturnsUnauthorized(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, authzTokenRequest(http.MethodPost, form))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), oauthErrors.ErrInvalidClient.Error())
}

func TestGetTokenRequestHandler_WrongClientSecret_ReturnsUnauthorized(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	req := authzTokenRequest(http.MethodPost, form)
	req.SetBasicAuth(authzTestClientID, "wrong-secret")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), oauthErrors.ErrInvalidClient.Error())
}

func TestGetTokenRequestHandler_InvalidAuthorizationCode_ReturnsUnauthorized(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "invalid-code")
	form.Set("redirect_uri", authzTestRedirectURI)
	req := authzTokenRequest(http.MethodPost, form)
	req.SetBasicAuth(authzTestClientID, authzTestClientSecret)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), oauthErrors.ErrInvalidGrant.Error())
}

func TestGetTokenRequestHandler_ClientCredentials_ReturnsOK(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	req := authzTokenRequest(http.MethodPost, form)
	req.SetBasicAuth(authzTestClientID, authzTestClientSecret)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var token map[string]interface{}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &token))
	assert.NotEmpty(t, token["access_token"])
	assert.Equal(t, "Bearer", token["token_type"])
}

func TestGetTokenRequestHandler_ResponseFailure_ReturnsBadRequest(t *testing.T) {
	srv := authzTestOAuthServer(t)
	srv.SetResponseTokenHandler(func(w http.ResponseWriter, data map[string]interface{}, header http.Header, statusCode ...int) error {
		return errors.New("unable to write response")
	})
	router := authzTestRouter(t, srv)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	req := authzTokenRequest(http.MethodPost, form)
	req.SetBasicAuth(authzTestClientID, authzTestClientSecret)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unable to write response")
}

func TestGetTokenRequestHandler_AuthorizationCode_ReturnsOK(t *testing.T) {
	router := authzTestRouter(t, authzTestOAuthServer(t))

	authorizeReq, _ := http.NewRequest(http.MethodGet, "/authorize?"+authzAuthorizeQuery().Encode(), nil)
	authorizeRes := serveInSession(t, router, authenticatedSession("alex@test.com"), authorizeReq)
	assert.Equal(t, http.StatusFound, authorizeRes.Code)
	location, err := url.Parse(authorizeRes.Header().Get("Location"))
	assert.NoError(t, err)
	code := location.Query().Get("code")
	assert.NotEmpty(t, code)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", authzTestRedirectURI)
	req := authzTokenRequest(http.MethodPost, form)
	req.SetBasicAuth(authzTestClientID, authzTestClientSecret)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var token map[string]interface{}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &token))
	assert.NotEmpty(t, token["access_token"])
	assert.NotEmpty(t, token["refresh_token"])

	// an authorization code can only be used once
	replayReq := authzTokenRequest(http.MethodPost, form)
	replayReq.SetBasicAuth(authzTestClientID, authzTestClientSecret)
	replay := httptest.NewRecorder()
	router.ServeHTTP(replay, replayReq)

	assert.Equal(t, http.StatusUnauthorized, replay.Code)
	assert.Contains(t, replay.Body.String(), oauthErrors.ErrInvalidGrant.Error())
}
