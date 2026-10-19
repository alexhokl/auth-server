package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alexhokl/auth-server/jwthelper"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

const oidcTestIssuer = "http://auth.example.com"
const oidcTestEmail = "alex@test.com"

type failingIDTokenSigner struct{}

func (failingIDTokenSigner) IDToken(_ *jwthelper.IDTokenClaims) (string, error) {
	return "", errors.New("signing failed")
}

func oidcTestSigner(t *testing.T) (*jwthelper.EcKeyJWTGenerator, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	return jwthelper.NewEcKeyJWTGenerator("test-kid", key, jwt.SigningMethodES256), key
}

// oidcTestOAuthServer returns the in-memory OAuth server of the
// authorization tests with the ID token hooks of server.GetRouter.
func oidcTestOAuthServer(t *testing.T, signer IDTokenSigner) *server.Server {
	t.Helper()
	srv := authzTestOAuthServer(t)
	srv.Manager.(*manage.Manager).SetExtractExtensionHandler(ExtractTokenExtension)
	srv.SetExtensionFieldsHandler(GetIDTokenExtensionFieldsHandler(signer))
	return srv
}

func oidcTestRouter(t *testing.T, srv *server.Server) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	dbConn, mock := getTestDBConnection()
	router := authzTestRouter(t, srv)
	withDB := func(c *gin.Context) {
		c.Set("db", dbConn)
		c.Next()
	}
	router.GET("/userinfo", withDB, GetUserInfoHandler(srv))
	router.POST("/userinfo", withDB, GetUserInfoHandler(srv))
	return router, mock
}

// oidcObtainTokens runs an authorization code flow for oidcTestEmail and
// returns the token response.
func oidcObtainTokens(t *testing.T, router *gin.Engine, scope string, nonce string) map[string]interface{} {
	t.Helper()

	query := authzAuthorizeQuery()
	query.Set("scope", scope)
	if nonce != "" {
		query.Set("nonce", nonce)
	}
	authorizeReq, _ := http.NewRequest(http.MethodGet, oidcTestIssuer+"/authorize?"+query.Encode(), nil)
	authorizeRes := serveInSession(t, router, authenticatedSession(oidcTestEmail), authorizeReq)
	assert.Equal(t, http.StatusFound, authorizeRes.Code)
	location, err := url.Parse(authorizeRes.Header().Get("Location"))
	assert.NoError(t, err)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", location.Query().Get("code"))
	form.Set("redirect_uri", authzTestRedirectURI)
	return oidcTokenRequest(t, router, form)
}

func oidcTokenRequest(t *testing.T, router *gin.Engine, form url.Values) map[string]interface{} {
	t.Helper()
	req := authzTokenRequest(http.MethodPost, form)
	req.SetBasicAuth(authzTestClientID, authzTestClientSecret)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var token map[string]interface{}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &token))
	return token
}

func parseTestIDToken(t *testing.T, key *ecdsa.PrivateKey, idToken string) *jwthelper.IDTokenClaims {
	t.Helper()
	claims := &jwthelper.IDTokenClaims{}
	token, err := jwt.ParseWithClaims(idToken, claims, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)
	return claims
}

func expectUserQuery(mock sqlmock.Sqlmock, displayName string, isEnabled bool) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs(oidcTestEmail, 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}).
			AddRow(oidcTestEmail, []byte("hash"), displayName, nil, isEnabled))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE "user_credentials"."user_email" = $1`)).
		WithArgs(oidcTestEmail).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "friendly_name"}))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_email" = $1`)).
		WithArgs(oidcTestEmail).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "role_name"}))
}

func userInfoRequest(t *testing.T, router *gin.Engine, method string, accessToken string) *httptest.ResponseRecorder {
	t.Helper()
	req, _ := http.NewRequest(method, "/userinfo", nil)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// ExtractTokenExtension Tests

func TestExtractTokenExtension_AuthorizationCodeRequest_SetsIssuerAndNonce(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, oidcTestIssuer+"/authorize?response_type=code&nonce=n-1", nil)
	ti := models.NewToken()

	ExtractTokenExtension(&oauth2.TokenGenerateRequest{Request: req}, ti)

	assert.Equal(t, oidcTestIssuer, ti.GetExtension().Get(extensionIssuer))
	assert.Equal(t, "n-1", ti.GetExtension().Get(extensionNonce))
}

func TestExtractTokenExtension_WithoutNonce_SetsIssuerOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, oidcTestIssuer+"/authorize?response_type=code", nil)
	ti := models.NewToken()

	ExtractTokenExtension(&oauth2.TokenGenerateRequest{Request: req}, ti)

	assert.Equal(t, oidcTestIssuer, ti.GetExtension().Get(extensionIssuer))
	assert.NotContains(t, ti.GetExtension(), extensionNonce)
}

func TestExtractTokenExtension_NilExtension_CreatesExtension(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, oidcTestIssuer+"/authorize?response_type=code", nil)
	ti := &models.Token{}

	ExtractTokenExtension(&oauth2.TokenGenerateRequest{Request: req}, ti)

	assert.Equal(t, oidcTestIssuer, ti.GetExtension().Get(extensionIssuer))
}

func TestExtractTokenExtension_TokenRequest_KeepsExtensionOfCode(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://other.example.com/token?nonce=other", nil)
	ti := models.NewToken()
	ti.GetExtension().Set(extensionIssuer, oidcTestIssuer)
	ti.GetExtension().Set(extensionNonce, "n-1")

	ExtractTokenExtension(&oauth2.TokenGenerateRequest{Request: req}, ti)

	assert.Equal(t, oidcTestIssuer, ti.GetExtension().Get(extensionIssuer))
	assert.Equal(t, "n-1", ti.GetExtension().Get(extensionNonce))
}

func TestExtractTokenExtension_ImplicitRequest_DoesNothing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, oidcTestIssuer+"/authorize?response_type=token&nonce=n-1", nil)
	ti := models.NewToken()

	ExtractTokenExtension(&oauth2.TokenGenerateRequest{Request: req}, ti)

	assert.Empty(t, ti.GetExtension())
}

func TestExtractTokenExtension_NilRequest_DoesNothing(t *testing.T) {
	ti := models.NewToken()

	ExtractTokenExtension(&oauth2.TokenGenerateRequest{}, ti)

	assert.Empty(t, ti.GetExtension())
}

// GetIDTokenExtensionFieldsHandler Tests

func oidcTestTokenInfo(scope string) *models.Token {
	ti := models.NewToken()
	ti.SetClientID(authzTestClientID)
	ti.SetUserID(oidcTestEmail)
	ti.SetScope(scope)
	ti.SetAccessCreateAt(time.Now().Truncate(time.Second))
	ti.SetAccessExpiresIn(time.Hour)
	ti.GetExtension().Set(extensionIssuer, oidcTestIssuer)
	ti.GetExtension().Set(extensionNonce, "n-1")
	return ti
}

func TestGetIDTokenExtensionFieldsHandler_OpenIDScope_ReturnsIDToken(t *testing.T) {
	signer, key := oidcTestSigner(t)
	ti := oidcTestTokenInfo("openid email")

	fields := GetIDTokenExtensionFieldsHandler(signer)(ti)

	idToken, ok := fields[idTokenField].(string)
	assert.True(t, ok)
	claims := parseTestIDToken(t, key, idToken)
	assert.Equal(t, oidcTestIssuer, claims.Issuer)
	assert.Equal(t, oidcTestEmail, claims.Subject)
	assert.Equal(t, jwt.ClaimStrings{authzTestClientID}, claims.Audience)
	assert.Equal(t, authzTestClientID, claims.AuthorizedParty)
	assert.Equal(t, "n-1", claims.Nonce)
	assert.Equal(t, oidcTestEmail, claims.Email)
	assert.Equal(t, ti.GetAccessCreateAt().Unix(), claims.IssuedAt.Unix())
	assert.Equal(t, ti.GetAccessCreateAt().Add(time.Hour).Unix(), claims.ExpiresAt.Unix())
}

func TestGetIDTokenExtensionFieldsHandler_WithoutEmailScope_OmitsEmail(t *testing.T) {
	signer, key := oidcTestSigner(t)

	fields := GetIDTokenExtensionFieldsHandler(signer)(oidcTestTokenInfo("openid profile"))

	claims := parseTestIDToken(t, key, fields[idTokenField].(string))
	assert.Empty(t, claims.Email)
}

func TestGetIDTokenExtensionFieldsHandler_WithoutOpenIDScope_ReturnsNothing(t *testing.T) {
	signer, _ := oidcTestSigner(t)

	fields := GetIDTokenExtensionFieldsHandler(signer)(oidcTestTokenInfo("email profile"))

	assert.Empty(t, fields)
}

func TestGetIDTokenExtensionFieldsHandler_WithoutUser_ReturnsNothing(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	ti := oidcTestTokenInfo("openid")
	ti.SetUserID("")

	fields := GetIDTokenExtensionFieldsHandler(signer)(ti)

	assert.Empty(t, fields)
}

func TestGetIDTokenExtensionFieldsHandler_WithoutIssuer_ReturnsNothing(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	ti := oidcTestTokenInfo("openid")
	ti.GetExtension().Del(extensionIssuer)

	fields := GetIDTokenExtensionFieldsHandler(signer)(ti)

	assert.Empty(t, fields)
}

func TestGetIDTokenExtensionFieldsHandler_SigningFails_ReturnsNothing(t *testing.T) {
	fields := GetIDTokenExtensionFieldsHandler(failingIDTokenSigner{})(oidcTestTokenInfo("openid"))

	assert.Empty(t, fields)
}

// Token endpoint Tests

func TestTokenEndpoint_AuthorizationCodeWithOpenID_ReturnsIDToken(t *testing.T) {
	signer, key := oidcTestSigner(t)
	router, _ := oidcTestRouter(t, oidcTestOAuthServer(t, signer))

	token := oidcObtainTokens(t, router, "openid email", "n-1")

	idToken, ok := token[idTokenField].(string)
	assert.True(t, ok)
	claims := parseTestIDToken(t, key, idToken)
	assert.Equal(t, oidcTestIssuer, claims.Issuer)
	assert.Equal(t, oidcTestEmail, claims.Subject)
	assert.Equal(t, jwt.ClaimStrings{authzTestClientID}, claims.Audience)
	assert.Equal(t, "n-1", claims.Nonce)
	assert.Equal(t, oidcTestEmail, claims.Email)
}

func TestTokenEndpoint_AuthorizationCodeWithoutOpenID_ReturnsNoIDToken(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	router, _ := oidcTestRouter(t, oidcTestOAuthServer(t, signer))

	token := oidcObtainTokens(t, router, "email", "")

	assert.NotEmpty(t, token["access_token"])
	assert.NotContains(t, token, idTokenField)
}

func TestTokenEndpoint_RefreshWithOpenID_ReturnsIDTokenOfOriginalRequest(t *testing.T) {
	signer, key := oidcTestSigner(t)
	router, _ := oidcTestRouter(t, oidcTestOAuthServer(t, signer))
	token := oidcObtainTokens(t, router, "openid", "n-1")

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", token["refresh_token"].(string))
	refreshed := oidcTokenRequest(t, router, form)

	idToken, ok := refreshed[idTokenField].(string)
	assert.True(t, ok)
	claims := parseTestIDToken(t, key, idToken)
	assert.Equal(t, oidcTestIssuer, claims.Issuer)
	assert.Equal(t, oidcTestEmail, claims.Subject)
}

func TestTokenEndpoint_ClientCredentials_ReturnsNoIDToken(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	router, _ := oidcTestRouter(t, oidcTestOAuthServer(t, signer))

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "openid")
	token := oidcTokenRequest(t, router, form)

	assert.NotEmpty(t, token["access_token"])
	assert.NotContains(t, token, idTokenField)
}

// GetUserInfoHandler Tests

func TestGetUserInfoHandler_MissingToken_ReturnsUnauthorized(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	router, _ := oidcTestRouter(t, oidcTestOAuthServer(t, signer))

	w := userInfoRequest(t, router, http.MethodGet, "")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
}

func TestGetUserInfoHandler_UnknownToken_ReturnsUnauthorized(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	router, _ := oidcTestRouter(t, oidcTestOAuthServer(t, signer))

	w := userInfoRequest(t, router, http.MethodGet, "unknown")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
}

func TestGetUserInfoHandler_WithoutOpenIDScope_ReturnsForbidden(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	router, _ := oidcTestRouter(t, oidcTestOAuthServer(t, signer))
	token := oidcObtainTokens(t, router, "email", "")

	w := userInfoRequest(t, router, http.MethodGet, token["access_token"].(string))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, `Bearer error="insufficient_scope"`, w.Header().Get("WWW-Authenticate"))
}

func TestGetUserInfoHandler_ClientCredentialsToken_ReturnsForbidden(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	router, _ := oidcTestRouter(t, oidcTestOAuthServer(t, signer))
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "openid")
	token := oidcTokenRequest(t, router, form)

	w := userInfoRequest(t, router, http.MethodGet, token["access_token"].(string))

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGetUserInfoHandler_AllScopes_ReturnsAllClaims(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			signer, _ := oidcTestSigner(t)
			router, mock := oidcTestRouter(t, oidcTestOAuthServer(t, signer))
			token := oidcObtainTokens(t, router, "openid email profile", "")
			expectUserQuery(mock, "Alex", true)

			w := userInfoRequest(t, router, method, token["access_token"].(string))

			assert.Equal(t, http.StatusOK, w.Code)
			assert.JSONEq(
				t,
				`{"sub":"alex@test.com","email":"alex@test.com","email_verified":true,"name":"Alex"}`,
				w.Body.String(),
			)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestGetUserInfoHandler_OpenIDScopeOnly_ReturnsSubjectOnly(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	router, mock := oidcTestRouter(t, oidcTestOAuthServer(t, signer))
	token := oidcObtainTokens(t, router, "openid", "")
	expectUserQuery(mock, "Alex", true)

	w := userInfoRequest(t, router, http.MethodGet, token["access_token"].(string))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"sub":"alex@test.com"}`, w.Body.String())
}

func TestGetUserInfoHandler_ProfileScopeWithoutDisplayName_OmitsName(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	router, mock := oidcTestRouter(t, oidcTestOAuthServer(t, signer))
	token := oidcObtainTokens(t, router, "openid profile", "")
	expectUserQuery(mock, "", true)

	w := userInfoRequest(t, router, http.MethodGet, token["access_token"].(string))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"sub":"alex@test.com"}`, w.Body.String())
}

func TestGetUserInfoHandler_DisabledUser_ReturnsUnauthorized(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	router, mock := oidcTestRouter(t, oidcTestOAuthServer(t, signer))
	token := oidcObtainTokens(t, router, "openid", "")
	expectUserQuery(mock, "Alex", false)

	w := userInfoRequest(t, router, http.MethodGet, token["access_token"].(string))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
}

func TestGetUserInfoHandler_UserNotFound_ReturnsUnauthorized(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	router, mock := oidcTestRouter(t, oidcTestOAuthServer(t, signer))
	token := oidcObtainTokens(t, router, "openid", "")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs(oidcTestEmail, 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}))

	w := userInfoRequest(t, router, http.MethodGet, token["access_token"].(string))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserInfoHandler_DatabaseError_ReturnsInternalError(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	router, mock := oidcTestRouter(t, oidcTestOAuthServer(t, signer))
	token := oidcObtainTokens(t, router, "openid", "")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WillReturnError(errors.New("connection refused"))

	w := userInfoRequest(t, router, http.MethodGet, token["access_token"].(string))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetUserInfoHandler_NoDatabaseConnection_ReturnsInternalError(t *testing.T) {
	signer, _ := oidcTestSigner(t)
	srv := oidcTestOAuthServer(t, signer)
	router := authzTestRouter(t, srv)
	router.GET("/userinfo", GetUserInfoHandler(srv))
	token := oidcObtainTokens(t, router, "openid", "")

	w := userInfoRequest(t, router, http.MethodGet, token["access_token"].(string))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// hasScope Tests

func TestHasScope(t *testing.T) {
	assert.True(t, hasScope("openid email", "openid"))
	assert.True(t, hasScope("email  openid", "openid"))
	assert.False(t, hasScope("openidx email", "openid"))
	assert.False(t, hasScope("", "openid"))
}
