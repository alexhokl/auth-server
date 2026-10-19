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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alexhokl/auth-server/db"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func TestGetOAuthConfig_Google(t *testing.T) {
	client := &db.OidcClient{
		Name:         string(Google),
		ClientID:     "google-client-id",
		ClientSecret: "google-client-secret",
		RedirectURI:  "https://auth.example.com/signin/google/callback",
	}

	config, err := getOAuthConfig(client)

	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, google.Endpoint, config.Endpoint)
	assert.Equal(t, []string{"openid", "profile", "email"}, config.Scopes)
	assert.Equal(t, "google-client-id", config.ClientID)
	assert.Equal(t, "google-client-secret", config.ClientSecret)
	assert.Equal(
		t,
		"https://auth.example.com/signin/google/callback",
		config.RedirectURL,
	)
}

func TestGetOAuthConfig_NotImplementedProviders(t *testing.T) {
	notImplemented := []OIDCProvider{Facebook, Microsoft}

	for _, provider := range notImplemented {
		t.Run(string(provider), func(t *testing.T) {
			config, err := getOAuthConfig(&db.OidcClient{Name: string(provider)})

			assert.Error(t, err)
			assert.Nil(t, config)
			assert.Contains(t, err.Error(), "not implemented")
		})
	}
}

func TestGetOAuthConfig_UnsupportedProvider(t *testing.T) {
	config, err := getOAuthConfig(&db.OidcClient{Name: "some-provider"})

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "some-provider")
}

func oidcTestClientColumns() []string {
	return []string{"name", "client_id", "client_secret", "redirect_uri", "button_name"}
}

func oidcExpectGetClient(mock sqlmock.Sqlmock, name string) *sqlmock.ExpectedQuery {
	return mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients" WHERE name = $1 ORDER BY "oidc_clients"."name" LIMIT $2`)).
		WithArgs(name, 1)
}

func oidcTestClientRows(name string) *sqlmock.Rows {
	return sqlmock.NewRows(oidcTestClientColumns()).
		AddRow(name, "google-client-id", "google-client-secret", "https://test.com/signin/google/callback", "Sign in with Google")
}

// oidcSessionValues returns session values with an OIDC session of the given
// state.
func oidcSessionValues(t *testing.T, state string) map[string]interface{} {
	t.Helper()

	sessionJSON, err := json.Marshal(oidcSession{
		State:                   state,
		PKCECodeChallengeMethod: pkceChallengeMethod,
		PKCECodeChallenge:       "challenge",
		PKCECodeVerifier:        "verifier",
		RedirectURI:             "/authorize",
	})
	assert.NoError(t, err)
	return map[string]interface{}{sessionOIDCKey: string(sessionJSON)}
}

// RedirectToOIDCEndpoint Tests

func TestRedirectToOIDCEndpoint_InvalidAction_ReturnsNotFound(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/:action/:oidc_name/start", RedirectToOIDCEndpoint)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/signout/google/start", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRedirectToOIDCEndpoint_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := gin.New()
	router.GET("/:action/:oidc_name/start", RedirectToOIDCEndpoint)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/signin/google/start", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRedirectToOIDCEndpoint_ClientQueryError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/:action/:oidc_name/start", RedirectToOIDCEndpoint)

	oidcExpectGetClient(mock, "google").WillReturnError(errors.New("database error"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/signin/google/start", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRedirectToOIDCEndpoint_ClientNotFound_ReturnsNotFound(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/:action/:oidc_name/start", RedirectToOIDCEndpoint)

	oidcExpectGetClient(mock, "google").WillReturnRows(sqlmock.NewRows(oidcTestClientColumns()))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/signin/google/start", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRedirectToOIDCEndpoint_UnsupportedProvider_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/:action/:oidc_name/start", RedirectToOIDCEndpoint)

	oidcExpectGetClient(mock, "some-provider").WillReturnRows(oidcTestClientRows("some-provider"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/signin/some-provider/start", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRedirectToOIDCEndpoint_Google_ReturnsFound(t *testing.T) {
	for _, action := range []string{"signin", "signup"} {
		t.Run(action, func(t *testing.T) {
			router, _, mock := getTestRouter()
			router.GET("/:action/:oidc_name/start", RedirectToOIDCEndpoint)

			var state, codeChallengeMethod, codeChallenge, codeVerifier, redirectURI string
			var isSignUp bool
			var sessionErr error
			router.GET("/__oidc_read_session", func(c *gin.Context) {
				state, codeChallengeMethod, codeChallenge, codeVerifier, redirectURI, isSignUp, sessionErr = getOIDCSession(c, "google")
			})

			oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/"+action+"/google/start?redirect_uri=/authorize", nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusFound, w.Code)
			assert.NoError(t, mock.ExpectationsWereMet())

			location, err := url.Parse(w.Header().Get("Location"))
			assert.NoError(t, err)
			assert.Equal(t, "accounts.google.com", location.Host)
			query := location.Query()
			assert.Equal(t, "google-client-id", query.Get("client_id"))
			assert.Equal(t, "https://test.com/signin/google/callback", query.Get("redirect_uri"))
			assert.Equal(t, "code", query.Get("response_type"))
			assert.Equal(t, "openid profile email", query.Get("scope"))
			assert.Equal(t, "online", query.Get("access_type"))
			assert.Equal(t, pkceChallengeMethod, query.Get("code_challenge_method"))
			assert.NotEmpty(t, query.Get("code_challenge"))
			assert.NotEmpty(t, query.Get("state"))

			// the OIDC session is saved for the callback
			readReq, _ := http.NewRequest(http.MethodGet, "/__oidc_read_session", nil)
			for _, cookie := range w.Result().Cookies() {
				readReq.AddCookie(cookie)
			}
			router.ServeHTTP(httptest.NewRecorder(), readReq)

			assert.NoError(t, sessionErr)
			assert.Equal(t, query.Get("state"), state)
			assert.Equal(t, pkceChallengeMethod, codeChallengeMethod)
			assert.Equal(t, query.Get("code_challenge"), codeChallenge)
			assert.NotEmpty(t, codeVerifier)
			assert.Equal(t, "/authorize", redirectURI)
			assert.Equal(t, action == "signup", isSignUp)
		})
	}
}

// OIDCCallback Tests

func TestOIDCCallback_NoSession_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/signin/google/callback?state=abc&code=xyz", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCCallback_StateMismatch_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	req, _ := http.NewRequest(http.MethodGet, "/signin/google/callback?state=other&code=xyz", nil)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCCallback_ErrorWithDescription_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	req, _ := http.NewRequest(http.MethodGet, "/signin/google/callback?state=expected-state&error=access_denied&error_description=denied", nil)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// Note that the handler does not return after responding with a bad request
// in this case and it carries on processing the callback; the router here has
// no database so that it stops right after.
func TestOIDCCallback_ErrorWithoutDescription_ReturnsBadRequest(t *testing.T) {
	router := gin.New()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	req, _ := http.NewRequest(http.MethodGet, "/signin/google/callback?state=expected-state&error=access_denied", nil)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDCCallback_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := gin.New()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	req, _ := http.NewRequest(http.MethodGet, "/signin/google/callback?state=expected-state&code=xyz", nil)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestOIDCCallback_ClientQueryError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnError(errors.New("database error"))

	req, _ := http.NewRequest(http.MethodGet, "/signin/google/callback?state=expected-state&code=xyz", nil)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCCallback_ClientNotFound_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(sqlmock.NewRows(oidcTestClientColumns()))

	req, _ := http.NewRequest(http.MethodGet, "/signin/google/callback?state=expected-state&code=xyz", nil)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCCallback_UnsupportedProvider_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "some-provider").WillReturnRows(oidcTestClientRows("some-provider"))

	req, _ := http.NewRequest(http.MethodGet, "/signin/some-provider/callback?state=expected-state&code=xyz", nil)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ListOIDCCLients Tests

func TestListOIDCCLients_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := gin.New()
	router.GET("/oidcclients", ListOIDCCLients)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oidcclients", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListOIDCCLients_DatabaseError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/oidcclients", ListOIDCCLients)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients"`)).
		WillReturnError(errors.New("database error"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oidcclients", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListOIDCCLients_Empty_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/oidcclients", ListOIDCCLients)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients"`)).
		WillReturnRows(sqlmock.NewRows(oidcTestClientColumns()))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oidcclients", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `[]`, w.Body.String())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListOIDCCLients_WithClients_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/oidcclients", ListOIDCCLients)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients"`)).
		WillReturnRows(oidcTestClientRows("google").
			AddRow("microsoft", "ms-client-id", "ms-client-secret", "https://test.com/signin/microsoft/callback", "Sign in with Microsoft"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oidcclients", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())

	var clients []OIDCClientResponse
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &clients))
	assert.Equal(t, []OIDCClientResponse{
		{
			Name:        "google",
			ClientID:    "google-client-id",
			RedirectURI: "https://test.com/signin/google/callback",
			ButtonName:  "Sign in with Google",
		},
		{
			Name:        "microsoft",
			ClientID:    "ms-client-id",
			RedirectURI: "https://test.com/signin/microsoft/callback",
			ButtonName:  "Sign in with Microsoft",
		},
	}, clients)
	// client secrets must not be exposed
	assert.NotContains(t, w.Body.String(), "secret")
}

// CreateOIDCClient Tests

const oidcTestCreateBody = `{"name":"google","client_id":"google-client-id","client_secret":"google-client-secret","redirect_uri":"https://test.com/signin/google/callback","button_name":"Sign in with Google"}`

func TestCreateOIDCClient_MalformedBody_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/oidcclients", CreateOIDCClient)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oidcclients", strings.NewReader(`{"invalid`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateOIDCClient_MissingFields_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/oidcclients", CreateOIDCClient)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oidcclients", strings.NewReader(`{"name":"google"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateOIDCClient_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := gin.New()
	router.POST("/oidcclients", CreateOIDCClient)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oidcclients", strings.NewReader(oidcTestCreateBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateOIDCClient_DatabaseError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/oidcclients", CreateOIDCClient)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "oidc_clients"`)).
		WillReturnError(errors.New("database error"))
	mock.ExpectRollback()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oidcclients", strings.NewReader(oidcTestCreateBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateOIDCClient_Success_ReturnsCreated(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/oidcclients", CreateOIDCClient)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "oidc_clients" ("name","client_id","client_secret","redirect_uri","button_name") VALUES ($1,$2,$3,$4,$5)`)).
		WithArgs("google", "google-client-id", "google-client-secret", "https://test.com/signin/google/callback", "Sign in with Google").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oidcclients", strings.NewReader(oidcTestCreateBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())

	var client OIDCClientResponse
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &client))
	assert.Equal(t, OIDCClientResponse{
		Name:        "google",
		ClientID:    "google-client-id",
		RedirectURI: "https://test.com/signin/google/callback",
		ButtonName:  "Sign in with Google",
	}, client)
	assert.NotContains(t, w.Body.String(), "google-client-secret")
}

// UpdateOIDCClient Tests

const oidcTestUpdateBody = `{"client_id":"new-client-id","client_secret":"new-client-secret","redirect_uri":"https://test.com/new/callback","button_name":"Google"}`

func TestUpdateOIDCClient_MalformedBody_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PUT("/oidcclients/:name", UpdateOIDCClient)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/oidcclients/google", strings.NewReader(`{"invalid`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateOIDCClient_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := gin.New()
	router.PUT("/oidcclients/:name", UpdateOIDCClient)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/oidcclients/google", strings.NewReader(oidcTestUpdateBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateOIDCClient_DatabaseError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PUT("/oidcclients/:name", UpdateOIDCClient)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "oidc_clients" SET`)).
		WillReturnError(errors.New("database error"))
	mock.ExpectRollback()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/oidcclients/google", strings.NewReader(oidcTestUpdateBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateOIDCClient_Success_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PUT("/oidcclients/:name", UpdateOIDCClient)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "oidc_clients" SET "client_id"=$1,"client_secret"=$2,"redirect_uri"=$3,"button_name"=$4 WHERE name = $5`)).
		WithArgs("new-client-id", "new-client-secret", "https://test.com/new/callback", "Google", "google", "google").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/oidcclients/google", strings.NewReader(oidcTestUpdateBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())

	var client OIDCClientResponse
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &client))
	assert.Equal(t, OIDCClientResponse{
		Name:        "google",
		ClientID:    "new-client-id",
		RedirectURI: "https://test.com/new/callback",
		ButtonName:  "Google",
	}, client)
}

// DeleteOIDCClient Tests

func TestDeleteOIDCClient_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := gin.New()
	router.DELETE("/oidcclients/:name", DeleteOIDCClient)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/oidcclients/google", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteOIDCClient_DatabaseError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.DELETE("/oidcclients/:name", DeleteOIDCClient)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "oidc_clients" WHERE name = $1`)).
		WithArgs("google").
		WillReturnError(errors.New("database error"))
	mock.ExpectRollback()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/oidcclients/google", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteOIDCClient_Success_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.DELETE("/oidcclients/:name", DeleteOIDCClient)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "oidc_clients" WHERE name = $1`)).
		WithArgs("google").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/oidcclients/google", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// getUserInformationFromOIDCProviderCallback Tests

func oidcTestGinContext() *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request, _ = http.NewRequest(http.MethodGet, "/signin/google/callback", nil)
	return c
}

func TestGetUserInformationFromOIDCProviderCallback_GoogleWithoutIDToken_ReturnsError(t *testing.T) {
	token := &oauth2.Token{AccessToken: "access-token"}

	email, err := getUserInformationFromOIDCProviderCallback(&db.OidcClient{Name: string(Google)}, token, oidcTestGinContext())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to get ID token")
	assert.Empty(t, email)
}

func TestGetUserInformationFromOIDCProviderCallback_NotImplementedProviders_ReturnsError(t *testing.T) {
	for _, provider := range []OIDCProvider{Facebook, Microsoft} {
		t.Run(string(provider), func(t *testing.T) {
			token := &oauth2.Token{AccessToken: "access-token"}

			email, err := getUserInformationFromOIDCProviderCallback(&db.OidcClient{Name: string(provider)}, token, oidcTestGinContext())

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not implemented")
			assert.Empty(t, email)
		})
	}
}

func TestGetUserInformationFromOIDCProviderCallback_UnsupportedProvider_ReturnsError(t *testing.T) {
	token := &oauth2.Token{AccessToken: "access-token"}

	email, err := getUserInformationFromOIDCProviderCallback(&db.OidcClient{Name: "some-provider"}, token, oidcTestGinContext())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported OIDC client: some-provider")
	assert.Empty(t, email)
}

// OIDCCallback Tests with a fake Google

const oidcTestGoogleClientID = "google-client-id"
const oidcTestGoogleKeyID = "test-key"

// oidcRoundTripper serves requests with a handler instead of the network.
type oidcRoundTripper struct {
	handler http.Handler
}

func (rt *oidcRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	rt.handler.ServeHTTP(w, r)
	return w.Result(), nil
}

type oidcFakeGoogle struct {
	key             *ecdsa.PrivateKey
	tokenStatusCode int
	idToken         string
}

// oidcNewFakeGoogle returns a fake Google which issues an ID token of the
// given email.
func oidcNewFakeGoogle(t *testing.T, email string) *oidcFakeGoogle {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":   "https://accounts.google.com",
		"aud":   oidcTestGoogleClientID,
		"sub":   "1234567890",
		"email": email,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = oidcTestGoogleKeyID
	idToken, err := token.SignedString(key)
	assert.NoError(t, err)

	return &oidcFakeGoogle{
		key:             key,
		tokenStatusCode: http.StatusOK,
		idToken:         idToken,
	}
}

func (g *oidcFakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Host + r.URL.Path {
	case "oauth2.googleapis.com/token":
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
	case "accounts.google.com/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                "https://accounts.google.com",
			"authorization_endpoint":                "https://accounts.google.com/o/oauth2/v2/auth",
			"token_endpoint":                        "https://oauth2.googleapis.com/token",
			"jwks_uri":                              "https://www.googleapis.com/oauth2/v3/certs",
			"id_token_signing_alg_values_supported": []string{"ES256"},
		})
	case "www.googleapis.com/oauth2/v3/certs":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{
				{
					"kty": "EC",
					"crv": "P-256",
					"alg": "ES256",
					"use": "sig",
					"kid": oidcTestGoogleKeyID,
					"x":   base64.RawURLEncoding.EncodeToString(g.key.X.FillBytes(make([]byte, 32))),
					"y":   base64.RawURLEncoding.EncodeToString(g.key.Y.FillBytes(make([]byte, 32))),
				},
			},
		})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// oidcCallbackRequest returns a callback request which reaches the fake
// Google instead of the network.
func oidcCallbackRequest(google *oidcFakeGoogle) *http.Request {
	client := &http.Client{Transport: &oidcRoundTripper{handler: google}}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/signin/google/callback?state=expected-state&code=auth-code", nil)
	return req
}

func oidcSignUpSessionValues(t *testing.T, redirectURI string) map[string]interface{} {
	t.Helper()

	sessionJSON, err := json.Marshal(oidcSession{
		State:                   "expected-state",
		PKCECodeChallengeMethod: pkceChallengeMethod,
		PKCECodeChallenge:       "challenge",
		PKCECodeVerifier:        "verifier",
		RedirectURI:             redirectURI,
		IsSignUp:                true,
	})
	assert.NoError(t, err)
	return map[string]interface{}{sessionOIDCKey: string(sessionJSON)}
}

func oidcExpectGetUser(mock sqlmock.Sqlmock, email string, isEnabled bool) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs(email, 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}).
			AddRow(email, []byte("hash"), "Alex", nil, isEnabled))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE "user_credentials"."user_email" = $1`)).
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "friendly_name"}))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_email" = $1`)).
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "role_name"}))
}

func oidcExpectUserNotFound(mock sqlmock.Sqlmock, email string) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs(email, 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}))
}

// oidcReadAuthenticatedEmail returns the authenticated email in the session
// of the given cookies.
func oidcReadAuthenticatedEmail(router *gin.Engine, cookies []*http.Cookie) string {
	var email string
	router.GET("/__oidc_read_authenticated_email", func(c *gin.Context) {
		email = getAuthenticatedEmailFromGinContext(c)
	})

	req, _ := http.NewRequest(http.MethodGet, "/__oidc_read_authenticated_email", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	router.ServeHTTP(httptest.NewRecorder(), req)
	return email
}

func TestOIDCCallback_TokenExchangeFailure_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))

	google := oidcNewFakeGoogle(t, "alex@test.com")
	google.tokenStatusCode = http.StatusBadRequest
	req := oidcCallbackRequest(google)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCCallback_NoIDToken_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))

	google := oidcNewFakeGoogle(t, "alex@test.com")
	google.idToken = ""
	req := oidcCallbackRequest(google)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCCallback_InvalidIDToken_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))

	google := oidcNewFakeGoogle(t, "alex@test.com")
	// signed by a key other than the one published
	google.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := oidcCallbackRequest(google)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCCallback_UserQueryError_ReturnsUnauthorized(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("alex@test.com", 1).
		WillReturnError(errors.New("database error"))

	req := oidcCallbackRequest(oidcNewFakeGoogle(t, "alex@test.com"))
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCCallback_SignInUserNotFound_ReturnsUnauthorized(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))
	oidcExpectUserNotFound(mock, "alex@test.com")

	req := oidcCallbackRequest(oidcNewFakeGoogle(t, "alex@test.com"))
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Empty(t, oidcReadAuthenticatedEmail(router, req.Cookies()))
}

func TestOIDCCallback_UserDisabled_ReturnsUnauthorized(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))
	oidcExpectGetUser(mock, "alex@test.com", false)

	req := oidcCallbackRequest(oidcNewFakeGoogle(t, "alex@test.com"))
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Empty(t, oidcReadAuthenticatedEmail(router, req.Cookies()))
}

func TestOIDCCallback_SignIn_ReturnsFound(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))
	oidcExpectGetUser(mock, "alex@test.com", true)

	req := oidcCallbackRequest(oidcNewFakeGoogle(t, "alex@test.com"))
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/authorize", w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Equal(t, "alex@test.com", oidcReadAuthenticatedEmail(router, req.Cookies()))
}

func TestOIDCCallback_SignUpNewUser_ReturnsFound(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))
	oidcExpectUserNotFound(mock, "new@test.com")
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "users"`)).
		WithArgs("new@test.com", sqlmock.AnyArg(), "", true).
		WillReturnRows(sqlmock.NewRows([]string{"web_authn_user_id"}).AddRow("6f1c3b4e-7a52-4d8e-9a0f-2b3c4d5e6f70"))
	mock.ExpectCommit()

	req := oidcCallbackRequest(oidcNewFakeGoogle(t, "new@test.com"))
	w := serveInSession(t, router, oidcSignUpSessionValues(t, ""), req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/authenticated", w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Equal(t, "new@test.com", oidcReadAuthenticatedEmail(router, req.Cookies()))
}

func TestOIDCCallback_SignUpCreateUserError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))
	oidcExpectUserNotFound(mock, "new@test.com")
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "users"`)).
		WillReturnError(errors.New("database error"))
	mock.ExpectRollback()

	req := oidcCallbackRequest(oidcNewFakeGoogle(t, "new@test.com"))
	w := serveInSession(t, router, oidcSignUpSessionValues(t, ""), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Empty(t, oidcReadAuthenticatedEmail(router, req.Cookies()))
}

// getUserInformationFromOIDCProviderCallback Tests with a fake Google

func TestGetUserInformationFromOIDCProviderCallback_GoogleValidIDToken_ReturnsEmail(t *testing.T) {
	google := oidcNewFakeGoogle(t, "alex@test.com")
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = oidcCallbackRequest(google)
	token := (&oauth2.Token{AccessToken: "access-token"}).WithExtra(map[string]interface{}{
		"id_token": google.idToken,
	})

	email, err := getUserInformationFromOIDCProviderCallback(&db.OidcClient{Name: string(Google), ClientID: oidcTestGoogleClientID}, token, c)

	assert.NoError(t, err)
	assert.Equal(t, "alex@test.com", email)
}

func TestGetUserInformationFromOIDCProviderCallback_GoogleOtherAudience_ReturnsError(t *testing.T) {
	google := oidcNewFakeGoogle(t, "alex@test.com")
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = oidcCallbackRequest(google)
	token := (&oauth2.Token{AccessToken: "access-token"}).WithExtra(map[string]interface{}{
		"id_token": google.idToken,
	})

	email, err := getUserInformationFromOIDCProviderCallback(&db.OidcClient{Name: string(Google), ClientID: "other-client-id"}, token, c)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to verify ID token")
	assert.Empty(t, email)
}

func TestGetUserInformationFromOIDCProviderCallback_GoogleDiscoveryFailure_ReturnsError(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	client := &http.Client{Transport: &oidcRoundTripper{handler: http.NotFoundHandler()}}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	c.Request, _ = http.NewRequestWithContext(ctx, http.MethodGet, "/signin/google/callback", nil)
	token := (&oauth2.Token{AccessToken: "access-token"}).WithExtra(map[string]interface{}{
		"id_token": "id-token",
	})

	email, err := getUserInformationFromOIDCProviderCallback(&db.OidcClient{Name: string(Google), ClientID: oidcTestGoogleClientID}, token, c)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to get ID token provider")
	assert.Empty(t, email)
}
