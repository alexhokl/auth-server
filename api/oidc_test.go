package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

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
		Nonce:                   oidcTestNonce,
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

func TestRedirectToOIDCEndpoint_ExternalRedirectURI_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/:action/:oidc_name/start", RedirectToOIDCEndpoint)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/signin/google/start?redirect_uri=https%3A%2F%2Fevil.com", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
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

			var session *oidcSession
			var sessionErr error
			router.GET("/__oidc_read_session", func(c *gin.Context) {
				session, sessionErr = getOIDCSession(c)
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
			assert.NotEmpty(t, query.Get("nonce"))

			// the OIDC session is saved for the callback
			readReq, _ := http.NewRequest(http.MethodGet, "/__oidc_read_session", nil)
			for _, cookie := range w.Result().Cookies() {
				readReq.AddCookie(cookie)
			}
			router.ServeHTTP(httptest.NewRecorder(), readReq)

			assert.NoError(t, sessionErr)
			assert.Equal(t, query.Get("state"), session.State)
			assert.Equal(t, query.Get("nonce"), session.Nonce)
			assert.Equal(t, pkceChallengeMethod, session.PKCECodeChallengeMethod)
			assert.Equal(t, query.Get("code_challenge"), session.PKCECodeChallenge)
			assert.NotEmpty(t, session.PKCECodeVerifier)
			assert.Equal(t, "/authorize", session.RedirectURI)
			assert.Equal(t, action == "signup", session.IsSignUp)
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

func TestOIDCCallback_ValidState_DeletesOIDCSession(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))
	oidcExpectGetUser(mock, "alex@test.com", true)

	req := oidcCallbackRequest(oidcNewFakeGoogle(t, "alex@test.com"))
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())

	// the same state cannot be used again
	replay := oidcCallbackRequest(oidcNewFakeGoogle(t, "alex@test.com"))
	for _, cookie := range req.Cookies() {
		replay.AddCookie(cookie)
	}
	replayResponse := httptest.NewRecorder()
	router.ServeHTTP(replayResponse, replay)

	assert.Equal(t, http.StatusInternalServerError, replayResponse.Code)
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
	router, dbConn, _ := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	queried := false
	assert.NoError(t, dbConn.Callback().Query().Before("gorm:query").Register("oidc_test:queried", func(*gorm.DB) {
		queried = true
	}))

	req, _ := http.NewRequest(http.MethodGet, "/signin/google/callback?state=expected-state&error=access_denied", nil)
	w := serveInSession(t, router, oidcSessionValues(t, "expected-state"), req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.False(t, queried, "OIDC client must not be looked up after an error from the provider")
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
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "oidc_clients" ("name","client_id","client_secret","redirect_uri","button_name","issuer","team_id","key_id") VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`)).
		WithArgs("google", "google-client-id", "google-client-secret", "https://test.com/signin/google/callback", "Sign in with Google", "", "", "").
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

func oidcSignUpSessionValues(t *testing.T, redirectURI string) map[string]interface{} {
	t.Helper()

	sessionJSON, err := json.Marshal(oidcSession{
		State:                   "expected-state",
		PKCECodeChallengeMethod: pkceChallengeMethod,
		PKCECodeChallenge:       "challenge",
		PKCECodeVerifier:        "verifier",
		Nonce:                   oidcTestNonce,
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
	google.key = oidcTestRSAKey(t)
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
		WithArgs("new@test.com", sqlmock.AnyArg(), "", true, sqlmock.AnyArg(), nil).
		WillReturnRows(sqlmock.NewRows([]string{"web_authn_user_id"}).AddRow("6f1c3b4e-7a52-4d8e-9a0f-2b3c4d5e6f70"))
	mock.ExpectCommit()

	req := oidcCallbackRequest(oidcNewFakeGoogle(t, "new@test.com"))
	w := serveInSession(t, router, oidcSignUpSessionValues(t, ""), req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/authenticated", w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Equal(t, "new@test.com", oidcReadAuthenticatedEmail(router, req.Cookies()))
}

func TestOIDCCallback_SignUpExistingUser_SignsIn(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))
	oidcExpectGetUser(mock, "alex@test.com", true)

	req := oidcCallbackRequest(oidcNewFakeGoogle(t, "alex@test.com"))
	w := serveInSession(t, router, oidcSignUpSessionValues(t, ""), req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/authenticated", w.Header().Get("Location"))
	// no user is inserted
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Equal(t, "alex@test.com", oidcReadAuthenticatedEmail(router, req.Cookies()))
}

func TestOIDCCallback_SignUpExistingDisabledUser_ReturnsUnauthorized(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/signin/:oidc_name/callback", OIDCCallback)

	oidcExpectGetClient(mock, "google").WillReturnRows(oidcTestClientRows("google"))
	oidcExpectGetUser(mock, "alex@test.com", false)

	req := oidcCallbackRequest(oidcNewFakeGoogle(t, "alex@test.com"))
	w := serveInSession(t, router, oidcSignUpSessionValues(t, ""), req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.Empty(t, oidcReadAuthenticatedEmail(router, req.Cookies()))
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
