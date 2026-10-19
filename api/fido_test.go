package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

const fidoTestEmail = "alex@test.com"

// fidoTestCredentialCreationBody is a parsable registration response taken
// from the test vectors of go-webauthn. It is issued for origin
// https://webauthn.io and thus fails verification against the test service.
const fidoTestCredentialCreationBody = `{
	"id":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"rawId":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"type":"public-key",
	"authenticatorAttachment":"platform",
	"clientExtensionResults":{"appid":true},
	"response":{
		"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw",
		"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
		"transports":["usb","nfc"]
	}
}`

// fidoTestCredentialAssertionBody is a parsable assertion response taken from
// the test vectors of go-webauthn. It is issued for origin
// https://webauthn.io and thus fails validation against the test service.
const fidoTestCredentialAssertionBody = `{
	"id":"AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
	"rawId":"AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
	"clientExtensionResults":{"vendorAppID":"example.com"},
	"type":"public-key",
	"response":{
		"authenticatorData":"dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiGa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ",
		"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJFNFBUY0lIX0hmWDFwQzZTaWdrMVNDOU5BbGdlenROMDQzOXZpOHpfYzlrIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9",
		"signature":"MEUCIBtIVOQxzFYdyWQyxaLR0tik1TnuPhGVhXVSNgFwLmN5AiEAnxXdCq0UeAVGWxOaFcjBZ_mEZoXqNboY5IkQDdlWZYc",
		"userHandle":"0ToAAAAAAAAAAA"
	}
}`

func fidoTestService(t *testing.T) *FidoService {
	t.Helper()

	w, err := webauthn.New(&webauthn.Config{
		RPID:          "test.com",
		RPDisplayName: "test",
		RPOrigins:     []string{"https://test.com"},
	})
	assert.NoError(t, err)
	return NewFidoService(w)
}

// fidoTestRouterWithoutDatabase returns a router without a database
// connection in its context.
func fidoTestRouterWithoutDatabase() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func fidoUserColumns() []string {
	return []string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}
}

// fidoExpectGetUser sets up the queries of db.GetUser for an existing user
// with the given credential rows.
func fidoExpectGetUser(mock sqlmock.Sqlmock, email string, isEnabled bool, credentials *sqlmock.Rows) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs(email, 1).
		WillReturnRows(sqlmock.NewRows(fidoUserColumns()).
			AddRow(email, []byte("hash"), "Alex", nil, isEnabled))
	if credentials == nil {
		credentials = sqlmock.NewRows([]string{"id", "user_email", "friendly_name"})
	}
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE "user_credentials"."user_email" = $1`)).
		WithArgs(email).
		WillReturnRows(credentials)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_email" = $1`)).
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "role_name"}))
}

func fidoExpectUserNotFound(mock sqlmock.Sqlmock, email string) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs(email, 1).
		WillReturnRows(sqlmock.NewRows(fidoUserColumns()))
}

func fidoExpectUserQueryError(mock sqlmock.Sqlmock, email string) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs(email, 1).
		WillReturnError(errors.New("database error"))
}

// fidoCredentialRows returns a single credential so that a login can begin.
func fidoCredentialRows(email string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "public_key", "attestation_type", "user_email", "friendly_name"}).
		AddRow([]byte("credential-id"), []byte("public-key"), "none", email, "My key")
}

// fidoWebAuthnSessionJSON returns a serialised webauthn session.
func fidoWebAuthnSessionJSON(t *testing.T) string {
	t.Helper()

	sessionJSON, err := json.Marshal(webauthn.SessionData{
		Challenge: "challenge",
		UserID:    []byte("user-id"),
	})
	assert.NoError(t, err)
	return string(sessionJSON)
}

// fidoReadSession reads values of the given keys from the session of the
// given cookies. Note that it can only be called once per router.
func fidoReadSession(t *testing.T, router *gin.Engine, cookies []*http.Cookie, keys ...string) map[string]interface{} {
	t.Helper()

	values := map[string]interface{}{}
	router.GET("/__fido_read_session", func(c *gin.Context) {
		for _, key := range keys {
			if value, ok := getValueFromSession(c, key); ok {
				values[key] = value
			}
		}
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/__fido_read_session", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	router.ServeHTTP(w, req)
	return values
}

func fidoJSONRequest(method string, path string, body string) *http.Request {
	req, _ := http.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// RegisterChallenge Tests

func TestRegisterChallenge_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := fidoTestRouterWithoutDatabase()
	router.POST("/fido/register/challenge", fidoTestService(t).RegisterChallenge)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/fido/register/challenge", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRegisterChallenge_UserQueryError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/register/challenge", fidoTestService(t).RegisterChallenge)

	fidoExpectUserQueryError(mock, fidoTestEmail)

	req, _ := http.NewRequest(http.MethodPost, "/fido/register/challenge", nil)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegisterChallenge_UserNotFound_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/register/challenge", fidoTestService(t).RegisterChallenge)

	fidoExpectUserNotFound(mock, fidoTestEmail)

	req, _ := http.NewRequest(http.MethodPost, "/fido/register/challenge", nil)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegisterChallenge_CredentialDescriptorsQueryError_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/register/challenge", fidoTestService(t).RegisterChallenge)

	fidoExpectGetUser(mock, fidoTestEmail, true, nil)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs(fidoTestEmail).
		WillReturnError(errors.New("database error"))

	req, _ := http.NewRequest(http.MethodPost, "/fido/register/challenge", nil)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegisterChallenge_Success_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/register/challenge", fidoTestService(t).RegisterChallenge)

	fidoExpectGetUser(mock, fidoTestEmail, true, nil)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs(fidoTestEmail).
		WillReturnRows(sqlmock.NewRows([]string{"id", "attestation_type", "user_email", "friendly_name"}).
			AddRow([]byte("existing-id"), "none", fidoTestEmail, "Existing key"))

	req, _ := http.NewRequest(http.MethodPost, "/fido/register/challenge", nil)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())

	var creation protocol.CredentialCreation
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &creation))
	assert.NotEmpty(t, creation.Response.Challenge)
	assert.Equal(t, "test.com", creation.Response.RelyingParty.ID)
	assert.Equal(t, fidoTestEmail, creation.Response.User.Name)
	assert.Len(t, creation.Response.CredentialExcludeList, 1)
	assert.Equal(t, protocol.URLEncodedBase64("existing-id"), creation.Response.CredentialExcludeList[0].CredentialID)

	values := fidoReadSession(t, router, req.Cookies(), sessionWebAuthnSessionKey)
	assert.Contains(t, values, sessionWebAuthnSessionKey)
	var sessionData webauthn.SessionData
	sessionJSON, _ := values[sessionWebAuthnSessionKey].(string)
	assert.NoError(t, json.Unmarshal([]byte(sessionJSON), &sessionData))
	assert.Equal(t, creation.Response.Challenge.String(), sessionData.Challenge)
}

// Register Tests

func TestRegister_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := fidoTestRouterWithoutDatabase()
	router.POST("/fido/register", fidoTestService(t).Register)

	w := httptest.NewRecorder()
	req := fidoJSONRequest(http.MethodPost, "/fido/register", fidoTestCredentialCreationBody)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRegister_MalformedBody_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/register", fidoTestService(t).Register)

	w := httptest.NewRecorder()
	req := fidoJSONRequest(http.MethodPost, "/fido/register", `{"invalid`)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegister_InvalidCredential_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/register", fidoTestService(t).Register)

	w := httptest.NewRecorder()
	req := fidoJSONRequest(http.MethodPost, "/fido/register", `{"id":"abc","type":"public-key"}`)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegister_UserQueryError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/register", fidoTestService(t).Register)

	fidoExpectUserQueryError(mock, fidoTestEmail)

	req := fidoJSONRequest(http.MethodPost, "/fido/register", fidoTestCredentialCreationBody)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegister_UserNotFound_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/register", fidoTestService(t).Register)

	fidoExpectUserNotFound(mock, fidoTestEmail)

	req := fidoJSONRequest(http.MethodPost, "/fido/register", fidoTestCredentialCreationBody)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegister_NoWebAuthnSession_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/register", fidoTestService(t).Register)

	fidoExpectGetUser(mock, fidoTestEmail, true, nil)

	req := fidoJSONRequest(http.MethodPost, "/fido/register", fidoTestCredentialCreationBody)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegister_VerificationFailure_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/register", fidoTestService(t).Register)

	fidoExpectGetUser(mock, fidoTestEmail, true, nil)

	sessionValues := authenticatedSession(fidoTestEmail)
	sessionValues[sessionWebAuthnSessionKey] = fidoWebAuthnSessionJSON(t)

	req := fidoJSONRequest(http.MethodPost, "/fido/register", fidoTestCredentialCreationBody)
	w := serveInSession(t, router, sessionValues, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// LoginChallenge Tests

func TestLoginChallenge_NoEmailInSession_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/challenge", fidoTestService(t).LoginChallenge)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/fido/signin/challenge", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginChallenge_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := fidoTestRouterWithoutDatabase()
	router.POST("/fido/signin/challenge", fidoTestService(t).LoginChallenge)

	req, _ := http.NewRequest(http.MethodPost, "/fido/signin/challenge", nil)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: fidoTestEmail}, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestLoginChallenge_UserQueryError_ReturnsUnauthorized(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/challenge", fidoTestService(t).LoginChallenge)

	fidoExpectUserQueryError(mock, fidoTestEmail)

	req, _ := http.NewRequest(http.MethodPost, "/fido/signin/challenge", nil)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: fidoTestEmail}, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginChallenge_UserNotFound_ReturnsUnauthorized(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/challenge", fidoTestService(t).LoginChallenge)

	fidoExpectUserNotFound(mock, fidoTestEmail)

	req, _ := http.NewRequest(http.MethodPost, "/fido/signin/challenge", nil)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: fidoTestEmail}, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginChallenge_UserDisabled_ReturnsUnauthorized(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/challenge", fidoTestService(t).LoginChallenge)

	fidoExpectGetUser(mock, fidoTestEmail, false, fidoCredentialRows(fidoTestEmail))

	req, _ := http.NewRequest(http.MethodPost, "/fido/signin/challenge", nil)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: fidoTestEmail}, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginChallenge_UserWithoutCredentials_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/challenge", fidoTestService(t).LoginChallenge)

	fidoExpectGetUser(mock, fidoTestEmail, true, nil)

	req, _ := http.NewRequest(http.MethodPost, "/fido/signin/challenge", nil)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: fidoTestEmail}, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginChallenge_ExternalRedirectURI_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/challenge", fidoTestService(t).LoginChallenge)

	req, _ := http.NewRequest(http.MethodPost, "/fido/signin/challenge?redirect_uri=https%3A%2F%2Fevil.com", nil)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: fidoTestEmail}, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginChallenge_Success_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/challenge", fidoTestService(t).LoginChallenge)

	fidoExpectGetUser(mock, fidoTestEmail, true, fidoCredentialRows(fidoTestEmail))

	req, _ := http.NewRequest(http.MethodPost, "/fido/signin/challenge?redirect_uri=/authorize%3Fclient_id%3Dcli", nil)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: fidoTestEmail}, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())

	var assertion protocol.CredentialAssertion
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	assert.NotEmpty(t, assertion.Response.Challenge)
	assert.Equal(t, "test.com", assertion.Response.RelyingPartyID)
	assert.Len(t, assertion.Response.AllowedCredentials, 1)
	assert.Equal(t, protocol.URLEncodedBase64("credential-id"), assertion.Response.AllowedCredentials[0].CredentialID)

	values := fidoReadSession(t, router, req.Cookies(), sessionRedirectURLKey, sessionWebAuthnSessionKey)
	assert.Equal(t, "/authorize?client_id=cli", values[sessionRedirectURLKey])
	assert.Contains(t, values, sessionWebAuthnSessionKey)
	var sessionData webauthn.SessionData
	sessionJSON, _ := values[sessionWebAuthnSessionKey].(string)
	assert.NoError(t, json.Unmarshal([]byte(sessionJSON), &sessionData))
	assert.Equal(t, assertion.Response.Challenge.String(), sessionData.Challenge)
}

// Login Tests

func TestLogin_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := fidoTestRouterWithoutDatabase()
	router.POST("/fido/signin", fidoTestService(t).Login)

	w := httptest.NewRecorder()
	req := fidoJSONRequest(http.MethodPost, "/fido/signin", fidoTestCredentialAssertionBody)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestLogin_MalformedBody_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", fidoTestService(t).Login)

	w := httptest.NewRecorder()
	req := fidoJSONRequest(http.MethodPost, "/fido/signin", `{"invalid`)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_InvalidAssertion_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", fidoTestService(t).Login)

	w := httptest.NewRecorder()
	req := fidoJSONRequest(http.MethodPost, "/fido/signin", `{"id":"abc","type":"public-key"}`)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_NoEmailInSession_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", fidoTestService(t).Login)

	w := httptest.NewRecorder()
	req := fidoJSONRequest(http.MethodPost, "/fido/signin", fidoTestCredentialAssertionBody)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_UserQueryError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", fidoTestService(t).Login)

	fidoExpectUserQueryError(mock, fidoTestEmail)

	req := fidoJSONRequest(http.MethodPost, "/fido/signin", fidoTestCredentialAssertionBody)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: fidoTestEmail}, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_UserNotFound_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", fidoTestService(t).Login)

	fidoExpectUserNotFound(mock, fidoTestEmail)

	req := fidoJSONRequest(http.MethodPost, "/fido/signin", fidoTestCredentialAssertionBody)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: fidoTestEmail}, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_NoWebAuthnSession_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", fidoTestService(t).Login)

	fidoExpectGetUser(mock, fidoTestEmail, true, fidoCredentialRows(fidoTestEmail))

	req := fidoJSONRequest(http.MethodPost, "/fido/signin", fidoTestCredentialAssertionBody)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: fidoTestEmail}, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_ValidationFailure_ReturnsUnauthorized(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", fidoTestService(t).Login)

	fidoExpectGetUser(mock, fidoTestEmail, true, fidoCredentialRows(fidoTestEmail))

	sessionValues := map[string]interface{}{
		sessionEmailKey:           fidoTestEmail,
		sessionWebAuthnSessionKey: fidoWebAuthnSessionJSON(t),
	}
	req := fidoJSONRequest(http.MethodPost, "/fido/signin", fidoTestCredentialAssertionBody)
	w := serveInSession(t, router, sessionValues, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())

	values := fidoReadSession(t, router, req.Cookies(), sessionIsAuthenticatedKey)
	assert.NotContains(t, values, sessionIsAuthenticatedKey)
}

// GetCredentials Tests

func TestGetCredentials_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := fidoTestRouterWithoutDatabase()
	router.GET("/fido/credentials", fidoTestService(t).GetCredentials)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/fido/credentials", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetCredentials_QueryError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/fido/credentials", fidoTestService(t).GetCredentials)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs(fidoTestEmail).
		WillReturnError(errors.New("database error"))

	req, _ := http.NewRequest(http.MethodGet, "/fido/credentials", nil)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetCredentials_Success_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/fido/credentials", fidoTestService(t).GetCredentials)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs(fidoTestEmail).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "friendly_name"}).
			AddRow([]byte("id-1"), fidoTestEmail, "Key 1").
			AddRow([]byte("id-2"), fidoTestEmail, "Key 2"))

	req, _ := http.NewRequest(http.MethodGet, "/fido/credentials", nil)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())

	var credentials []CredentialInfo
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &credentials))
	assert.Equal(t, []CredentialInfo{
		{ID: []byte("id-1"), Name: "Key 1"},
		{ID: []byte("id-2"), Name: "Key 2"},
	}, credentials)
}

// DeleteCredential Tests

func fidoCredentialID() string {
	return base64.RawURLEncoding.EncodeToString([]byte("credential-id"))
}

func fidoExpectFindCredential(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1 AND id = $2 ORDER BY "user_credentials"."id" LIMIT $3`)).
		WithArgs(fidoTestEmail, []byte("credential-id"), 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "public_key", "attestation_type", "user_email", "friendly_name"}).
			AddRow([]byte("credential-id"), []byte("public-key"), "none", fidoTestEmail, "My key"))
}

func TestDeleteCredential_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := fidoTestRouterWithoutDatabase()
	router.DELETE("/fido/credentials/:id", fidoTestService(t).DeleteCredential)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/fido/credentials/"+fidoCredentialID(), nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteCredential_InvalidID_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.DELETE("/fido/credentials/:id", fidoTestService(t).DeleteCredential)

	req, _ := http.NewRequest(http.MethodDelete, "/fido/credentials/not+base64url=", nil)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteCredential_DatabaseError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.DELETE("/fido/credentials/:id", fidoTestService(t).DeleteCredential)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1 AND id = $2 ORDER BY "user_credentials"."id" LIMIT $3`)).
		WithArgs(fidoTestEmail, []byte("credential-id"), 1).
		WillReturnError(errors.New("database error"))

	req, _ := http.NewRequest(http.MethodDelete, "/fido/credentials/"+fidoCredentialID(), nil)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteCredential_Success_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.DELETE("/fido/credentials/:id", fidoTestService(t).DeleteCredential)

	fidoExpectFindCredential(mock)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "user_credentials" WHERE "user_credentials"."id" = $1`)).
		WithArgs([]byte("credential-id")).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	req, _ := http.NewRequest(http.MethodDelete, "/fido/credentials/"+fidoCredentialID(), nil)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// UpdateCredential Tests

func TestUpdateCredential_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := fidoTestRouterWithoutDatabase()
	router.PATCH("/fido/credentials/:id", fidoTestService(t).UpdateCredential)

	w := httptest.NewRecorder()
	req := fidoJSONRequest(http.MethodPatch, "/fido/credentials/"+fidoCredentialID(), `{"name":"New name"}`)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateCredential_InvalidID_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/fido/credentials/:id", fidoTestService(t).UpdateCredential)

	req := fidoJSONRequest(http.MethodPatch, "/fido/credentials/not+base64url=", `{"name":"New name"}`)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// Note that a malformed request body is reported as an internal server error
// rather than a bad request.
func TestUpdateCredential_MalformedBody_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/fido/credentials/:id", fidoTestService(t).UpdateCredential)

	req := fidoJSONRequest(http.MethodPatch, "/fido/credentials/"+fidoCredentialID(), `{"invalid`)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateCredential_MissingName_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/fido/credentials/:id", fidoTestService(t).UpdateCredential)

	req := fidoJSONRequest(http.MethodPatch, "/fido/credentials/"+fidoCredentialID(), `{}`)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateCredential_CredentialNotFound_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/fido/credentials/:id", fidoTestService(t).UpdateCredential)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1 AND id = $2 ORDER BY "user_credentials"."id" LIMIT $3`)).
		WithArgs(fidoTestEmail, []byte("credential-id"), 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "friendly_name"}))

	req := fidoJSONRequest(http.MethodPatch, "/fido/credentials/"+fidoCredentialID(), `{"name":"New name"}`)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateCredential_DuplicatedName_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/fido/credentials/:id", fidoTestService(t).UpdateCredential)

	fidoExpectFindCredential(mock)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_credentials" SET`)).
		WillReturnError(gorm.ErrDuplicatedKey)
	mock.ExpectRollback()

	req := fidoJSONRequest(http.MethodPatch, "/fido/credentials/"+fidoCredentialID(), `{"name":"New name"}`)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateCredential_DatabaseError_ReturnsInternalServerError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/fido/credentials/:id", fidoTestService(t).UpdateCredential)

	fidoExpectFindCredential(mock)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_credentials" SET`)).
		WillReturnError(errors.New("database error"))
	mock.ExpectRollback()

	req := fidoJSONRequest(http.MethodPatch, "/fido/credentials/"+fidoCredentialID(), `{"name":"New name"}`)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateCredential_Success_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/fido/credentials/:id", fidoTestService(t).UpdateCredential)

	fidoExpectFindCredential(mock)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_credentials" SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	req := fidoJSONRequest(http.MethodPatch, "/fido/credentials/"+fidoCredentialID(), `{"name":"New name"}`)
	w := serveInSession(t, router, authenticatedSession(fidoTestEmail), req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}
