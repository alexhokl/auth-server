package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// fidoTestChallenge is a challenge as it is stored in a WebAuthn session,
// which is the base64url encoding of random bytes.
const fidoTestChallenge = "1zN3SAmD8pBfdRmQzrTdC5f0DjRfcvMHU5KWqf3TUjM"

var fidoTestUserID = uuid.MustParse("6f4e0c6a-3f7d-4a44-9a0b-5c7b9b6d1e21")

var fidoTestCredentialID = []byte("passkey-credential-id")

// fidoTestAuthenticator signs assertions with a P-256 key.
type fidoTestAuthenticator struct {
	key            *ecdsa.PrivateKey
	backupEligible bool
}

func newFidoTestAuthenticator(t *testing.T) *fidoTestAuthenticator {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	return &fidoTestAuthenticator{key: key}
}

// publicKey returns the COSE encoding of the public key as it is stored in a
// credential.
func (a *fidoTestAuthenticator) publicKey(t *testing.T) []byte {
	t.Helper()

	x := make([]byte, 32)
	y := make([]byte, 32)
	a.key.PublicKey.X.FillBytes(x)
	a.key.PublicKey.Y.FillBytes(y)
	publicKey, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: x,
		YCoord: y,
	})
	assert.NoError(t, err)
	return publicKey
}

// credentialRows returns the credential of the authenticator with the given
// stored sign counter and clone warning.
func (a *fidoTestAuthenticator) credentialRows(t *testing.T, email string, signCount uint32, cloneWarning bool) *sqlmock.Rows {
	t.Helper()

	return sqlmock.NewRows([]string{"id", "public_key", "attestation_type", "user_present", "user_verified", "backup_eligible", "backup_state", "sign_count", "clone_warning", "user_email", "friendly_name"}).
		AddRow(fidoTestCredentialID, a.publicKey(t), "none", true, true, a.backupEligible, false, signCount, cloneWarning, email, "My passkey")
}

// assertionBody returns an assertion of the challenge in fidoTestChallenge
// with the given counter and user handle.
func (a *fidoTestAuthenticator) assertionBody(t *testing.T, counter uint32, userHandle []byte) string {
	t.Helper()

	rpIDHash := sha256.Sum256([]byte("test.com"))
	flags := protocol.FlagUserPresent | protocol.FlagUserVerified
	if a.backupEligible {
		flags |= protocol.FlagBackupEligible | protocol.FlagBackupState
	}
	authenticatorData := append([]byte{}, rpIDHash[:]...)
	authenticatorData = append(authenticatorData, byte(flags))
	authenticatorData = binary.BigEndian.AppendUint32(authenticatorData, counter)

	// the front end encodes the characters of the stored challenge, which
	// pairs with the re-encoding on the server
	clientDataJSON, err := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString([]byte(fidoTestChallenge)),
		"origin":    "https://test.com",
	})
	assert.NoError(t, err)

	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := sha256.Sum256(append(append([]byte{}, authenticatorData...), clientDataHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, signed[:])
	assert.NoError(t, err)

	encode := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]interface{}{
		"id":    encode(fidoTestCredentialID),
		"rawId": encode(fidoTestCredentialID),
		"type":  "public-key",
		"response": map[string]string{
			"authenticatorData": encode(authenticatorData),
			"clientDataJSON":    encode(clientDataJSON),
			"signature":         encode(signature),
			"userHandle":        encode(userHandle),
		},
	})
	assert.NoError(t, err)
	return string(body)
}

// fidoUserHandle is the user handle of fidoTestUserID, as returned by a
// passkey.
func fidoUserHandle() []byte {
	return []byte(fidoTestUserID.String())
}

// fidoLoginSessionJSON returns the WebAuthn session of an email-first sign-in
// of the user of fidoTestUserID.
func fidoLoginSessionJSON(t *testing.T) string {
	t.Helper()

	sessionJSON, err := json.Marshal(webauthn.SessionData{
		Challenge:        fidoTestChallenge,
		UserID:           fidoUserHandle(),
		UserVerification: protocol.VerificationRequired,
	})
	assert.NoError(t, err)
	return string(sessionJSON)
}

// fidoPasskeySessionJSON returns the WebAuthn session of a discoverable
// sign-in.
func fidoPasskeySessionJSON(t *testing.T) string {
	t.Helper()

	sessionJSON, err := json.Marshal(webauthn.SessionData{
		Challenge:        fidoTestChallenge,
		UserVerification: protocol.VerificationRequired,
	})
	assert.NoError(t, err)
	return string(sessionJSON)
}

func fidoUserRows(email string, isEnabled bool) *sqlmock.Rows {
	return sqlmock.NewRows(fidoUserColumns()).
		AddRow(email, []byte("hash"), "Alex", fidoTestUserID, isEnabled)
}

func fidoExpectAssociations(mock sqlmock.Sqlmock, email string, credentials *sqlmock.Rows) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE "user_credentials"."user_email" = $1`)).
		WithArgs(email).
		WillReturnRows(credentials)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_email" = $1`)).
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "role_name"}))
}

// fidoExpectGetUserWithCredential sets up the queries of db.GetUser for the
// user of fidoTestUserID.
func fidoExpectGetUserWithCredential(mock sqlmock.Sqlmock, email string, isEnabled bool, credentials *sqlmock.Rows) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs(email, 1).
		WillReturnRows(fidoUserRows(email, isEnabled))
	fidoExpectAssociations(mock, email, credentials)
}

const fidoGetUserByWebAuthnIDQuery = `SELECT * FROM "users" WHERE web_authn_user_id = $1 ORDER BY "users"."email" LIMIT $2`

// fidoExpectGetUserByWebAuthnID sets up the queries of
// db.GetUserByWebAuthnID for the user of fidoTestUserID.
func fidoExpectGetUserByWebAuthnID(mock sqlmock.Sqlmock, email string, isEnabled bool, credentials *sqlmock.Rows) {
	mock.ExpectQuery(regexp.QuoteMeta(fidoGetUserByWebAuthnIDQuery)).
		WithArgs(fidoTestUserID, 1).
		WillReturnRows(fidoUserRows(email, isEnabled))
	fidoExpectAssociations(mock, email, credentials)
}

// fidoExpectUpdateCredentialAuthenticator sets up the write-back of a
// credential after a sign-in.
func fidoExpectUpdateCredentialAuthenticator(mock sqlmock.Sqlmock, email string, signCount uint32, cloneWarning bool) {
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_credentials" SET "backup_state"=$1,"clone_warning"=$2,"sign_count"=$3 WHERE user_email = $4 AND id = $5`)).
		WithArgs(false, cloneWarning, signCount, email, fidoTestCredentialID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

func fidoExpectUpdateCredentialAuthenticatorError(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_credentials" SET`)).
		WillReturnError(errors.New("database error"))
	mock.ExpectRollback()
}

// fidoRequestFromIP returns a JSON request from throttleTestIP.
func fidoRequestFromIP(path string, body string) *http.Request {
	req := fidoJSONRequest(http.MethodPost, path, body)
	req.RemoteAddr = throttleTestIP + ":1234"
	return req
}

// fidoServeAgain serves another request with the cookies of req.
func fidoServeAgain(router *gin.Engine, req *http.Request, path string, body string) *httptest.ResponseRecorder {
	again := fidoJSONRequest(http.MethodPost, path, body)
	for _, cookie := range req.Cookies() {
		again.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, again)
	return w
}

func fidoFailureCounts(t *testing.T, throttle *SignInThrottle, email string) (int64, int64) {
	t.Helper()

	emailCount, err := throttle.store.Count(context.Background(), signInFailureEmailKey(email))
	assert.NoError(t, err)
	ipCount, err := throttle.store.Count(context.Background(), signInFailureIPKey(throttleTestIP))
	assert.NoError(t, err)
	return emailCount, ipCount
}

// Content type Tests

func TestFidoSignIn_NonJSONRequest_ReturnsBadRequest(t *testing.T) {
	service := fidoTestService(t)
	tests := []struct {
		path    string
		handler gin.HandlerFunc
	}{
		{"/fido/signin/challenge", service.LoginChallenge},
		{"/fido/signin", service.Login},
		{"/fido/signin/passkey/challenge", service.PasskeyLoginChallenge},
		{"/fido/signin/passkey", service.PasskeyLogin},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			router, _, mock := getTestRouter()
			router.POST(test.path, test.handler)

			sessionValues := map[string]interface{}{
				sessionEmailKey:           fidoTestEmail,
				sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t),
			}
			req := userFormRequest(http.MethodPost, test.path, map[string]string{"id": "abc"})
			req.Header.Set("Content-Type", "text/plain")
			w := serveInSession(t, router, sessionValues, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.NoError(t, mock.ExpectationsWereMet())

			// the pending challenge is left untouched
			values := fidoReadSession(t, router, req.Cookies(), sessionWebAuthnSessionKey)
			assert.Contains(t, values, sessionWebAuthnSessionKey)
		})
	}
}

func TestFidoSignIn_JSONWithCharset_IsAccepted(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey/challenge", fidoTestService(t).PasskeyLoginChallenge)

	w := httptest.NewRecorder()
	req := fidoJSONRequest(http.MethodPost, "/fido/signin/passkey/challenge", "")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// PasskeyLoginChallenge Tests

func TestPasskeyLoginChallenge_Success_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey/challenge", fidoTestService(t).PasskeyLoginChallenge)

	req := fidoJSONRequest(http.MethodPost, "/fido/signin/passkey/challenge?redirect_uri=/authorize%3Fclient_id%3Dcli", "")
	w := serveInSession(t, router, map[string]interface{}{}, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	assert.NotContains(t, w.Body.String(), "allowCredentials")

	var assertion protocol.CredentialAssertion
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
	assert.NotEmpty(t, assertion.Response.Challenge)
	assert.Equal(t, "test.com", assertion.Response.RelyingPartyID)
	assert.Empty(t, assertion.Response.AllowedCredentials)

	values := fidoReadSession(t, router, req.Cookies(), sessionRedirectURLKey, sessionWebAuthnSessionKey)
	assert.Equal(t, "/authorize?client_id=cli", values[sessionRedirectURLKey])
	var sessionData webauthn.SessionData
	sessionJSON, _ := values[sessionWebAuthnSessionKey].(string)
	assert.NoError(t, json.Unmarshal([]byte(sessionJSON), &sessionData))
	assert.Equal(t, assertion.Response.Challenge.String(), sessionData.Challenge)
	assert.Empty(t, sessionData.UserID)
}

func TestPasskeyLoginChallenge_ExternalRedirectURI_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey/challenge", fidoTestService(t).PasskeyLoginChallenge)

	w := httptest.NewRecorder()
	req := fidoJSONRequest(http.MethodPost, "/fido/signin/passkey/challenge?redirect_uri=https%3A%2F%2Fevil.com", "")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPasskeyLoginChallenge_IPBlocked_ReturnsTooManyRequests(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, "other@test.com", throttleTestIP, 5)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey/challenge", WithSignInThrottle(throttle), fidoTestService(t).PasskeyLoginChallenge)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, fidoRequestFromIP("/fido/signin/passkey/challenge", ""))

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// PasskeyLogin Tests

func TestPasskeyLogin_NoDatabase_ReturnsInternalServerError(t *testing.T) {
	router := fidoTestRouterWithoutDatabase()
	router.POST("/fido/signin/passkey", fidoTestService(t).PasskeyLogin)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, fidoJSONRequest(http.MethodPost, "/fido/signin/passkey", fidoTestCredentialAssertionBody))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestPasskeyLogin_MalformedBody_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", fidoTestService(t).PasskeyLogin)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, fidoJSONRequest(http.MethodPost, "/fido/signin/passkey", `{"invalid`))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPasskeyLogin_NoWebAuthnSession_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", fidoTestService(t).PasskeyLogin)

	authenticator := newFidoTestAuthenticator(t)
	req := fidoJSONRequest(http.MethodPost, "/fido/signin/passkey", authenticator.assertionBody(t, 1, fidoUserHandle()))
	w := serveInSession(t, router, map[string]interface{}{}, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPasskeyLogin_UnknownUserHandle_ReturnsUnauthorized(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", WithSignInThrottle(throttle), fidoTestService(t).PasskeyLogin)
	mock.ExpectQuery(regexp.QuoteMeta(fidoGetUserByWebAuthnIDQuery)).
		WithArgs(fidoTestUserID, 1).
		WillReturnRows(sqlmock.NewRows(fidoUserColumns()))

	authenticator := newFidoTestAuthenticator(t)
	req := fidoRequestFromIP("/fido/signin/passkey", authenticator.assertionBody(t, 1, fidoUserHandle()))
	w := serveInSession(t, router, map[string]interface{}{sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t)}, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	_, ipCount := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(1), ipCount)
}

func TestPasskeyLogin_LegacyUserHandle_ReturnsUnauthorized(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", WithSignInThrottle(throttle), fidoTestService(t).PasskeyLogin)

	// a credential registered before the user handle fix holds the base64url
	// text of the handle rather than the handle itself
	legacyHandle := []byte(base64.RawURLEncoding.EncodeToString(fidoUserHandle()))
	assert.Len(t, legacyHandle, 48)

	authenticator := newFidoTestAuthenticator(t)
	req := fidoRequestFromIP("/fido/signin/passkey", authenticator.assertionBody(t, 1, legacyHandle))
	w := serveInSession(t, router, map[string]interface{}{sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t)}, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	_, ipCount := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(1), ipCount)
}

func TestPasskeyLogin_NilUserHandle_ReturnsUnauthorized(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", fidoTestService(t).PasskeyLogin)

	authenticator := newFidoTestAuthenticator(t)
	req := fidoJSONRequest(http.MethodPost, "/fido/signin/passkey", authenticator.assertionBody(t, 1, []byte(uuid.Nil.String())))
	w := serveInSession(t, router, map[string]interface{}{sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t)}, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPasskeyLogin_UserDisabled_ReturnsUnauthorized(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", WithSignInThrottle(throttle), fidoTestService(t).PasskeyLogin)

	authenticator := newFidoTestAuthenticator(t)
	fidoExpectGetUserByWebAuthnID(mock, fidoTestEmail, false, authenticator.credentialRows(t, fidoTestEmail, 0, false))

	req := fidoRequestFromIP("/fido/signin/passkey", authenticator.assertionBody(t, 1, fidoUserHandle()))
	w := serveInSession(t, router, map[string]interface{}{sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t)}, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	emailCount, ipCount := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(1), emailCount)
	assert.Equal(t, int64(1), ipCount)

	values := fidoReadSession(t, router, req.Cookies(), sessionIsAuthenticatedKey)
	assert.NotContains(t, values, sessionIsAuthenticatedKey)
}

func TestPasskeyLogin_IPBlocked_ReturnsTooManyRequests(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, "other@test.com", throttleTestIP, 5)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", WithSignInThrottle(throttle), fidoTestService(t).PasskeyLogin)

	authenticator := newFidoTestAuthenticator(t)
	req := fidoRequestFromIP("/fido/signin/passkey", authenticator.assertionBody(t, 1, fidoUserHandle()))
	w := serveInSession(t, router, map[string]interface{}{sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t)}, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	_, ipCount := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(5), ipCount)
}

func TestPasskeyLogin_EmailBlocked_ReturnsTooManyRequests(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, fidoTestEmail, "198.51.100.1", 3)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", WithSignInThrottle(throttle), fidoTestService(t).PasskeyLogin)

	authenticator := newFidoTestAuthenticator(t)
	// a blocked user gets 429 even when disabled
	fidoExpectGetUserByWebAuthnID(mock, fidoTestEmail, false, authenticator.credentialRows(t, fidoTestEmail, 0, false))

	req := fidoRequestFromIP("/fido/signin/passkey", authenticator.assertionBody(t, 1, fidoUserHandle()))
	w := serveInSession(t, router, map[string]interface{}{sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t)}, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	emailCount, ipCount := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(3), emailCount)
	assert.Equal(t, int64(0), ipCount)
}

func TestPasskeyLogin_UserQueryError_ReturnsInternalServerError(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", WithSignInThrottle(throttle), fidoTestService(t).PasskeyLogin)
	mock.ExpectQuery(regexp.QuoteMeta(fidoGetUserByWebAuthnIDQuery)).
		WithArgs(fidoTestUserID, 1).
		WillReturnError(errors.New("database error"))

	authenticator := newFidoTestAuthenticator(t)
	req := fidoRequestFromIP("/fido/signin/passkey", authenticator.assertionBody(t, 1, fidoUserHandle()))
	w := serveInSession(t, router, map[string]interface{}{sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t)}, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	_, ipCount := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(0), ipCount)
}

func TestPasskeyLogin_ValidationFailure_RecordsFailureOfUser(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", WithSignInThrottle(throttle), fidoTestService(t).PasskeyLogin)

	// the assertion is signed by another key than the stored one
	stored := newFidoTestAuthenticator(t)
	fidoExpectGetUserByWebAuthnID(mock, fidoTestEmail, true, stored.credentialRows(t, fidoTestEmail, 0, false))

	other := newFidoTestAuthenticator(t)
	req := fidoRequestFromIP("/fido/signin/passkey", other.assertionBody(t, 1, fidoUserHandle()))
	w := serveInSession(t, router, map[string]interface{}{sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t)}, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	emailCount, ipCount := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(1), emailCount)
	assert.Equal(t, int64(1), ipCount)

	// the challenge is consumed by a failed validation
	again := fidoServeAgain(router, req, "/fido/signin/passkey", other.assertionBody(t, 1, fidoUserHandle()))
	assert.Equal(t, http.StatusBadRequest, again.Code)
}

func TestPasskeyLogin_Success_SignsIn(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, fidoTestEmail, "198.51.100.1", 2)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", WithSignInThrottle(throttle), fidoTestService(t).PasskeyLogin)

	authenticator := newFidoTestAuthenticator(t)
	fidoExpectGetUserByWebAuthnID(mock, fidoTestEmail, true, authenticator.credentialRows(t, fidoTestEmail, 4, false))
	fidoExpectUpdateCredentialAuthenticator(mock, fidoTestEmail, 5, false)

	body := authenticator.assertionBody(t, 5, fidoUserHandle())
	req := fidoRequestFromIP("/fido/signin/passkey", body)
	w := serveInSession(t, router, map[string]interface{}{sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t)}, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	emailCount, _ := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(0), emailCount)

	// the challenge cannot be used again
	again := fidoServeAgain(router, req, "/fido/signin/passkey", body)
	assert.Equal(t, http.StatusBadRequest, again.Code)

	values := fidoReadSession(t, router, req.Cookies(), sessionEmailKey, sessionIsAuthenticatedKey, sessionAuthenticatedAtKey, sessionWebAuthnSessionKey)
	assert.Equal(t, fidoTestEmail, values[sessionEmailKey])
	assert.Equal(t, true, values[sessionIsAuthenticatedKey])
	assert.Contains(t, values, sessionAuthenticatedAtKey)
	assert.NotContains(t, values, sessionWebAuthnSessionKey)
}

func TestPasskeyLogin_SuccessWithRedirect_ReturnsFound(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", fidoTestService(t).PasskeyLogin)

	authenticator := newFidoTestAuthenticator(t)
	fidoExpectGetUserByWebAuthnID(mock, fidoTestEmail, true, authenticator.credentialRows(t, fidoTestEmail, 0, false))
	fidoExpectUpdateCredentialAuthenticator(mock, fidoTestEmail, 1, false)

	req := fidoJSONRequest(http.MethodPost, "/fido/signin/passkey", authenticator.assertionBody(t, 1, fidoUserHandle()))
	w := serveInSession(t, router, map[string]interface{}{
		sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t),
		sessionRedirectURLKey:     "/authorize?client_id=cli",
	}, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/authorize?client_id=cli", w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPasskeyLogin_SyncedPasskeyWithZeroCounter_SignsIn(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", fidoTestService(t).PasskeyLogin)

	authenticator := newFidoTestAuthenticator(t)
	authenticator.backupEligible = true
	fidoExpectGetUserByWebAuthnID(mock, fidoTestEmail, true, authenticator.credentialRows(t, fidoTestEmail, 0, false))
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_credentials" SET "backup_state"=$1,"clone_warning"=$2,"sign_count"=$3 WHERE user_email = $4 AND id = $5`)).
		WithArgs(true, false, uint32(0), fidoTestEmail, fidoTestCredentialID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	req := fidoJSONRequest(http.MethodPost, "/fido/signin/passkey", authenticator.assertionBody(t, 0, fidoUserHandle()))
	w := serveInSession(t, router, map[string]interface{}{sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t)}, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPasskeyLogin_CloneWarning_ReturnsUnauthorized(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", WithSignInThrottle(throttle), fidoTestService(t).PasskeyLogin)

	authenticator := newFidoTestAuthenticator(t)
	fidoExpectGetUserByWebAuthnID(mock, fidoTestEmail, true, authenticator.credentialRows(t, fidoTestEmail, 9, false))
	// the counter is not advanced and the warning is kept
	fidoExpectUpdateCredentialAuthenticator(mock, fidoTestEmail, 9, true)

	req := fidoRequestFromIP("/fido/signin/passkey", authenticator.assertionBody(t, 5, fidoUserHandle()))
	w := serveInSession(t, router, map[string]interface{}{sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t)}, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	emailCount, ipCount := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(1), emailCount)
	assert.Equal(t, int64(1), ipCount)

	values := fidoReadSession(t, router, req.Cookies(), sessionIsAuthenticatedKey)
	assert.NotContains(t, values, sessionIsAuthenticatedKey)
}

func TestPasskeyLogin_WriteBackFailure_ReturnsInternalServerError(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, fidoTestEmail, "198.51.100.1", 2)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin/passkey", WithSignInThrottle(throttle), fidoTestService(t).PasskeyLogin)

	authenticator := newFidoTestAuthenticator(t)
	fidoExpectGetUserByWebAuthnID(mock, fidoTestEmail, true, authenticator.credentialRows(t, fidoTestEmail, 0, false))
	fidoExpectUpdateCredentialAuthenticatorError(mock)

	req := fidoRequestFromIP("/fido/signin/passkey", authenticator.assertionBody(t, 1, fidoUserHandle()))
	w := serveInSession(t, router, map[string]interface{}{sessionWebAuthnSessionKey: fidoPasskeySessionJSON(t)}, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	// no success is recorded
	emailCount, _ := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(2), emailCount)

	values := fidoReadSession(t, router, req.Cookies(), sessionIsAuthenticatedKey)
	assert.NotContains(t, values, sessionIsAuthenticatedKey)
}

// Login Tests with a valid assertion

func fidoLoginSession() map[string]interface{} {
	return map[string]interface{}{
		sessionEmailKey: fidoTestEmail,
	}
}

func TestLogin_Success_PersistsSignCount(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, fidoTestEmail, "198.51.100.1", 2)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", WithSignInThrottle(throttle), fidoTestService(t).Login)

	authenticator := newFidoTestAuthenticator(t)
	fidoExpectGetUserWithCredential(mock, fidoTestEmail, true, authenticator.credentialRows(t, fidoTestEmail, 4, false))
	fidoExpectUpdateCredentialAuthenticator(mock, fidoTestEmail, 5, false)

	sessionValues := fidoLoginSession()
	sessionValues[sessionWebAuthnSessionKey] = fidoLoginSessionJSON(t)
	body := authenticator.assertionBody(t, 5, fidoUserHandle())
	req := fidoRequestFromIP("/fido/signin", body)
	w := serveInSession(t, router, sessionValues, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	emailCount, _ := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(0), emailCount)

	// the challenge cannot be used again; the user is looked up before the
	// session is read
	fidoExpectGetUserWithCredential(mock, fidoTestEmail, true, authenticator.credentialRows(t, fidoTestEmail, 5, false))
	again := fidoServeAgain(router, req, "/fido/signin", body)
	assert.Equal(t, http.StatusBadRequest, again.Code)

	values := fidoReadSession(t, router, req.Cookies(), sessionEmailKey, sessionIsAuthenticatedKey, sessionAuthenticatedAtKey)
	assert.Equal(t, fidoTestEmail, values[sessionEmailKey])
	assert.Equal(t, true, values[sessionIsAuthenticatedKey])
	assert.Contains(t, values, sessionAuthenticatedAtKey)
}

func TestLogin_ValidationFailure_ConsumesChallenge(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", fidoTestService(t).Login)

	stored := newFidoTestAuthenticator(t)
	other := newFidoTestAuthenticator(t)
	fidoExpectGetUserWithCredential(mock, fidoTestEmail, true, stored.credentialRows(t, fidoTestEmail, 0, false))

	sessionValues := fidoLoginSession()
	sessionValues[sessionWebAuthnSessionKey] = fidoLoginSessionJSON(t)
	body := other.assertionBody(t, 1, fidoUserHandle())
	req := fidoJSONRequest(http.MethodPost, "/fido/signin", body)
	w := serveInSession(t, router, sessionValues, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	fidoExpectGetUserWithCredential(mock, fidoTestEmail, true, stored.credentialRows(t, fidoTestEmail, 0, false))
	again := fidoServeAgain(router, req, "/fido/signin", body)
	assert.Equal(t, http.StatusBadRequest, again.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_CloneWarning_RecordsFailure(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, fidoTestEmail, "198.51.100.1", 1)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", WithSignInThrottle(throttle), fidoTestService(t).Login)

	authenticator := newFidoTestAuthenticator(t)
	fidoExpectGetUserWithCredential(mock, fidoTestEmail, true, authenticator.credentialRows(t, fidoTestEmail, 9, false))
	fidoExpectUpdateCredentialAuthenticator(mock, fidoTestEmail, 9, true)

	sessionValues := fidoLoginSession()
	sessionValues[sessionWebAuthnSessionKey] = fidoLoginSessionJSON(t)
	req := fidoRequestFromIP("/fido/signin", authenticator.assertionBody(t, 9, fidoUserHandle()))
	w := serveInSession(t, router, sessionValues, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	// a failure is recorded rather than a success, which would reset it
	emailCount, _ := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(2), emailCount)

	values := fidoReadSession(t, router, req.Cookies(), sessionIsAuthenticatedKey)
	assert.NotContains(t, values, sessionIsAuthenticatedKey)
}

func TestLogin_StoredCloneWarning_ReturnsUnauthorized(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", fidoTestService(t).Login)

	authenticator := newFidoTestAuthenticator(t)
	fidoExpectGetUserWithCredential(mock, fidoTestEmail, true, authenticator.credentialRows(t, fidoTestEmail, 3, true))
	// a higher counter advances the stored one but the warning is kept
	fidoExpectUpdateCredentialAuthenticator(mock, fidoTestEmail, 4, true)

	sessionValues := fidoLoginSession()
	sessionValues[sessionWebAuthnSessionKey] = fidoLoginSessionJSON(t)
	req := fidoJSONRequest(http.MethodPost, "/fido/signin", authenticator.assertionBody(t, 4, fidoUserHandle()))
	w := serveInSession(t, router, sessionValues, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin_WriteBackFailure_ReturnsInternalServerError(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	throttleRecordFailures(t, throttle, fidoTestEmail, "198.51.100.1", 2)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", WithSignInThrottle(throttle), fidoTestService(t).Login)

	authenticator := newFidoTestAuthenticator(t)
	fidoExpectGetUserWithCredential(mock, fidoTestEmail, true, authenticator.credentialRows(t, fidoTestEmail, 0, false))
	fidoExpectUpdateCredentialAuthenticatorError(mock)

	sessionValues := fidoLoginSession()
	sessionValues[sessionWebAuthnSessionKey] = fidoLoginSessionJSON(t)
	req := fidoRequestFromIP("/fido/signin", authenticator.assertionBody(t, 1, fidoUserHandle()))
	w := serveInSession(t, router, sessionValues, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	emailCount, _ := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(2), emailCount)

	values := fidoReadSession(t, router, req.Cookies(), sessionIsAuthenticatedKey)
	assert.NotContains(t, values, sessionIsAuthenticatedKey)
}

func TestLogin_UserDisabled_ReturnsUnauthorized(t *testing.T) {
	throttle, _ := throttleTestThrottle(t, 3, 5)
	router, _, mock := getTestRouter()
	router.POST("/fido/signin", WithSignInThrottle(throttle), fidoTestService(t).Login)

	authenticator := newFidoTestAuthenticator(t)
	fidoExpectGetUserWithCredential(mock, fidoTestEmail, false, authenticator.credentialRows(t, fidoTestEmail, 0, false))

	sessionValues := fidoLoginSession()
	sessionValues[sessionWebAuthnSessionKey] = fidoLoginSessionJSON(t)
	req := fidoRequestFromIP("/fido/signin", authenticator.assertionBody(t, 1, fidoUserHandle()))
	w := serveInSession(t, router, sessionValues, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
	emailCount, ipCount := fidoFailureCounts(t, throttle, fidoTestEmail)
	assert.Equal(t, int64(1), emailCount)
	assert.Equal(t, int64(1), ipCount)

	// the assertion is never validated, thus the challenge is kept
	values := fidoReadSession(t, router, req.Cookies(), sessionIsAuthenticatedKey, sessionWebAuthnSessionKey)
	assert.NotContains(t, values, sessionIsAuthenticatedKey)
	assert.Contains(t, values, sessionWebAuthnSessionKey)
}
