package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alexhokl/helper/database"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func getTestRouter() (*gin.Engine, *gorm.DB, sqlmock.Sqlmock) {
	mockDB, mock, _ := sqlmock.New()
	dialector := database.GetDatabaseDialectorFromConnection(mockDB)
	dbConn, _ := gorm.Open(dialector, &gorm.Config{})

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("db", dbConn)
		c.Set("expiration_period", int64(3600))
		c.Set("domain", "test.com")
		c.Next()
	})

	return router, dbConn, mock
}

// SignUp Tests

func TestSignUp_MissingRequestBody_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/signup", SignUp)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signup", nil)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignUp_InvalidJSON_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/signup", SignUp)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signup", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignUp_MissingEmail_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/signup", SignUp)

	body := `{"password": "password123", "display_name": "Test User"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignUp_InvalidEmailFormat_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/signup", SignUp)

	body := `{"email": "notanemail", "password": "password123", "display_name": "Test User"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// SignIn Tests

func TestSignIn_MissingRequestBody_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/signin", SignIn)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signin", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignIn_MissingEmail_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/signin", SignIn)

	form := url.Values{}
	form.Add("password", "password123")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signin", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// SignInPasswordChallenge Tests

func TestSignInPasswordChallenge_MissingPassword_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/signin/challenge", SignInPasswordChallenge)

	form := url.Values{}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signin/challenge", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignInPasswordChallenge_NoEmailInSession_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/signin/challenge", SignInPasswordChallenge)

	form := url.Values{}
	form.Add("password", "password123")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signin/challenge", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// SignOut Tests

func TestSignOut_NotAuthenticated_ReturnsNoContent(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/signout", SignOut)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signout", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

// HasEmailInSession Tests

func TestHasEmailInSession_NoEmail_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.GET("/test", HasEmailInSession, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ListUsers Tests

func TestListUsers_EmptyList_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/users", ListUsers)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users"`)).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}))
	// No preload queries when the user list is empty

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/users", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListUsers_WithUsers_ReturnsUserList(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/users", ListUsers)

	userID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users"`)).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}).
			AddRow("alex@test.com", []byte("hash"), "Alex", userID, true).
			AddRow("bob@test.com", []byte("hash2"), "Bob", uuid.New(), false))
	// GORM preloads credentials first
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE "user_credentials"."user_email" IN ($1,$2)`)).
		WithArgs("alex@test.com", "bob@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "friendly_name"}))
	// Then preloads user_roles join table
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_email" IN ($1,$2)`)).
		WithArgs("alex@test.com", "bob@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "role_name"}).
			AddRow("alex@test.com", "admin"))
	// Then loads the roles
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "roles" WHERE "roles"."name" = $1`)).
		WithArgs("admin").
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("admin"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/users", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var users []UserResponse
	err := json.Unmarshal(w.Body.Bytes(), &users)
	assert.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, "alex@test.com", users[0].Email)
	assert.Equal(t, "bob@test.com", users[1].Email)
}

func TestListUsers_NoDatabaseConnection_ReturnsInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Don't set db in context
	router.GET("/users", ListUsers)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/users", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ChangePassword Tests

func TestChangePassword_MissingRequestBody_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/changepassword", ChangePassword)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/changepassword", nil)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangePassword_NoEmailInSession_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/changepassword", ChangePassword)

	body := `{"old_password": "oldpass", "new_password": "newpass"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/changepassword", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ResetPassword Tests

func TestResetPassword_MissingEmail_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/resetpassword", ResetPassword)

	body := `{}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/resetpassword", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResetPassword_UserNotFound_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/resetpassword", ResetPassword)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("notfound@test.com", 1).
		WillReturnError(gorm.ErrRecordNotFound)

	body := `{"email": "notfound@test.com"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/resetpassword", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Returns OK to prevent email enumeration
	assert.Equal(t, http.StatusOK, w.Code)
}

// Confirm Tests

func TestConfirm_NotFound_ReturnsNotFound(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/confirm/:otp", Confirm)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1 ORDER BY "user_confirmations"."user_email" LIMIT $2`)).
		WithArgs("invalid-otp", 1).
		WillReturnError(gorm.ErrRecordNotFound)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/confirm/invalid-otp", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestConfirm_Expired_ReturnsGone(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/confirm/:otp", Confirm)

	// Return an expired confirmation
	expiredTime := time.Now().Add(-1 * time.Hour).Unix()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1 ORDER BY "user_confirmations"."user_email" LIMIT $2`)).
		WithArgs("expired-otp", 1).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "one_time_password", "expiry_time", "confirmed_time"}).
			AddRow("alex@test.com", "expired-otp", expiredTime, 0))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/confirm/expired-otp", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusGone, w.Code)
}

func TestConfirm_Valid_ReturnsNoContent(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/confirm/:otp", Confirm)

	// Return a valid confirmation
	futureTime := time.Now().Add(1 * time.Hour).Unix()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1 ORDER BY "user_confirmations"."user_email" LIMIT $2`)).
		WithArgs("valid-otp", 1).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "one_time_password", "expiry_time", "confirmed_time"}).
			AddRow("alex@test.com", "valid-otp", futureTime, 0))

	// Expect transaction for confirmation
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_confirmations" SET "confirmed_time"=$1 WHERE one_time_password = $2`)).
		WithArgs(sqlmock.AnyArg(), "valid-otp").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "is_enabled"=$1 WHERE email = $2`)).
		WithArgs(true, "alex@test.com").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/confirm/valid-otp", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ConfirmResetPassword Tests

func TestConfirmResetPassword_NotFound_ReturnsNotFound(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/resetpassword/:otp", ConfirmResetPassword)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1 ORDER BY "user_confirmations"."user_email" LIMIT $2`)).
		WithArgs("invalid-otp", 1).
		WillReturnError(gorm.ErrRecordNotFound)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/resetpassword/invalid-otp", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestConfirmResetPassword_Expired_ReturnsGone(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/resetpassword/:otp", ConfirmResetPassword)

	expiredTime := time.Now().Add(-1 * time.Hour).Unix()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1 ORDER BY "user_confirmations"."user_email" LIMIT $2`)).
		WithArgs("expired-otp", 1).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "one_time_password", "expiry_time", "confirmed_time"}).
			AddRow("alex@test.com", "expired-otp", expiredTime, 0))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/resetpassword/expired-otp", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusGone, w.Code)
}

// NewPassword Tests

func TestNewPassword_MissingRequestBody_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/newpassword", NewPassword)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/newpassword", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestNewPassword_InvalidOTP_ReturnsNotFound(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/newpassword", NewPassword)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1 ORDER BY "user_confirmations"."user_email" LIMIT $2`)).
		WithArgs("invalid-otp", 1).
		WillReturnError(gorm.ErrRecordNotFound)

	form := url.Values{}
	form.Add("otp", "invalid-otp")
	form.Add("new_password", "newpassword123")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/newpassword", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestNewPassword_ExpiredOTP_ReturnsGone(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/newpassword", NewPassword)

	expiredTime := time.Now().Add(-1 * time.Hour).Unix()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1 ORDER BY "user_confirmations"."user_email" LIMIT $2`)).
		WithArgs("expired-otp", 1).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "one_time_password", "expiry_time", "confirmed_time"}).
			AddRow("alex@test.com", "expired-otp", expiredTime, 0))

	form := url.Values{}
	form.Add("otp", "expired-otp")
	form.Add("new_password", "newpassword123")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/newpassword", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusGone, w.Code)
}

// generateConfirmationInfo Tests

func TestGenerateConfirmationInfo_ReturnsValidInfo(t *testing.T) {
	email := "test@example.com"
	expiryPeriod := int64(3600)

	info, err := generateConfirmationInfo(email, expiryPeriod)

	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, email, info.UserEmail)
	assert.NotEmpty(t, info.OneTimePassword)
	assert.Greater(t, info.ExpiryTime, time.Now().Unix())
	assert.Equal(t, int64(0), info.ConfirmedTime)
}

func TestGenerateConfirmationInfo_ExpiryTimeIsCorrect(t *testing.T) {
	email := "test@example.com"
	expiryPeriod := int64(7200) // 2 hours

	beforeTime := time.Now().Unix()
	info, err := generateConfirmationInfo(email, expiryPeriod)
	afterTime := time.Now().Unix()

	assert.NoError(t, err)
	// Expiry time should be between beforeTime + expiryPeriod and afterTime + expiryPeriod
	assert.GreaterOrEqual(t, info.ExpiryTime, beforeTime+expiryPeriod)
	assert.LessOrEqual(t, info.ExpiryTime, afterTime+expiryPeriod)
}

// generateOneTimePassword Tests

func TestGenerateOneTimePassword_ReturnsNonEmptyString(t *testing.T) {
	otp, err := generateOneTimePassword(64)

	assert.NoError(t, err)
	assert.NotEmpty(t, otp)
}

func TestGenerateOneTimePassword_DifferentCalls_ReturnDifferentValues(t *testing.T) {
	otp1, _ := generateOneTimePassword(64)
	otp2, _ := generateOneTimePassword(64)

	assert.NotEqual(t, otp1, otp2)
}

func TestGenerateOneTimePassword_LengthAffectsOutput(t *testing.T) {
	otp32, _ := generateOneTimePassword(32)
	otp128, _ := generateOneTimePassword(128)

	// Base64 encoding: each 3 bytes become 4 characters
	// 32 bytes -> ~43 characters, 128 bytes -> ~171 characters
	assert.Less(t, len(otp32), len(otp128))
}

// UserResponse JSON serialization

func TestUserResponse_JSONSerialization(t *testing.T) {
	user := UserResponse{
		Email:       "test@example.com",
		DisplayName: "Test User",
		Roles:       []string{"admin", "user"},
		Credentials: []CredentialInfo{
			{ID: []byte("cred1"), Name: "Key 1"},
		},
		IsEnabled: true,
	}

	data, err := json.Marshal(user)
	assert.NoError(t, err)

	var decoded UserResponse
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, user.Email, decoded.Email)
	assert.Equal(t, user.DisplayName, decoded.DisplayName)
	assert.Equal(t, user.Roles, decoded.Roles)
	assert.Equal(t, user.IsEnabled, decoded.IsEnabled)
}

// Helper function to create password hash for testing
func createTestPasswordHash(password string) []byte {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return hash
}

// Test helper: create valid form data
func createFormData(values map[string]string) *bytes.Buffer {
	form := url.Values{}
	for k, v := range values {
		form.Add(k, v)
	}
	return bytes.NewBufferString(form.Encode())
}

// Test helpers for the user handlers

const userTestEmail = "alex@test.com"
const userTestPassword = "P@ssw0rd"

// userTestPasswordHash uses the minimum cost so that the comparison of
// passwords is fast. Slow comparisons widen the window for a data race in the
// in-memory session store of go-session between its garbage collection and
// session updates, which is reported by the race detector.
var userTestPasswordHash, _ = bcrypt.GenerateFromPassword([]byte(userTestPassword), bcrypt.MinCost)

var userErrDatabase = errors.New("database failure")

// userGetTestRouter returns a test router with mail settings in the context.
func userGetTestRouter() (*gin.Engine, sqlmock.Sqlmock) {
	router, _, mock := getTestRouter()
	router.Use(mailSettings())
	return router, mock
}

// userGetTestRouterWithoutDB returns a test router without a database
// connection in the context.
func userGetTestRouterWithoutDB() *gin.Engine {
	router := gin.New()
	router.Use(mailSettings())
	return router
}

func userFormRequest(method string, target string, values map[string]string) *http.Request {
	req, _ := http.NewRequest(method, target, createFormData(values))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func userExpectGetUser(mock sqlmock.Sqlmock, email string, passwordHash []byte, isEnabled bool) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs(email, 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}).
			AddRow(email, passwordHash, "Alex", uuid.New(), isEnabled))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE "user_credentials"."user_email" = $1`)).
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email"}))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_email" = $1`)).
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "role_name"}))
}

func userExpectGetUserError(mock sqlmock.Sqlmock, email string, err error) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs(email, 1).
		WillReturnError(err)
}

func userExpectCreateUser(mock sqlmock.Sqlmock, email string, err error) {
	mock.ExpectBegin()
	query := mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "users"`)).
		WithArgs(email, sqlmock.AnyArg(), "", false)
	if err != nil {
		query.WillReturnError(err)
		mock.ExpectRollback()
		return
	}
	query.WillReturnRows(sqlmock.NewRows([]string{"web_authn_user_id"}).AddRow(uuid.New()))
	mock.ExpectCommit()
}

func userExpectCreateConfirmation(mock sqlmock.Sqlmock, email string, err error) {
	mock.ExpectBegin()
	exec := mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "user_confirmations" ("user_email","one_time_password","expiry_time","confirmed_time") VALUES ($1,$2,$3,$4)`)).
		WithArgs(email, sqlmock.AnyArg(), sqlmock.AnyArg(), 0)
	if err != nil {
		exec.WillReturnError(err)
		mock.ExpectRollback()
		return
	}
	exec.WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

func userExpectChangePassword(mock sqlmock.Sqlmock, email string, err error) {
	mock.ExpectBegin()
	exec := mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "password_hash"=$1 WHERE email = $2`)).
		WithArgs(sqlmock.AnyArg(), email)
	if err != nil {
		exec.WillReturnError(err)
		mock.ExpectRollback()
		return
	}
	exec.WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

func userExpectGetConfirmation(mock sqlmock.Sqlmock, otp string, expiryTime int64) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1 ORDER BY "user_confirmations"."user_email" LIMIT $2`)).
		WithArgs(otp, 1).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "one_time_password", "expiry_time", "confirmed_time"}).
			AddRow(userTestEmail, otp, expiryTime, 0))
}

func userExpectGetConfirmationError(mock sqlmock.Sqlmock, otp string, err error) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1 ORDER BY "user_confirmations"."user_email" LIMIT $2`)).
		WithArgs(otp, 1).
		WillReturnError(err)
}

func userSignUpRequest() *http.Request {
	body := `{"email": "alex@test.com", "password": "P@ssw0rd"}`
	req, _ := http.NewRequest(http.MethodPost, "/signup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func userResetPasswordRequest() *http.Request {
	body := `{"email": "alex@test.com"}`
	req, _ := http.NewRequest(http.MethodPost, "/resetpassword", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func userServe(router *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// SignUp Tests

func TestSignUp_NoDatabaseConnection_ReturnsInternalServerError(t *testing.T) {
	router := userGetTestRouterWithoutDB()
	router.POST("/signup", SignUp)

	w := userServe(router, userSignUpRequest())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSignUp_CreateUserError_ReturnsInternalServerError(t *testing.T) {
	mailServer := useTestMailServer(t, http.StatusOK)
	router, mock := userGetTestRouter()
	router.POST("/signup", SignUp)
	userExpectCreateUser(mock, userTestEmail, userErrDatabase)

	w := userServe(router, userSignUpRequest())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, mailServer.Requests())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignUp_CreateConfirmationError_ReturnsInternalServerError(t *testing.T) {
	mailServer := useTestMailServer(t, http.StatusOK)
	router, mock := userGetTestRouter()
	router.POST("/signup", SignUp)
	userExpectCreateUser(mock, userTestEmail, nil)
	userExpectCreateConfirmation(mock, userTestEmail, userErrDatabase)

	w := userServe(router, userSignUpRequest())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, mailServer.Requests())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignUp_MailError_ReturnsInternalServerError(t *testing.T) {
	useTestMailServer(t, http.StatusInternalServerError)
	router, mock := userGetTestRouter()
	router.POST("/signup", SignUp)
	userExpectCreateUser(mock, userTestEmail, nil)
	userExpectCreateConfirmation(mock, userTestEmail, nil)

	w := userServe(router, userSignUpRequest())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignUp_Success_ReturnsFound(t *testing.T) {
	mailServer := useTestMailServer(t, http.StatusOK)
	router, mock := userGetTestRouter()
	router.POST("/signup", SignUp)
	userExpectCreateUser(mock, userTestEmail, nil)
	userExpectCreateConfirmation(mock, userTestEmail, nil)

	w := userServe(router, userSignUpRequest())

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/signup_continue", w.Header().Get("Location"))
	requests := mailServer.Requests()
	if assert.Len(t, requests, 1) {
		assert.Equal(t, []string{userTestEmail}, requests[0].To)
		assert.Equal(t, mailTestConfirmationSubject, requests[0].Subject)
		assert.Contains(t, requests[0].Html, "https://test.com/confirm/")
	}
	assert.NoError(t, mock.ExpectationsWereMet())
}

// SignIn Tests

func TestSignIn_Success_ReturnsFound(t *testing.T) {
	router, _ := userGetTestRouter()
	router.POST("/signin", SignIn)
	router.GET("/email", func(c *gin.Context) {
		c.String(http.StatusOK, getEmailFromSession(c))
	})

	w := userServe(router, userFormRequest(http.MethodPost, "/signin?redirect_uri=%2Fauthenticated", map[string]string{
		"email": userTestEmail,
	}))

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/signin/challenge?redirect_uri=%2Fauthenticated", w.Header().Get("Location"))

	cookies := w.Result().Cookies()
	assert.NotEmpty(t, cookies)
	req, _ := http.NewRequest(http.MethodGet, "/email", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	follow := userServe(router, req)
	assert.Equal(t, userTestEmail, follow.Body.String())
}

func TestSignIn_InvalidSessionCookie_ReturnsInternalServerError(t *testing.T) {
	router, _ := userGetTestRouter()
	router.POST("/signin", SignIn)

	req := userFormRequest(http.MethodPost, "/signin", map[string]string{
		"email": userTestEmail,
	})
	req.AddCookie(&http.Cookie{Name: "go_session_id", Value: "invalid"})
	w := userServe(router, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// SignInPasswordChallenge Tests

func userSignInChallengeRequest(target string, password string) *http.Request {
	return userFormRequest(http.MethodPost, target, map[string]string{
		"password": password,
	})
}

func TestSignInPasswordChallenge_NoDatabaseConnection_ReturnsInternalServerError(t *testing.T) {
	router := userGetTestRouterWithoutDB()
	router.POST("/signin/challenge", SignInPasswordChallenge)

	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: userTestEmail},
		userSignInChallengeRequest("/signin/challenge", userTestPassword))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSignInPasswordChallenge_UserQueryError_ReturnsUnauthorized(t *testing.T) {
	router, mock := userGetTestRouter()
	router.POST("/signin/challenge", SignInPasswordChallenge)
	userExpectGetUserError(mock, userTestEmail, userErrDatabase)

	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: userTestEmail},
		userSignInChallengeRequest("/signin/challenge", userTestPassword))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignInPasswordChallenge_UserNotFound_ReturnsUnauthorized(t *testing.T) {
	router, mock := userGetTestRouter()
	router.POST("/signin/challenge", SignInPasswordChallenge)
	userExpectGetUserError(mock, userTestEmail, gorm.ErrRecordNotFound)

	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: userTestEmail},
		userSignInChallengeRequest("/signin/challenge", userTestPassword))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignInPasswordChallenge_UserDisabled_ReturnsUnauthorized(t *testing.T) {
	router, mock := userGetTestRouter()
	router.POST("/signin/challenge", SignInPasswordChallenge)
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, false)

	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: userTestEmail},
		userSignInChallengeRequest("/signin/challenge", userTestPassword))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignInPasswordChallenge_WrongPassword_ReturnsUnauthorized(t *testing.T) {
	router, mock := userGetTestRouter()
	router.POST("/signin/challenge", SignInPasswordChallenge)
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, true)

	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: userTestEmail},
		userSignInChallengeRequest("/signin/challenge", "wrong password"))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignInPasswordChallenge_Success_ReturnsCreated(t *testing.T) {
	router, mock := userGetTestRouter()
	router.POST("/signin/challenge", SignInPasswordChallenge)
	router.GET("/authenticated", func(c *gin.Context) {
		c.String(http.StatusOK, getAuthenticatedEmailFromGinContext(c))
	})
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, true)

	req := userSignInChallengeRequest("/signin/challenge", userTestPassword)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: userTestEmail}, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())

	followReq, _ := http.NewRequest(http.MethodGet, "/authenticated", nil)
	for _, cookie := range req.Cookies() {
		followReq.AddCookie(cookie)
	}
	follow := userServe(router, followReq)
	assert.Equal(t, userTestEmail, follow.Body.String())
}

func TestSignInPasswordChallenge_SuccessWithRedirectURI_ReturnsFound(t *testing.T) {
	router, mock := userGetTestRouter()
	router.POST("/signin/challenge", SignInPasswordChallenge)
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, true)

	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: userTestEmail},
		userSignInChallengeRequest("/signin/challenge?redirect_uri=%2Fauthenticated", userTestPassword))

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/authenticated", w.Header().Get("Location"))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// SignOut Tests

func TestSignOut_Authenticated_ReturnsNoContent(t *testing.T) {
	router, _ := userGetTestRouter()
	router.POST("/signout", SignOut)
	router.GET("/state", func(c *gin.Context) {
		c.String(http.StatusOK, "%s|%t", getEmailFromSession(c), isAuthenticated(c))
	})

	req, _ := http.NewRequest(http.MethodPost, "/signout", nil)
	w := serveInSession(t, router, authenticatedSession(userTestEmail), req)

	assert.Equal(t, http.StatusNoContent, w.Code)

	followReq, _ := http.NewRequest(http.MethodGet, "/state", nil)
	for _, cookie := range req.Cookies() {
		followReq.AddCookie(cookie)
	}
	follow := userServe(router, followReq)
	assert.Equal(t, "|false", follow.Body.String())
}

// ChangePassword Tests

func userChangePasswordRequest(oldPassword string) *http.Request {
	return userFormRequest(http.MethodPost, "/changepassword", map[string]string{
		"current_password": oldPassword,
		"new_password":     "NewP@ssw0rd",
	})
}

func TestChangePassword_ValidRequestNoEmailInSession_ReturnsBadRequest(t *testing.T) {
	router, _ := userGetTestRouter()
	router.POST("/changepassword", ChangePassword)

	w := userServe(router, userChangePasswordRequest(userTestPassword))

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangePassword_NoDatabaseConnection_ReturnsInternalServerError(t *testing.T) {
	router := userGetTestRouterWithoutDB()
	router.POST("/changepassword", ChangePassword)

	w := serveInSession(t, router, authenticatedSession(userTestEmail), userChangePasswordRequest(userTestPassword))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestChangePassword_UserQueryError_ReturnsInternalServerError(t *testing.T) {
	router, mock := userGetTestRouter()
	router.POST("/changepassword", ChangePassword)
	userExpectGetUserError(mock, userTestEmail, userErrDatabase)

	w := serveInSession(t, router, authenticatedSession(userTestEmail), userChangePasswordRequest(userTestPassword))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestChangePassword_UserNotFound_ReturnsNotFound(t *testing.T) {
	router, mock := userGetTestRouter()
	router.POST("/changepassword", ChangePassword)
	userExpectGetUserError(mock, userTestEmail, gorm.ErrRecordNotFound)

	w := serveInSession(t, router, authenticatedSession(userTestEmail), userChangePasswordRequest(userTestPassword))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestChangePassword_WrongOldPassword_ReturnsBadRequest(t *testing.T) {
	mailServer := useTestMailServer(t, http.StatusOK)
	router, mock := userGetTestRouter()
	router.POST("/changepassword", ChangePassword)
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, true)

	w := serveInSession(t, router, authenticatedSession(userTestEmail), userChangePasswordRequest("wrong password"))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, mailServer.Requests())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestChangePassword_UpdateError_ReturnsInternalServerError(t *testing.T) {
	mailServer := useTestMailServer(t, http.StatusOK)
	router, mock := userGetTestRouter()
	router.POST("/changepassword", ChangePassword)
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, true)
	userExpectChangePassword(mock, userTestEmail, userErrDatabase)

	w := serveInSession(t, router, authenticatedSession(userTestEmail), userChangePasswordRequest(userTestPassword))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, mailServer.Requests())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestChangePassword_MailError_ReturnsInternalServerError(t *testing.T) {
	useTestMailServer(t, http.StatusInternalServerError)
	router, mock := userGetTestRouter()
	router.POST("/changepassword", ChangePassword)
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, true)
	userExpectChangePassword(mock, userTestEmail, nil)

	w := serveInSession(t, router, authenticatedSession(userTestEmail), userChangePasswordRequest(userTestPassword))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestChangePassword_Success_ReturnsFound(t *testing.T) {
	mailServer := useTestMailServer(t, http.StatusOK)
	router, mock := userGetTestRouter()
	router.POST("/changepassword", ChangePassword)
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, true)
	userExpectChangePassword(mock, userTestEmail, nil)

	w := serveInSession(t, router, authenticatedSession(userTestEmail), userChangePasswordRequest(userTestPassword))

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/changepassword_completed", w.Header().Get("Location"))
	requests := mailServer.Requests()
	if assert.Len(t, requests, 1) {
		assert.Equal(t, []string{userTestEmail}, requests[0].To)
		assert.Equal(t, mailTestPasswordChangedSubject, requests[0].Subject)
	}
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ResetPassword Tests

func TestResetPassword_NoDatabaseConnection_ReturnsInternalServerError(t *testing.T) {
	router := userGetTestRouterWithoutDB()
	router.POST("/resetpassword", ResetPassword)

	w := userServe(router, userResetPasswordRequest())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestResetPassword_UnknownUser_ReturnsOK(t *testing.T) {
	mailServer := useTestMailServer(t, http.StatusOK)
	router, mock := userGetTestRouter()
	router.POST("/resetpassword", ResetPassword)
	userExpectGetUserError(mock, userTestEmail, gorm.ErrRecordNotFound)

	w := userServe(router, userResetPasswordRequest())

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, mailServer.Requests())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestResetPassword_UserQueryError_ReturnsInternalServerError(t *testing.T) {
	router, mock := userGetTestRouter()
	router.POST("/resetpassword", ResetPassword)
	userExpectGetUserError(mock, userTestEmail, userErrDatabase)

	w := userServe(router, userResetPasswordRequest())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestResetPassword_CreateConfirmationError_ReturnsInternalServerError(t *testing.T) {
	mailServer := useTestMailServer(t, http.StatusOK)
	router, mock := userGetTestRouter()
	router.POST("/resetpassword", ResetPassword)
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, true)
	userExpectCreateConfirmation(mock, userTestEmail, userErrDatabase)

	w := userServe(router, userResetPasswordRequest())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, mailServer.Requests())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestResetPassword_MailError_ReturnsInternalServerError(t *testing.T) {
	useTestMailServer(t, http.StatusInternalServerError)
	router, mock := userGetTestRouter()
	router.POST("/resetpassword", ResetPassword)
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, true)
	userExpectCreateConfirmation(mock, userTestEmail, nil)

	w := userServe(router, userResetPasswordRequest())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestResetPassword_Success_ReturnsNoContent(t *testing.T) {
	mailServer := useTestMailServer(t, http.StatusOK)
	router, mock := userGetTestRouter()
	router.POST("/resetpassword", ResetPassword)
	userExpectGetUser(mock, userTestEmail, userTestPasswordHash, true)
	userExpectCreateConfirmation(mock, userTestEmail, nil)

	w := userServe(router, userResetPasswordRequest())

	assert.Equal(t, http.StatusNoContent, w.Code)
	requests := mailServer.Requests()
	if assert.Len(t, requests, 1) {
		assert.Equal(t, []string{userTestEmail}, requests[0].To)
		assert.Equal(t, mailTestResetPasswordSubject, requests[0].Subject)
		assert.Contains(t, requests[0].Html, "https://test.com/confirmresetpassword/")
	}
	assert.NoError(t, mock.ExpectationsWereMet())
}

// Confirm Tests

func TestConfirm_NoDatabaseConnection_ReturnsInternalServerError(t *testing.T) {
	router := userGetTestRouterWithoutDB()
	router.GET("/confirm/:otp", Confirm)

	req, _ := http.NewRequest(http.MethodGet, "/confirm/some-otp", nil)
	w := userServe(router, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestConfirm_QueryError_ReturnsInternalServerError(t *testing.T) {
	router, mock := userGetTestRouter()
	router.GET("/confirm/:otp", Confirm)
	userExpectGetConfirmationError(mock, "some-otp", userErrDatabase)

	req, _ := http.NewRequest(http.MethodGet, "/confirm/some-otp", nil)
	w := userServe(router, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConfirm_ConfirmUserError_ReturnsInternalServerError(t *testing.T) {
	router, mock := userGetTestRouter()
	router.GET("/confirm/:otp", Confirm)
	userExpectGetConfirmation(mock, "some-otp", time.Now().Add(time.Hour).Unix())
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_confirmations" SET "confirmed_time"=$1 WHERE one_time_password = $2`)).
		WithArgs(sqlmock.AnyArg(), "some-otp").
		WillReturnError(userErrDatabase)
	mock.ExpectRollback()

	req, _ := http.NewRequest(http.MethodGet, "/confirm/some-otp", nil)
	w := userServe(router, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ConfirmResetPassword Tests

func TestConfirmResetPassword_NoDatabaseConnection_ReturnsInternalServerError(t *testing.T) {
	router := userGetTestRouterWithoutDB()
	router.GET("/confirmresetpassword/:otp", ConfirmResetPassword)

	req, _ := http.NewRequest(http.MethodGet, "/confirmresetpassword/some-otp", nil)
	w := userServe(router, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestConfirmResetPassword_QueryError_ReturnsInternalServerError(t *testing.T) {
	router, mock := userGetTestRouter()
	router.GET("/confirmresetpassword/:otp", ConfirmResetPassword)
	userExpectGetConfirmationError(mock, "some-otp", userErrDatabase)

	req, _ := http.NewRequest(http.MethodGet, "/confirmresetpassword/some-otp", nil)
	w := userServe(router, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConfirmResetPassword_Valid_ReturnsOK(t *testing.T) {
	router, mock := userGetTestRouter()
	router.SetHTMLTemplate(template.Must(template.New("new_password.tmpl").Parse(`otp={{.otp}}`)))
	router.GET("/confirmresetpassword/:otp", ConfirmResetPassword)
	userExpectGetConfirmation(mock, "some-otp", time.Now().Add(time.Hour).Unix())

	req, _ := http.NewRequest(http.MethodGet, "/confirmresetpassword/some-otp", nil)
	w := userServe(router, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "otp=some-otp", w.Body.String())
	assert.NoError(t, mock.ExpectationsWereMet())
}

// NewPassword Tests

func userNewPasswordRequest() *http.Request {
	return userFormRequest(http.MethodPost, "/newpassword", map[string]string{
		"otp":          "some-otp",
		"new_password": "NewP@ssw0rd",
	})
}

func TestNewPassword_NoDatabaseConnection_ReturnsInternalServerError(t *testing.T) {
	router := userGetTestRouterWithoutDB()
	router.POST("/newpassword", NewPassword)

	w := userServe(router, userNewPasswordRequest())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestNewPassword_QueryError_ReturnsInternalServerError(t *testing.T) {
	router, mock := userGetTestRouter()
	router.POST("/newpassword", NewPassword)
	userExpectGetConfirmationError(mock, "some-otp", userErrDatabase)

	w := userServe(router, userNewPasswordRequest())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestNewPassword_ChangePasswordError_ReturnsInternalServerError(t *testing.T) {
	mailServer := useTestMailServer(t, http.StatusOK)
	router, mock := userGetTestRouter()
	router.POST("/newpassword", NewPassword)
	userExpectGetConfirmation(mock, "some-otp", time.Now().Add(time.Hour).Unix())
	userExpectChangePassword(mock, userTestEmail, userErrDatabase)

	w := userServe(router, userNewPasswordRequest())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, mailServer.Requests())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestNewPassword_MailError_ReturnsInternalServerError(t *testing.T) {
	useTestMailServer(t, http.StatusInternalServerError)
	router, mock := userGetTestRouter()
	router.POST("/newpassword", NewPassword)
	userExpectGetConfirmation(mock, "some-otp", time.Now().Add(time.Hour).Unix())
	userExpectChangePassword(mock, userTestEmail, nil)

	w := userServe(router, userNewPasswordRequest())

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestNewPassword_Success_ReturnsNoContent(t *testing.T) {
	mailServer := useTestMailServer(t, http.StatusOK)
	router, mock := userGetTestRouter()
	router.POST("/newpassword", NewPassword)
	userExpectGetConfirmation(mock, "some-otp", time.Now().Add(time.Hour).Unix())
	userExpectChangePassword(mock, userTestEmail, nil)

	w := userServe(router, userNewPasswordRequest())

	assert.Equal(t, http.StatusNoContent, w.Code)
	requests := mailServer.Requests()
	if assert.Len(t, requests, 1) {
		assert.Equal(t, []string{userTestEmail}, requests[0].To)
		assert.Equal(t, mailTestPasswordChangedSubject, requests[0].Subject)
	}
	assert.NoError(t, mock.ExpectationsWereMet())
}

// SignInUI Tests

const userSignInTemplate = `{{.hasClients}}{{range .clients}}|{{.Name}},{{.ButtonName}},{{.StartEndpoint}}{{end}}`

func userSetSignInTemplate(router *gin.Engine) {
	router.SetHTMLTemplate(template.Must(template.New("signin.html").Parse(userSignInTemplate)))
}

func TestSignInUI_OIDCDisabled_ReturnsOK(t *testing.T) {
	router, mock := userGetTestRouter()
	userSetSignInTemplate(router)
	router.GET("/signin", WithOIDC(false), SignInUI)

	req, _ := http.NewRequest(http.MethodGet, "/signin", nil)
	w := userServe(router, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "false", w.Body.String())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignInUI_OIDCEnabledWithClients_ReturnsOK(t *testing.T) {
	router, mock := userGetTestRouter()
	userSetSignInTemplate(router)
	router.GET("/signin", WithOIDC(true), SignInUI)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients"`)).
		WillReturnRows(sqlmock.NewRows([]string{"name", "client_id", "client_secret", "redirect_uri", "button_name"}).
			AddRow("google", "client-id", "secret", "https://test.com/callback", "Sign in with Google"))

	req, _ := http.NewRequest(http.MethodGet, "/signin", nil)
	w := userServe(router, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "true|google,Sign in with Google,"+OIDC_START_ENDPOINT, w.Body.String())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignInUI_OIDCEnabledListError_ReturnsOK(t *testing.T) {
	router, mock := userGetTestRouter()
	userSetSignInTemplate(router)
	router.GET("/signin", WithOIDC(true), SignInUI)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients"`)).
		WillReturnError(userErrDatabase)

	req, _ := http.NewRequest(http.MethodGet, "/signin", nil)
	w := userServe(router, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "false", w.Body.String())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestSignInUI_OIDCEnabledNoDatabaseConnection_ReturnsInternalServerError(t *testing.T) {
	router := userGetTestRouterWithoutDB()
	userSetSignInTemplate(router)
	router.GET("/signin", WithOIDC(true), SignInUI)

	req, _ := http.NewRequest(http.MethodGet, "/signin", nil)
	w := userServe(router, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// Static UI Tests

func TestStaticUI_FilesExist_ReturnsOK(t *testing.T) {
	// the files are served relative to the working directory which is the
	// repository root when the server runs
	t.Chdir("..")

	tests := []struct {
		name    string
		handler gin.HandlerFunc
	}{
		{name: "SignInChallengeUI", handler: SignInChallengeUI},
		{name: "AuthenticatedUI", handler: AuthenticatedUI},
		{name: "ChangePasswordUI", handler: ChangePasswordUI},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/ui", tt.handler)

			req, _ := http.NewRequest(http.MethodGet, "/ui", nil)
			w := userServe(router, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), "<html")
		})
	}
}

// RedirectToChangePasswordUI Tests

func TestRedirectToChangePasswordUI_ReturnsFound(t *testing.T) {
	router := gin.New()
	router.GET("/redirect", RedirectToChangePasswordUI)

	req, _ := http.NewRequest(http.MethodGet, "http://auth.test.com/redirect", nil)
	w := userServe(router, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "http://auth.test.com/changepassword", w.Header().Get("Location"))
}

func TestListUsers_QueryError_ReturnsInternalServerError(t *testing.T) {
	router, mock := userGetTestRouter()
	router.GET("/users", ListUsers)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users"`)).
		WillReturnError(userErrDatabase)

	req, _ := http.NewRequest(http.MethodGet, "/users", nil)
	w := userServe(router, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}
