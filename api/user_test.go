package api

import (
	"bytes"
	"encoding/json"
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
