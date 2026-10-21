package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alexhokl/helper/database"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func getTestDBConnection() (*gorm.DB, sqlmock.Sqlmock) {
	mockDB, mock, _ := sqlmock.New()
	dialector := database.GetDatabaseDialectorFromConnection(mockDB)
	dbConn, _ := gorm.Open(dialector, &gorm.Config{})
	return dbConn, mock
}

// RequiredAuthenticated Tests

func TestRequiredAuthenticated_NotAuthenticated_RedirectsToSignIn(t *testing.T) {
	router := gin.New()
	router.GET("/protected", RequiredAuthenticated(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "/signin")
}

func TestRequiredAuthenticated_NotAuthenticated_IncludesRedirectURL(t *testing.T) {
	router := gin.New()
	router.GET("/protected/resource", RequiredAuthenticated(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected/resource?param=value", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "/signin")
	assert.Contains(t, location, "redirect_uri")
}

func TestRequiredAuthenticated_POSTRequest_NoRedirectParam(t *testing.T) {
	router := gin.New()
	router.POST("/protected", RequiredAuthenticated(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/protected", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Equal(t, "/signin", location)
}

// RequiredAdminAccess Tests

func TestRequiredAdminAccess_NotAuthenticated_ReturnsForbidden(t *testing.T) {
	router := gin.New()
	router.GET("/admin", RequiredAdminAccess(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequiredAdminAccess_NoDatabaseConnection_ReturnsForbidden(t *testing.T) {
	router := gin.New()
	// Simulate authenticated but no database connection
	router.Use(func(c *gin.Context) {
		// Don't set db in context
		c.Next()
	})
	router.GET("/admin", RequiredAdminAccess(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// WithDatabaseConnection Tests

func TestWithDatabaseConnection_SetsDBInContext(t *testing.T) {
	dbConn, _ := getTestDBConnection()

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("db", dbConn)
		c.Next()
	})
	router.GET("/test", func(c *gin.Context) {
		db, ok := getDatabaseConnectionFromContext(c)
		if !ok {
			c.Status(http.StatusInternalServerError)
			return
		}
		if db == nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// WithExpirationPeriod Tests

func TestWithExpirationPeriod_SetsValueInContext(t *testing.T) {
	router := gin.New()
	router.Use(WithExpirationPeriod(3600))
	router.GET("/test", func(c *gin.Context) {
		period := c.GetInt64("expiration_period")
		if period != 3600 {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// WithMail Tests

func TestWithMail_SetsAllMailConfigInContext(t *testing.T) {
	router := gin.New()
	router.Use(WithMail(
		"api-key",
		"from@example.com",
		"From Name",
		"Confirm Subject",
		"Password Changed Subject",
		"Reset Password Subject",
	))
	router.GET("/test", func(c *gin.Context) {
		apiKey, _ := c.Get("resend_api_key")
		mailFrom, _ := c.Get("mail_from")
		mailFromName, _ := c.Get("mail_from_name")
		confirmSubject, _ := c.Get("confirmation_mail_subject")
		passwordChangedSubject, _ := c.Get("password_changed_mail_subject")
		resetPasswordSubject, _ := c.Get("reset_password_mail_subject")

		if apiKey != "api-key" ||
			mailFrom != "from@example.com" ||
			mailFromName != "From Name" ||
			confirmSubject != "Confirm Subject" ||
			passwordChangedSubject != "Password Changed Subject" ||
			resetPasswordSubject != "Reset Password Subject" {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// WithDomain Tests

func TestWithDomain_SetsDomainInContext(t *testing.T) {
	router := gin.New()
	router.Use(WithDomain("example.com"))
	router.GET("/test", func(c *gin.Context) {
		domain, _ := c.Get("domain")
		if domain != "example.com" {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// WithRedirects Tests

func TestWithRedirects_SetsValuesInContext(t *testing.T) {
	router := gin.New()
	router.Use(WithRedirects("/welcome", "/password-changed"))
	router.GET("/test", func(c *gin.Context) {
		if c.GetString("signup_redirect") != "/welcome" ||
			c.GetString("change_password_redirect") != "/password-changed" {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetRedirectFromContext_EmptyReturnsDefault(t *testing.T) {
	router := gin.New()
	router.Use(WithRedirects("", ""))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, getRedirectFromContext(c, "signup_redirect", DefaultSignUpRedirect))
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, DefaultSignUpRedirect, w.Body.String())
}

// WithOIDC Tests

func TestWithOIDC_EnabledSetsTrue(t *testing.T) {
	router := gin.New()
	router.Use(WithOIDC(true))
	router.GET("/test", func(c *gin.Context) {
		enabled := c.GetBool("enable_oidc")
		if !enabled {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWithOIDC_DisabledSetsFalse(t *testing.T) {
	router := gin.New()
	router.Use(WithOIDC(false))
	router.GET("/test", func(c *gin.Context) {
		enabled := c.GetBool("enable_oidc")
		if enabled {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// getDatabaseConnectionFromContext Tests

func TestGetDatabaseConnectionFromContext_NoDBInContext(t *testing.T) {
	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		_, ok := getDatabaseConnectionFromContext(c)
		if ok {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetDatabaseConnectionFromContext_WrongTypeInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("db", "not a db connection")
		c.Next()
	})
	router.GET("/test", func(c *gin.Context) {
		_, ok := getDatabaseConnectionFromContext(c)
		if ok {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetDatabaseConnectionFromContext_ValidDBInContext(t *testing.T) {
	dbConn, _ := getTestDBConnection()

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("db", dbConn)
		c.Next()
	})
	router.GET("/test", func(c *gin.Context) {
		db, ok := getDatabaseConnectionFromContext(c)
		if !ok || db == nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// isAdmin Tests (requires database and session mocking, complex to test thoroughly)

func TestIsAdmin_NotAuthenticated_ReturnsFalse(t *testing.T) {
	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		admin, err := isAdmin(c)
		assert.NoError(t, err)
		if admin {
			c.Status(http.StatusOK)
			return
		}
		c.Status(http.StatusForbidden)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestIsAdmin_NoDatabaseConnection_ReturnsFalse(t *testing.T) {
	router := gin.New()
	// No database connection set
	router.GET("/test", func(c *gin.Context) {
		admin, err := isAdmin(c)
		assert.NoError(t, err)
		if admin {
			c.Status(http.StatusOK)
			return
		}
		c.Status(http.StatusForbidden)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// Integration-like test for middleware chain

func TestMiddlewareChain_AllMiddlewaresApplied(t *testing.T) {
	dbConn, mock := getTestDBConnection()

	// Expect the query for ListUsers
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users"`)).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}))
	// Expect preload for credentials
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles"`)).
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "role_name"}))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials"`)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email"}))

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("db", dbConn)
		c.Next()
	})
	router.Use(WithExpirationPeriod(3600))
	router.Use(WithDomain("test.com"))
	router.Use(WithOIDC(true))
	router.GET("/users", ListUsers)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/users", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// isAdmin and RequiredAdminAccess Tests with a signed in user

func mwExpectHasRole(mock sqlmock.Sqlmock, email string, role string, count int) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "user_roles" WHERE user_email = $1 AND role_name = $2`)).
		WithArgs(email, role).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(count))
}

func mwGetAdminRouter(handlers ...gin.HandlerFunc) (*gin.Engine, sqlmock.Sqlmock) {
	dbConn, mock := getTestDBConnection()
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("db", dbConn)
		c.Next()
	})
	router.GET("/test", handlers...)
	return router, mock
}

func mwIsAdminHandler(c *gin.Context) {
	admin, err := isAdmin(c)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	if admin {
		c.Status(http.StatusOK)
		return
	}
	c.Status(http.StatusForbidden)
}

func TestIsAdmin_AuthenticatedWithAdminRole_ReturnsTrue(t *testing.T) {
	router, mock := mwGetAdminRouter(mwIsAdminHandler)
	expectActiveUser(mock, "admin@test.com", true, nil)
	mwExpectHasRole(mock, "admin@test.com", "admin", 1)

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := serveInSession(t, router, authenticatedSession("admin@test.com"), req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIsAdmin_AuthenticatedWithoutAdminRole_ReturnsFalse(t *testing.T) {
	router, mock := mwGetAdminRouter(mwIsAdminHandler)
	expectActiveUser(mock, "user@test.com", true, nil)
	mwExpectHasRole(mock, "user@test.com", "admin", 0)

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := serveInSession(t, router, authenticatedSession("user@test.com"), req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIsAdmin_EmailWithoutAuthentication_ReturnsFalse(t *testing.T) {
	router, mock := mwGetAdminRouter(mwIsAdminHandler)

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := serveInSession(t, router, map[string]interface{}{sessionEmailKey: "admin@test.com"}, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	// no role is queried for a user not signed in
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRequiredAdminAccess_Admin_ReturnsOK(t *testing.T) {
	router, mock := mwGetAdminRouter(RequiredAdminAccess(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	expectActiveUser(mock, "admin@test.com", true, nil)
	mwExpectHasRole(mock, "admin@test.com", "admin", 1)

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := serveInSession(t, router, authenticatedSession("admin@test.com"), req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRequiredAdminAccess_NonAdmin_ReturnsForbidden(t *testing.T) {
	router, mock := mwGetAdminRouter(RequiredAdminAccess(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	expectActiveUser(mock, "user@test.com", true, nil)
	mwExpectHasRole(mock, "user@test.com", "admin", 0)

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := serveInSession(t, router, authenticatedSession("user@test.com"), req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIsAdmin_AuthenticatedWithoutDatabase_ReturnsError(t *testing.T) {
	router := gin.New()
	router.GET("/test", mwIsAdminHandler)

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := serveInSession(t, router, authenticatedSession("admin@test.com"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRequiredAdminAccess_DatabaseError_ReturnsInternalServerError(t *testing.T) {
	router, mock := mwGetAdminRouter(RequiredAdminAccess(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	expectActiveUser(mock, "admin@test.com", true, nil)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "user_roles" WHERE user_email = $1 AND role_name = $2`)).
		WithArgs("admin@test.com", "admin").
		WillReturnError(errors.New("database error"))

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := serveInSession(t, router, authenticatedSession("admin@test.com"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// RequiredAuthenticated Tests with a signed in user

func TestRequiredAuthenticated_Authenticated_ReturnsOK(t *testing.T) {
	router, mock := mwGetAdminRouter(RequiredAuthenticated(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	expectActiveUser(mock, "user@test.com", true, nil)

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := serveInSession(t, router, authenticatedSession("user@test.com"), req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRequiredAuthenticated_InactiveUser_RedirectsToSignIn(t *testing.T) {
	revokedAt := time.Now().Add(time.Minute)
	tests := []struct {
		name   string
		expect func(mock sqlmock.Sqlmock)
	}{
		{"disabled", func(mock sqlmock.Sqlmock) { expectActiveUser(mock, "user@test.com", false, nil) }},
		{"revoked", func(mock sqlmock.Sqlmock) { expectActiveUser(mock, "user@test.com", true, &revokedAt) }},
		{"deleted", func(mock sqlmock.Sqlmock) {
			mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
				WithArgs("user@test.com", 1).
				WillReturnError(gorm.ErrRecordNotFound)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stillAuthenticated := true
			router, mock := mwGetAdminRouter(RequiredAuthenticated(), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})
			router.GET("/check", func(c *gin.Context) {
				stillAuthenticated = isAuthenticated(c)
			})
			tt.expect(mock)

			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			w := serveInSession(t, router, authenticatedSession("user@test.com"), req)

			assert.Equal(t, http.StatusFound, w.Code)
			assert.Contains(t, w.Header().Get("Location"), "/signin")
			assert.NoError(t, mock.ExpectationsWereMet())

			// the session is signed out
			check, _ := http.NewRequest(http.MethodGet, "/check", nil)
			for _, cookie := range req.Cookies() {
				check.AddCookie(cookie)
			}
			router.ServeHTTP(httptest.NewRecorder(), check)
			assert.False(t, stillAuthenticated)
		})
	}
}

// A session authenticated before the time of authentication was recorded is
// not trusted.
func TestRequiredAuthenticated_WithoutAuthenticatedAt_RedirectsToSignIn(t *testing.T) {
	router, mock := mwGetAdminRouter(RequiredAuthenticated(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := serveInSession(t, router, map[string]interface{}{
		sessionEmailKey:           "user@test.com",
		sessionIsAuthenticatedKey: true,
	}, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRequiredAuthenticated_DatabaseError_ReturnsInternalServerError(t *testing.T) {
	router, mock := mwGetAdminRouter(RequiredAuthenticated(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("user@test.com", 1).
		WillReturnError(errors.New("database error"))

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := serveInSession(t, router, authenticatedSession("user@test.com"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRequiredAuthenticated_NoDatabaseConnection_ReturnsInternalServerError(t *testing.T) {
	router := gin.New()
	router.GET("/test", RequiredAuthenticated(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := serveInSession(t, router, authenticatedSession("user@test.com"), req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// A disabled administrator keeps their role but loses admin access.
func TestRequiredAdminAccess_DisabledAdmin_ReturnsForbidden(t *testing.T) {
	router, mock := mwGetAdminRouter(RequiredAdminAccess(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	expectActiveUser(mock, "admin@test.com", false, nil)

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	w := serveInSession(t, router, authenticatedSession("admin@test.com"), req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// WithDatabaseConnection Tests with the middleware itself

// mwFailingDialector is a dialector which fails to initialise.
type mwFailingDialector struct {
	gorm.Dialector
}

func (d mwFailingDialector) Initialize(*gorm.DB) error {
	return errors.New("unable to connect")
}

func TestWithDatabaseConnection_ConnectionError_ReturnsInternalServerError(t *testing.T) {
	mockDB, _, _ := sqlmock.New()
	dialector := mwFailingDialector{Dialector: database.GetDatabaseDialectorFromConnection(mockDB)}

	handlerCalled := false
	router := gin.New()
	router.GET("/test", WithDatabaseConnection(dialector), func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.False(t, handlerCalled)
}
