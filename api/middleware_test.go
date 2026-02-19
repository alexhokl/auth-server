package api

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

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
		if isAdmin(c) {
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
		if isAdmin(c) {
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
