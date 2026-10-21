package api

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/helper/database"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func RequiredAuthenticated() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isAuthenticated(c) {
			url, _ := url.Parse("/signin")
			if c.Request.Method == http.MethodGet {
				query := url.Query()
				query.Add(queryParamRedirectURL, c.Request.URL.RequestURI())
				url.RawQuery = query.Encode()
			}
			c.Redirect(http.StatusFound, url.String())
			c.Abort()
			return
		}
		c.Next()
	}
}

func RequiredAdminAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		admin, err := isAdmin(c)
		if err != nil {
			handleInternalError(c, err, "Unable to check admin access")
			return
		}
		if !admin {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

func WithDatabaseConnection(dialector gorm.Dialector) gin.HandlerFunc {
	return func(c *gin.Context) {
		dbConn, err := database.GetDatabaseConnection(dialector)
		if err != nil {
			handleInternalError(c, err, "Unable to connect to database")
			return
		}
		c.Set("db", dbConn)
		c.Next()
	}
}

func WithExpirationPeriod(expirationPeriod int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("expiration_period", expirationPeriod)
		c.Next()
	}
}

func WithMail(resendAPIKey, mailFrom, mailFromName, confirmationMailSubject string, passwordChangedMailSubject string, resetPasswordMailSubject string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("resend_api_key", resendAPIKey)
		c.Set("mail_from", mailFrom)
		c.Set("mail_from_name", mailFromName)
		c.Set("confirmation_mail_subject", confirmationMailSubject)
		c.Set("password_changed_mail_subject", passwordChangedMailSubject)
		c.Set("reset_password_mail_subject", resetPasswordMailSubject)

		c.Next()
	}
}

func WithDomain(domain string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("domain", domain)
		c.Next()
	}
}

// Default redirect targets after a successful sign-up and password change.
const (
	DefaultSignUpRedirect         = "/signup_continue"
	DefaultChangePasswordRedirect = "/changepassword_completed"
)

func WithRedirects(signUpRedirect, changePasswordRedirect string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("signup_redirect", signUpRedirect)
		c.Set("change_password_redirect", changePasswordRedirect)
		c.Next()
	}
}

// getRedirectFromContext returns the redirect target stored under key, or
// defaultRedirect when it is not set.
func getRedirectFromContext(c *gin.Context, key string, defaultRedirect string) string {
	if redirect := c.GetString(key); redirect != "" {
		return redirect
	}
	return defaultRedirect
}

func WithOIDC(enable bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("enable_oidc", enable)
		c.Next()
	}
}

func getDatabaseConnectionFromContext(c *gin.Context) (*gorm.DB, bool) {
	dbConnObj, ok := c.Get("db")
	if !ok {
		return nil, false
	}

	dbConn, ok := dbConnObj.(*gorm.DB)
	if !ok {
		return nil, false
	}

	return dbConn, true
}

func isAdmin(c *gin.Context) (bool, error) {
	if !isAuthenticated(c) {
		return false, nil
	}
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		return false, fmt.Errorf("missing configuration for database")
	}
	email := getEmailFromSession(c)
	return db.HasRole(dbConn, email, "admin")
}
