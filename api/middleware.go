package api

import (
	"net/http"
	"net/url"

	"github.com/alexhokl/auth-server/db"
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
		if !isAdmin(c) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

func WithDatabaseConnection(dialector gorm.Dialector) gin.HandlerFunc {
	return func(c *gin.Context) {
		dbConn, err := db.GetDatabaseConnection(dialector)
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

func isAdmin(c *gin.Context) bool {
	if !isAuthenticated(c) {
		return false
	}
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		return false
	}
	email := getEmailFromSession(c)
	return db.HasRole(dbConn, email, "admin")
}
