package api

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

func RequiredAuthenticated() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isSignedIn(c) {
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

func isAdmin(c *gin.Context) bool {
	// TODO: implement
	return true
}
