package api

import (
	"fmt"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	session "github.com/go-session/session/v3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/slog"
)

const headerHost = "Host"
const headerXForwardedFor = "X-Forwarded-For"
const headerXForwardedHost = "X-Forwarded-Host"
const queryParamRedirectURL = "redirect_url"

func isSignedIn(c *gin.Context) bool {
	sessionStore, err := getSessionStore(c)
	if err != nil {
		slog.Error("Unable to start a cookie session", slog.String("error", err.Error()))
		return false
	}

	_, exist := sessionStore.Get(cookieEmailKey)
	return exist
}

func getSessionStore(c *gin.Context) (session.Store, error) {
	return session.Start(c.Request.Context(), c.Writer, c.Request)
}

func getHostWithoutPort(host string) string {
	domain, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return domain
}

func getPasswordHash(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes)
}

func getDomainFromHostHeaders(c *gin.Context) string {
	domain := getHostWithoutPort(c.Request.Header.Get(headerXForwardedHost))
	if domain == "" {
		domain = getHostWithoutPort(c.Request.Host)
		if domain == "" {
			domain = "localhost"
		}
	}
	return domain
}

func getProtocolFromHostHeaders(c *gin.Context) string {
	if c.Request.Header.Get(headerXForwardedHost) != "" {
		return "https"
	}
	return "http"
}

func getPortFromHostHeaders(c *gin.Context) string {
	if c.Request.Header.Get(headerXForwardedHost) != "" {
		return ""
	}
	return fmt.Sprintf(":%d", viper.GetInt("port"))
}

func handleUnexpectedError(c *gin.Context, err error) {
	slog.Error("Unexpected error", slog.String("error", err.Error()))
	c.Status(http.StatusInternalServerError)
}

func handleInternalError(c *gin.Context, err error, internalErrorMessage string) {
	slog.Error(internalErrorMessage, slog.String("error", err.Error()))
	c.Status(http.StatusInternalServerError)
}
