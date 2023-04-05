package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	session "github.com/go-session/session/v3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/slog"
)

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

func getPasswordHash(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes)
}

func handleUnexpectedError(c *gin.Context, err error) {
	slog.Error("Unexpected error", slog.String("error", err.Error()))
	c.Status(http.StatusInternalServerError)
}

func handleInternalError(c *gin.Context, err error, internalErrorMessage string) {
	slog.Error(internalErrorMessage, slog.String("error", err.Error()))
	c.Status(http.StatusInternalServerError)
}
