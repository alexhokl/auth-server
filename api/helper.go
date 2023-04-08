package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/slog"
)

const queryParamRedirectURL = "redirect_url"

func isMaliciousRequest(c *gin.Context) error {
	// TODO: Implement
	return nil
}

func getPasswordHash(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes)
}

func handleUnexpectedError(c *gin.Context, err error) {
	slog.Error("Unexpected error", slog.String("error", err.Error()))
	c.AbortWithStatus(http.StatusInternalServerError)
}

func handleInternalError(c *gin.Context, err error, internalErrorMessage string) {
	slog.Error(internalErrorMessage, slog.String("error", err.Error()))
	c.AbortWithStatus(http.StatusInternalServerError)
}
