package api

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/slog"
)

const queryParamRedirectURL = "redirect_url"

func isMaliciousRequest(c *gin.Context) error {
	// TODO: Implement
	return nil
}

func getPasswordHash(password string) []byte {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return bytes
}

func handleUnexpectedError(c *gin.Context, err error) {
	slog.Error("Unexpected error", slog.String("error", err.Error()))
	c.AbortWithStatus(http.StatusInternalServerError)
}

func handleInternalError(c *gin.Context, err error, internalErrorMessage string) {
	if err == nil {
		slog.Error(internalErrorMessage)
	} else {
		slog.Error(internalErrorMessage, slog.String("error", err.Error()))
	}
	c.AbortWithStatus(http.StatusInternalServerError)
}

func handleBadRequest(c *gin.Context, err error, internalErrorMessage string) {
	slog.Error(internalErrorMessage, slog.String("error", err.Error()))
	c.AbortWithStatus(http.StatusBadRequest)
}

func generateUniqueCredentialName(existingCredentialNames []string) string {
	for i := 0; i < 100; i++ {
		generatedName := fmt.Sprintf("key %d", i)
		if !slices.Contains(existingCredentialNames, generatedName) {
			return generatedName
		}
	}
	return ""
}
