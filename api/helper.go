package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/alexhokl/auth-server/db"
	"github.com/gin-gonic/gin"
	"github.com/resendlabs/resend-go"
	"golang.org/x/crypto/bcrypt"
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

func sendConfirmationEmail(c *gin.Context, confirmationInfo *db.UserConfirmation) error {
	apiKey := c.GetString("resend_api_key")
	mailFrom := c.GetString("mail_from")
	mailFromName := c.GetString("mail_from_name")
	confirmationMailSubject := c.GetString("confirmation_mail_subject")
	domain := c.GetString("domain")
	confirmationURL := fmt.Sprintf("https://%s/confirm/%s", domain, confirmationInfo.OneTimePassword)
    client := resend.NewClient(apiKey)

    params := &resend.SendEmailRequest{
        From:    fmt.Sprintf("%s <%s>", mailFromName, mailFrom),
        To:      []string{confirmationInfo.UserEmail},
        Html:    getMailContent(confirmationURL),
        Subject: confirmationMailSubject,
        Cc:      []string{},
        Bcc:     []string{},
        ReplyTo: mailFrom,
    }

    sent, err := client.Emails.Send(params)
    if err != nil {
		return err
    }
	slog.Info(
		"Confirmation email sent",
		slog.String("id", sent.Id),
		slog.String("to", confirmationInfo.UserEmail),
	)

	return nil
}

func getMailContent(confirmationURL string) string {
	return fmt.Sprintf("<p>Hi,</p><p><a href=\"%s\">Click here to confirm your email address</a></p><p>Regards</p>", confirmationURL)
}
