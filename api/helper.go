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

const queryParamRedirectURL = "redirect_uri"

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
        Html:    getConfirmationMailContent(confirmationURL),
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

func sendPasswordChangedEmail(c *gin.Context, email string) error {
	apiKey := c.GetString("resend_api_key")
	mailFrom := c.GetString("mail_from")
	mailFromName := c.GetString("mail_from_name")
	passwordChangedMailSubject := c.GetString("password_changed_mail_subject")
	client := resend.NewClient(apiKey)

	params := &resend.SendEmailRequest{
		From:    fmt.Sprintf("%s <%s>", mailFromName, mailFrom),
		To:      []string{email},
		Html:    getPasswordChangedMailContent(),
		Subject: passwordChangedMailSubject,
		Cc:      []string{},
		Bcc:     []string{},
		ReplyTo: mailFrom,
	}

	sent, err := client.Emails.Send(params)
	if err != nil {
		return err
	}
	slog.Info(
		"Password changed email sent",
		slog.String("id", sent.Id),
		slog.String("to", email),
	)

	return nil
}

func sendResetPasswordEmail(c *gin.Context, confirmationInfo *db.UserConfirmation) error {
	apiKey := c.GetString("resend_api_key")
	mailFrom := c.GetString("mail_from")
	mailFromName := c.GetString("mail_from_name")
	domain := c.GetString("domain")
	resetPasswordURL := fmt.Sprintf("https://%s/confirmresetpassword/%s", domain, confirmationInfo.OneTimePassword)
	resetPasswordMailSubject := c.GetString("reset_password_mail_subject")
	client := resend.NewClient(apiKey)

	params := &resend.SendEmailRequest{
		From:    fmt.Sprintf("%s <%s>", mailFromName, mailFrom),
		To:      []string{confirmationInfo.UserEmail},
		Html:    getResetPasswordMailContent(resetPasswordURL),
		Subject: resetPasswordMailSubject,
		Cc:      []string{},
		Bcc:     []string{},
		ReplyTo: mailFrom,
	}

	sent, err := client.Emails.Send(params)
	if err != nil {
		return err
	}
	slog.Info(
		"Reset password email sent",
		slog.String("id", sent.Id),
		slog.String("to", confirmationInfo.UserEmail),
	)

	return nil
}

func getConfirmationMailContent(confirmationURL string) string {
	return fmt.Sprintf("<p>Hi,</p><p><a href=\"%s\">Click here to confirm your email address</a></p><p>Regards</p>", confirmationURL)
}

func getPasswordChangedMailContent() string {
	return "<p>Hi,</p><p>Your password has been changed.</p><p>Regards</p>"
}

func getResetPasswordMailContent(resetPasswordURL string) string {
	return fmt.Sprintf("<p>Hi,</p><p><a href=\"%s\">Click here to reset your password</a></p><p>Regards</p>", resetPasswordURL)
}
