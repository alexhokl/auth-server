package api

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/helper/httphelper"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// SignUp creates a new user
//
//	@Summary		Creates a new user
//	@Description	Creates a new user but it does not verify the email address yet
//	@Tags			user
//	@Accept			json
//	@Produce		json
//	@Param			body	body	UserSignUpRequest	true	"User sign up request"
//	@Router			/signup [post]
func SignUp(c *gin.Context) {
	var req UserSignUpRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	expirationPeriod := c.GetInt64("expiration_period")

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	user, err := req.ToUser()
	if err != nil {
		handleInternalError(c, err, "Unable to hash password")
		return
	}
	if err := db.CreateUser(dbConn, user); err != nil {
		handleInternalError(c, err, "Unable to create user")
		return
	}

	confirmationInfo, err := generateConfirmationInfo(user.Email, expirationPeriod, db.ConfirmationPurposeSignUp)
	if err != nil {
		handleInternalError(c, err, "Unable to generate confirmation info")
		return
	}

	if err := db.CreateConfirmation(dbConn, confirmationInfo); err != nil {
		handleInternalError(c, err, "Unable to create user confirmation")
		return
	}

	if err := sendConfirmationEmail(c, confirmationInfo); err != nil {
		handleInternalError(c, err, "Unable to send confirmation email")
		return
	}

	c.Redirect(http.StatusFound, getRedirectFromContext(c, "signup_redirect", DefaultSignUpRedirect))
}

func Confirm(c *gin.Context) {
	otp := c.Param("otp")

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	confirmationInfo, err := db.GetConfirmation(dbConn, otp, db.ConfirmationPurposeSignUp)
	if err != nil {
		handleInternalError(c, err, "Unable to get confirmation info")
		return
	}

	if confirmationInfo == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	if isConfirmationUsedOrExpired(confirmationInfo) {
		c.AbortWithStatus(http.StatusGone)
		return
	}

	if err := db.ConfirmUser(dbConn, confirmationInfo); err != nil {
		if errors.Is(err, db.ErrConfirmationUsed) {
			c.AbortWithStatus(http.StatusGone)
			return
		}
		handleInternalError(c, err, "Unable to confirm user")
		return
	}

	c.Status(http.StatusNoContent)
}

// SignIn starts a sign in session with a user
//
//	@Summary	Starts a sign in session with a user
//	@Tags		user
//	@Accept		x-www-form-urlencoded
//	@Produce	json
//	@Param		body	formData	UserSignInRequest	true	"Sign in request"
//	@Router		/signin [post]
func SignIn(c *gin.Context) {
	var formValues UserSignInRequest
	if err := c.ShouldBind(&formValues); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	redirectURL := c.Query(queryParamRedirectURL)

	if !isSafeRedirectURL(redirectURL) {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if err := isMaliciousRequest(c); err != nil {
		c.AbortWithStatus(http.StatusTooManyRequests)
		return
	}

	if err := setEmailToSession(c, formValues.Email); err != nil {
		handleInternalError(c, err, "Unable to save cookie session")
		return
	}

	challengeURL, _ := url.Parse("/signin/challenge")
	challengeQuery := challengeURL.Query()
	challengeQuery.Add("redirect_uri", redirectURL)
	challengeURL.RawQuery = challengeQuery.Encode()

	c.Redirect(http.StatusFound, challengeURL.String())
}

// SignInPasswordChallenge signs in a user with a password
//
//	@Summary	Signs in a user with a password
//	@Tags		user
//	@Accept		x-www-form-urlencoded
//	@Produce	json
//	@Param		body	formData	UserSignInWithPasswordRequest	true	"Sign in request"
//	@Router		/signin/challenge [post]
func SignInPasswordChallenge(c *gin.Context) {
	var formValues UserSignInWithPasswordRequest
	if err := c.ShouldBind(&formValues); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := getEmailFromSession(c)
	if email == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	redirectURL := c.Query(queryParamRedirectURL)

	if !isSafeRedirectURL(redirectURL) {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	logger := slog.With(
		slog.String("email", email),
	)

	user, err := db.GetUser(dbConn, email)
	if err != nil {
		logger.Warn(
			"Unable to find user",
			slog.String("error", err.Error()),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}
	if user == nil {
		logger.Warn(
			"User not found",
			slog.String("email", email),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	if !user.IsEnabled {
		logger.Warn("User is disabled")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	matches, needsRehash, err := verifyPassword(user.PasswordHash, formValues.Password)
	if err != nil {
		logger.Warn("Unable to verify password", slog.String("error", err.Error()))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}
	if !matches {
		logger.Warn("Invalid password")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}
	if needsRehash {
		upgradePasswordHash(dbConn, user.Email, formValues.Password)
	}

	if err := setAuthenticationToSession(c, true); err != nil {
		handleInternalError(c, err, "Unable to save cookie session")
		return
	}

	if redirectURL == "" {
		c.Status(http.StatusCreated)
		return
	}

	c.Redirect(http.StatusFound, redirectURL)
}

// SignOut signs out a user
//
//	@Summary		Signs out a user
//	@Description	Signs out a user and deletes its email from session. Note that the session cookie would not be deleted.
//	@Tags			user
//	@Produce		json
//	@Router			/signout [post]
func SignOut(c *gin.Context) {
	if !isAuthenticated(c) {
		slog.Info("User is not signed in")
		c.Status(http.StatusNoContent)
		return
	}

	if err := unsetAuthenticatedEmail(c); err != nil {
		handleInternalError(c, err, "Unable to delete cookie session")
		return
	}

	c.Status(http.StatusNoContent)
}

func SignInUI(c *gin.Context) {
	type OIDCClientViewModel struct {
		Name          string
		ButtonName    string
		StartEndpoint string
	}

	enableOIDC := c.GetBool("enable_oidc")
	if !enableOIDC {
		c.HTML(http.StatusOK, "signin.html", gin.H{
			"clients":    []OIDCClientViewModel{},
			"hasClients": false,
		})
		return
	}

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	oidcClients, err := db.ListOIDCClients(dbConn)
	if err != nil {
		slog.Error(
			"Unable to list OIDC clients",
			slog.String("error", err.Error()),
		)
		oidcClients = []db.OidcClient{}
	}

	var viewModels []OIDCClientViewModel
	for _, c := range oidcClients {
		// a client of a provider which is no longer supported cannot sign in
		if !isSupportedExternalProvider(c.Name) {
			continue
		}
		viewModels = append(viewModels, OIDCClientViewModel{
			Name:          c.Name,
			ButtonName:    c.ButtonName,
			StartEndpoint: OIDC_START_ENDPOINT,
		})
	}

	c.HTML(http.StatusOK, "signin.html", gin.H{
		"clients":    viewModels,
		"hasClients": len(viewModels) > 0,
	})
}

func SignInChallengeUI(c *gin.Context) {
	c.File("./assets/signin_challenge.html")
}

func AuthenticatedUI(c *gin.Context) {
	c.File("./assets/authenticated.html")
}

func ChangePasswordUI(c *gin.Context) {
	c.File("./assets/changepassword.html")
}

func HasEmailInSession(c *gin.Context) {
	if email := getEmailFromSession(c); email == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
}

// ListUsers lists users
//
//	@Summary		Lists users
//	@Description	Lists users with their roles and credentials
//	@Tags			users
//	@Produce		json
//	@Success		200	{array}	api.UserResponse
//	@Failure		500
//	@Router			/users [get]
func ListUsers(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	users, err := db.ListUsers(dbConn)
	if err != nil {
		handleInternalError(c, err, "Unable to list users")
		return
	}

	var viewModels []UserResponse
	for _, user := range users {
		viewModels = append(viewModels, ToUserResponse(user))
	}

	c.JSON(http.StatusOK, viewModels)
}

// GetUser retrieves a user
//
//	@Summary		Retrieves a user
//	@Description	Retrieves a user with their roles and credentials
//	@Tags			users
//	@Produce		json
//	@Param			email	path		string	true	"Email address of the user"
//	@Success		200		{object}	api.UserResponse
//	@Failure		404
//	@Failure		500
//	@Router			/users/{email} [get]
func GetUser(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	user, ok := getUserFromPath(c, dbConn)
	if !ok {
		return
	}

	c.JSON(http.StatusOK, ToUserResponse(*user))
}

// UpdateUser patches a user
//
//	@Summary		Patches a user
//	@Description	Patches the display name or the enabled state of a user; only the fields provided are updated. An administrator cannot disable themselves.
//	@Tags			users
//	@Accept			json
//	@Produce		json
//	@Param			email	path		string					true	"Email address of the user"
//	@Param			body	body		api.UserUpdateRequest	true	"User details to be updated"
//	@Success		200		{object}	api.UserResponse
//	@Failure		400
//	@Failure		404
//	@Failure		500
//	@Router			/users/{email} [patch]
func UpdateUser(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	var req UserUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, ok := getUserFromPath(c, dbConn)
	if !ok {
		return
	}

	if req.IsEnabled != nil && !*req.IsEnabled && user.Email == getEmailFromSession(c) {
		handleBadRequest(c, errors.New("unable to disable oneself"), "Unable to update user")
		return
	}

	if err := db.UpdateUser(dbConn, user.Email, req.DisplayName, req.IsEnabled); err != nil {
		handleInternalError(c, err, "Unable to update user")
		return
	}
	if req.DisplayName != nil {
		user.DisplayName = *req.DisplayName
	}
	if req.IsEnabled != nil {
		user.IsEnabled = *req.IsEnabled
	}

	c.JSON(http.StatusOK, ToUserResponse(*user))
}

// DeleteUser deletes a user
//
//	@Summary		Deletes a user
//	@Description	Deletes a user together with their credentials and roles. A user owning OAuth clients cannot be deleted, and an administrator cannot delete themselves.
//	@Tags			users
//	@Param			email	path	string	true	"Email address of the user"
//	@Success		204
//	@Failure		400
//	@Failure		404
//	@Failure		409
//	@Failure		500
//	@Router			/users/{email} [delete]
func DeleteUser(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	user, ok := getUserFromPath(c, dbConn)
	if !ok {
		return
	}

	if user.Email == getEmailFromSession(c) {
		handleBadRequest(c, errors.New("unable to delete oneself"), "Unable to delete user")
		return
	}

	hasClients, err := db.HasClients(dbConn, user.Email)
	if err != nil {
		handleInternalError(c, err, "Unable to check clients of user")
		return
	}
	if hasClients {
		slog.Warn("User owns clients", slog.String("email", user.Email))
		c.JSON(http.StatusConflict, gin.H{"error": "user owns OAuth clients"})
		return
	}

	if err := db.DeleteUser(dbConn, user.Email); err != nil {
		handleInternalError(c, err, "Unable to delete user")
		return
	}

	c.Status(http.StatusNoContent)
}

// AddUserRole grants a role to a user
//
//	@Summary		Grants a role to a user
//	@Description	Grants a role to a user; the role is created if it does not exist
//	@Tags			users
//	@Accept			json
//	@Param			email	path	string				true	"Email address of the user"
//	@Param			body	body	api.UserRoleRequest	true	"Role to be granted"
//	@Success		201
//	@Failure		400
//	@Failure		404
//	@Failure		409
//	@Failure		500
//	@Router			/users/{email}/roles [post]
func AddUserRole(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	var req UserRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, ok := getUserFromPath(c, dbConn)
	if !ok {
		return
	}

	if err := db.AddUserRole(dbConn, user.Email, req.Name); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			c.JSON(http.StatusConflict, gin.H{"error": "user holds the role already"})
			return
		}
		handleInternalError(c, err, "Unable to add role to user")
		return
	}

	c.Status(http.StatusCreated)
}

// RemoveUserRole revokes a role from a user
//
//	@Summary		Revokes a role from a user
//	@Description	Revokes a role from a user. An administrator cannot revoke their own role admin.
//	@Tags			users
//	@Param			email	path	string	true	"Email address of the user"
//	@Param			role	path	string	true	"Name of the role"
//	@Success		204
//	@Failure		400
//	@Failure		404
//	@Failure		500
//	@Router			/users/{email}/roles/{role} [delete]
func RemoveUserRole(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	email := c.Param("email")
	role := c.Param("role")
	if role == "admin" && email == getEmailFromSession(c) {
		handleBadRequest(c, errors.New("unable to revoke role admin from oneself"), "Unable to remove role from user")
		return
	}

	removed, err := db.RemoveUserRole(dbConn, email, role)
	if err != nil {
		handleInternalError(c, err, "Unable to remove role from user")
		return
	}
	if !removed {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	c.Status(http.StatusNoContent)
}

// getUserFromPath retrieves the user of path parameter email; it aborts the
// request and returns false if the user cannot be found.
func getUserFromPath(c *gin.Context, dbConn *gorm.DB) (*db.User, bool) {
	email := c.Param("email")
	user, err := db.GetUser(dbConn, email)
	if err != nil {
		handleInternalError(c, err, "Unable to retrieve user")
		return nil, false
	}
	if user == nil {
		slog.Warn("User not found", slog.String("email", email))
		c.AbortWithStatus(http.StatusNotFound)
		return nil, false
	}
	return user, true
}

func ChangePassword(c *gin.Context) {
	var req PasswordChangeRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := getEmailFromSession(c)
	if email == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	user, err := db.GetUser(dbConn, email)
	if err != nil {
		handleInternalError(c, err, "Unable to get user")
		return
	}
	if user == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	matches, _, err := verifyPassword(user.PasswordHash, req.OldPassword)
	if err != nil || !matches {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid old password"})
		return
	}

	newPasswordHash, err := hashPassword(req.NewPassword)
	if err != nil {
		handleInternalError(c, err, "Unable to hash password")
		return
	}

	if err := db.ChangePassword(dbConn, user.Email, newPasswordHash); err != nil {
		handleInternalError(c, err, "Unable to change password")
		return
	}

	if err := sendPasswordChangedEmail(c, user.Email); err != nil {
		handleInternalError(c, err, "Unable to send password changed email")
		return
	}

	c.Redirect(http.StatusFound, getRedirectFromContext(c, "change_password_redirect", DefaultChangePasswordRedirect))
}

func ResetPassword(c *gin.Context) {
	var req PasswordResetRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	expirationPeriod := c.GetInt64("expiration_period")

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	user, err := db.GetUser(dbConn, req.Email)
	if err != nil {
		handleInternalError(c, err, "Unable to get user")
		return
	}
	if user == nil {
		c.Status(http.StatusOK)
		return
	}

	confirmationInfo, err := generateConfirmationInfo(user.Email, expirationPeriod, db.ConfirmationPurposeResetPassword)
	if err != nil {
		handleInternalError(c, err, "Unable to generate confirmation info")
		return
	}

	if err := db.CreateConfirmation(dbConn, confirmationInfo); err != nil {
		handleInternalError(c, err, "Unable to create user confirmation")
		return
	}

	if err := sendResetPasswordEmail(c, confirmationInfo); err != nil {
		handleInternalError(c, err, "Unable to send reset password email")
		return
	}

	c.Status(http.StatusNoContent)
}

func ConfirmResetPassword(c *gin.Context) {
	otp := c.Param("otp")

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	confirmationInfo, err := db.GetConfirmation(dbConn, otp, db.ConfirmationPurposeResetPassword)
	if err != nil {
		handleInternalError(c, err, "Unable to get confirmation info")
		return
	}

	if confirmationInfo == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	if isConfirmationUsedOrExpired(confirmationInfo) {
		c.AbortWithStatus(http.StatusGone)
		return
	}

	c.HTML(http.StatusOK, "new_password.tmpl", gin.H{
		"otp": otp,
	})
}

func NewPassword(c *gin.Context) {
	var req NewPasswordRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	confirmationInfo, err := db.GetConfirmation(dbConn, req.OTP, db.ConfirmationPurposeResetPassword)
	if err != nil {
		handleInternalError(c, err, "Unable to get confirmation info")
		return
	}

	if confirmationInfo == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	if isConfirmationUsedOrExpired(confirmationInfo) {
		c.AbortWithStatus(http.StatusGone)
		return
	}

	newPasswordHash, err := hashPassword(req.NewPassword)
	if err != nil {
		handleInternalError(c, err, "Unable to hash password")
		return
	}

	if err := db.ResetPassword(dbConn, confirmationInfo, newPasswordHash); err != nil {
		if errors.Is(err, db.ErrConfirmationUsed) {
			c.AbortWithStatus(http.StatusGone)
			return
		}
		handleInternalError(c, err, "Unable to change password")
		return
	}

	if err := sendPasswordChangedEmail(c, confirmationInfo.UserEmail); err != nil {
		handleInternalError(c, err, "Unable to send password changed email")
		return
	}

	c.Status(http.StatusNoContent)
}

func RedirectToChangePasswordUI(c *gin.Context) {
	issuer := httphelper.GetBaseURL(c.Request)
	c.Redirect(http.StatusFound, fmt.Sprintf("%s/changepassword", issuer))
}

func isConfirmationUsedOrExpired(confirmation *db.UserConfirmation) bool {
	return confirmation.ConfirmedTime != 0 || confirmation.ExpiryTime < time.Now().Unix()
}

func generateConfirmationInfo(email string, expiryPeriod int64, purpose string) (*db.UserConfirmation, error) {
	otp, err := generateOneTimePassword(128)
	if err != nil {
		return nil, err
	}

	expiryTime := time.Unix(time.Now().Unix()+expiryPeriod, 0)

	return &db.UserConfirmation{
		UserEmail:       email,
		OneTimePassword: otp,
		ExpiryTime:      expiryTime.Unix(),
		ConfirmedTime:   0,
		Purpose:         purpose,
	}, nil
}

func generateOneTimePassword(lengthRandomBytes int) (string, error) {
	buf := make([]byte, lengthRandomBytes)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(buf), nil
}

