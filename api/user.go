package api

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/alexhokl/auth-server/db"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
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

	user := req.ToUser()
	if err := db.CreateUser(dbConn, user); err != nil {
		handleInternalError(c, err, "Unable to create user")
		return
	}

	confirmationInfo, err := generateConfirmationInfo(user.Email, expirationPeriod)
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

	// TODO: make this configurable
	c.Redirect(http.StatusFound, "/signup_continue")
}

func Confirm(c *gin.Context) {
	otp := c.Param("otp")

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	confirmationInfo, err := db.GetConfirmation(dbConn, otp)
	if err != nil {
		handleInternalError(c, err, "Unable to get confirmation info")
		return
	}

	if confirmationInfo == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	if confirmationInfo.ExpiryTime < time.Now().Unix() {
		c.AbortWithStatus(http.StatusGone)
		return
	}

	if err := db.ConfirmUser(dbConn, confirmationInfo); err != nil {
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
	challengeQuery.Add("redirect_url", redirectURL)
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

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(formValues.Password)); err != nil {
		logger.Warn("Invalid password")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
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

func SignInChallengeUI(c *gin.Context) {
	c.File("./assets/signin_challenge.html")
}

func AuthenticatedUI(c *gin.Context) {
	c.File("./assets/authenticated.html")
}

func HomeUI(c *gin.Context) {
	c.File("./assets/home.html")
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
		m := UserResponse{
			Email:       user.Email,
			DisplayName: user.DisplayName,
			Roles:       []string{},
			Credentials: []CredentialInfo{},
			IsEnabled:   user.IsEnabled,
		}
		for _, role := range user.Roles {
			m.Roles = append(m.Roles, role.Name)
		}
		for _, credential := range user.Credentials {
			m.Credentials = append(m.Credentials, CredentialInfo{
				ID:   credential.ID,
				Name: credential.FriendlyName,
			})
		}

		viewModels = append(viewModels, m)
	}

	c.JSON(http.StatusOK, viewModels)
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

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid old password"})
		return
	}

	if err := db.ChangePassword(dbConn, user.Email, getPasswordHash(req.NewPassword)); err != nil {
		handleInternalError(c, err, "Unable to change password")
		return
	}

	if err := sendPasswordChangedEmail(c, user.Email); err != nil {
		handleInternalError(c, err, "Unable to send password changed email")
		return
	}

	// TODO: make this configurable
	c.Redirect(http.StatusFound, "/changepassword_completed")
}


func generateConfirmationInfo(email string, expiryPeriod int64) (*db.UserConfirmation, error) {
	otp, err := generateOneTimePassword()
	if err != nil {
		return nil, err
	}

	expiryTime := time.Unix(time.Now().Unix()+expiryPeriod, 0)

	return &db.UserConfirmation{
		UserEmail:       email,
		OneTimePassword: otp,
		ExpiryTime:      expiryTime.Unix(),
		ConfirmedTime:   0,
	}, nil
}

func generateOneTimePassword() (string, error) {
	buf := make([]byte, 128)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(buf), nil
}
