package api

import (
	"log/slog"
	"net/http"
	"net/url"

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
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user := req.ToUser()

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	if err := db.CreateUser(dbConn, user); err != nil {
		handleInternalError(c, err, "Unable to create user")
		return
	}

	c.Status(http.StatusCreated)
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
		}
		for _, role := range user.Roles {
			m.Roles = append(m.Roles, role.Name)
		}
		for _, credential := range user.Credentials {
			m.Credentials = append(m.Credentials, CredentialInfo{
				ID:           credential.ID,
				Name: credential.FriendlyName,
			})
		}

		viewModels = append(viewModels, m)
	}

	c.JSON(http.StatusOK, viewModels)
}
