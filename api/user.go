package api

import (
	"net/http"

	"github.com/alexhokl/auth-server/db"
	"github.com/gin-gonic/gin"
	"golang.org/x/exp/slog"
)

const cookieEmailKey = "email"

// SignUp creates a new user
//
//	@Summary		Creates a new user
//	@Description	Creates a new user
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

	conn, err := db.GetDatabaseConnection()
	if err != nil {
		handleInternalError(c, err, "Unable to connect to database")
		return
	}

	if result := conn.Create(user); result.Error != nil {
		handleInternalError(c, result.Error, "Unable to create user")
		return
	}

	c.Status(http.StatusCreated)
}

// SignIn signs in a user
//
//	@Summary	Signs in a user
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

	passwordHash := getPasswordHash(formValues.Password)

	conn, err := db.GetDatabaseConnection()
	if err != nil {
		handleInternalError(c, err, "Unable to connect to database")
		return
	}

	logger := slog.With(
		slog.String("email", formValues.Email),
		slog.String(headerXForwardedFor, c.Request.Header.Get(headerXForwardedFor)),
		slog.String(headerXForwardedHost, c.Request.Header.Get(headerXForwardedHost)),
		slog.String(headerHost, c.Request.Host),
	)

	var user db.User
	dbResult := conn.First(&user, "email = ?", formValues.Email)
	if dbResult.Error != nil {
		logger.Warn(
			"Unable to find user",
			slog.String("error", dbResult.Error.Error()),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}
	if user.PasswordHash != passwordHash {
		logger.Warn("Invalid password")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	sessionStore, err := getSessionStore(c)
	if err != nil {
		handleInternalError(c, err, "Unable to start a cookie session")
		return
	}
	sessionStore.Set(cookieEmailKey, formValues.Email)
	if err = sessionStore.Save(); err != nil {
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
//	@Summary	Signs out a user
//	@Tags		user
//	@Produce	json
//	@Router		/signout [post]
func SignOut(c *gin.Context) {
	sessionStore, err := getSessionStore(c)
	if err != nil {
		handleInternalError(c, err, "Unable to start a cookie session")
		return
	}

	if !isSignedIn(c) {
		slog.Info("User is not signed in")
		c.Status(http.StatusNoContent)
		return
	}

	sessionStore.Delete(cookieEmailKey)
	sessionStore.Flush()

	c.Status(http.StatusNoContent)
}