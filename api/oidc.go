package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/helper/authhelper"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

const OIDC_START_ENDPOINT = "start"
const OIDC_CALLBACK_ENDPOINT = "callback"

const lengthStateStr = 32
const pkceChallengeMethod = "S256"

func RedirectToOIDCEndpoint(c *gin.Context) {
	if c.Param("action") != "signin" && c.Param("action") != "signup" {
		c.Status(http.StatusNotFound)
		return
	}

	oidcName := c.Param("oidc_name")
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
	oidcClient, err := db.GetOIDCClient(dbConn, oidcName)
	if err != nil {
		handleInternalError(c, err, "Unable to get OIDC client")
		return
	}
	if oidcClient == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	oauthConfig, provider, err := getOAuthConfig(c.Request.Context(), oidcClient)
	if err != nil {
		handleInternalError(c, err, "Unable to get OAuth configuration")
		return
	}

	state, err := authhelper.GenerateState(lengthStateStr)
	if err != nil {
		handleInternalError(c, err, "Unable to generate state")
		return
	}
	session := &oidcSession{
		State:       state,
		RedirectURI: redirectURL,
		IsSignUp:    c.Param("action") == "signup",
	}
	var authOpts []oauth2.AuthCodeOption
	for key, value := range provider.authParams {
		authOpts = append(authOpts, oauth2.SetAuthURLParam(key, value))
	}
	if provider.usesPKCE {
		session.PKCECodeVerifier = authhelper.GeneratePKCEVerifier()
		session.PKCECodeChallenge = authhelper.GeneratePKCEChallenge(session.PKCECodeVerifier)
		session.PKCECodeChallengeMethod = pkceChallengeMethod
		authOpts = append(
			authOpts,
			oauth2.SetAuthURLParam("code_challenge", session.PKCECodeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", pkceChallengeMethod),
		)
	}
	if provider.usesNonce {
		nonce, err := authhelper.GenerateState(lengthStateStr)
		if err != nil {
			handleInternalError(c, err, "Unable to generate nonce")
			return
		}
		session.Nonce = nonce
		authOpts = append(authOpts, oauth2.SetAuthURLParam("nonce", nonce))
	}

	authCodeURL := oauthConfig.AuthCodeURL(state, authOpts...)

	if err := setOIDCSession(c, session); err != nil {
		handleInternalError(c, err, "Unable to save OIDC session")
		return
	}

	slog.Info(
		"Redirecting to OIDC endpoint",
		slog.String("endpoint", authCodeURL),
	)

	c.Redirect(http.StatusFound, authCodeURL)
}

func OIDCCallback(c *gin.Context) {
	oidcName := c.Param("oidc_name")

	session, err := getOIDCSession(c)
	if err != nil {
		handleInternalError(c, err, "Unable to get OIDC session")
		return
	}

	// a callback is a form post (Apple) or a redirect with a query string
	state := c.Request.FormValue("state")

	if state != session.State {
		handleBadRequest(c, fmt.Errorf("expected state [%s] but got [%s]", session.State, state), "Invalid state")
		return
	}

	// the state, the PKCE verifier and the nonce are for one callback only
	if err := deleteOIDCSession(c); err != nil {
		handleInternalError(c, err, "Unable to delete OIDC session")
		return
	}

	// codeChallenge := c.Query("code_challenge")
	// if codeChallenge != originCodeChallenge {
	// 	handleBadRequest(c, fmt.Errorf("expected code challenge [%s] but got [%s]", originCodeChallenge, codeChallenge), "Invalid code challenge")
	// 	return
	// }

	// codeChallengeMethod := c.Query("code_challenge_method")
	// if codeChallengeMethod != originCodeChallengeMethod {
	// 	handleBadRequest(c, fmt.Errorf("expected code challenge method [%s] but got [%s]", originCodeChallengeMethod, codeChallengeMethod), "Invalid code challenge method")
	// 	return
	// }

	errorParam := c.Request.FormValue("error")
	if errorParam != "" {
		if errorDescription := c.Request.FormValue("error_description"); errorDescription != "" {
			err = fmt.Errorf("%s: %s", errorParam, errorDescription)
			handleBadRequest(c, err, "Error from OIDC provider")
			return
		}
		err = fmt.Errorf("%s", errorParam)
		handleBadRequest(c, err, "Error from OIDC provider")
		return
	}

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}
	oidcClient, err := db.GetOIDCClient(dbConn, oidcName)
	if err != nil {
		handleInternalError(c, err, "Unable to get OIDC client")
		return
	}
	if oidcClient == nil {
		handleInternalError(c, nil, "Unable to get OIDC client")
		return
	}
	oauthConfig, provider, err := getOAuthConfig(c.Request.Context(), oidcClient)
	if err != nil {
		handleInternalError(c, err, "Unable to get OAuth configuration")
		return
	}
	if provider.clientSecret != nil {
		if oauthConfig.ClientSecret, err = provider.clientSecret(oidcClient); err != nil {
			handleInternalError(c, err, "Unable to generate client secret")
			return
		}
	}

	var authOpts []oauth2.AuthCodeOption
	if provider.usesPKCE {
		authOpts = append(authOpts, oauth2.VerifierOption(session.PKCECodeVerifier))
	}

	token, err := oauthConfig.Exchange(
		c.Request.Context(),
		c.Request.FormValue("code"),
		authOpts...,
	)
	if err != nil {
		handleInternalError(c, err, "Unable to exchange token")
		return
	}

	email, err := provider.email(c.Request.Context(), oidcClient, oauthConfig, token, session.Nonce)
	if err != nil {
		handleInternalError(c, err, "Unable to get user information from OIDC provider")
		return
	}

	slog.Info(
		"Obtained user information from OIDC provider",
		slog.String("email", email),
	)

	logger := slog.With(
		slog.String("email", email),
	)

	user, err := db.GetUser(dbConn, email)
	if err != nil {
		logger.Warn(
			"Unable to find user",
			slog.String("error", err.Error()),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}
	// a sign up of an existing user is treated as a sign in as the user has
	// proven the ownership of the email address with the OIDC provider
	if user == nil {
		if !session.IsSignUp {
			logger.Warn(
				"User not found",
				slog.String("email", email),
			)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		password, err := generateOneTimePassword(32)
		if err != nil {
			handleInternalError(c, err, "Unable to generate password")
			return
		}

		passwordHash, err := hashPassword(password)
		if err != nil {
			handleInternalError(c, err, "Unable to hash password")
			return
		}

		user = &db.User{
			Email:        email,
			PasswordHash: passwordHash,
			IsEnabled:    true,
		}
		if err := db.CreateUser(dbConn, user); err != nil {
			handleInternalError(c, err, "Unable to create user")
			return
		}
	}

	if !user.IsEnabled {
		logger.Warn("User is disabled")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User has been disabled"})
		return
	}

	if err := setEmailToSession(c, user.Email); err != nil {
		handleInternalError(c, err, "Unable to save cookie session")
		return
	}

	if err := setAuthenticationToSession(c, true); err != nil {
		handleInternalError(c, err, "Unable to save cookie session")
		return
	}

	redirectURI := session.RedirectURI
	if redirectURI == "" {
		redirectURI = "/authenticated"
	}

	c.Redirect(http.StatusFound, redirectURI)
}

func ListOIDCCLients(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	clients, err := db.ListOIDCClients(dbConn)
	if err != nil {
		handleInternalError(c, err, "Failed to list OIDC clients")
		return
	}

	if len(clients) == 0 {
		c.JSON(http.StatusOK, []OIDCClientResponse{})
		return
	}

	var viewModels []OIDCClientResponse
	for _, c := range clients {
		viewModels = append(viewModels, toOIDCClientResponse(&c))
	}

	c.JSON(http.StatusOK, viewModels)
}

func CreateOIDCClient(c *gin.Context) {
	var request OIDCClientCreateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		handleBadRequest(c, err, "Failed to parse request body")
		return
	}

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	client := db.OidcClient{
		Name:         request.Name,
		ClientID:     request.ClientID,
		ClientSecret: request.ClientSecret,
		RedirectURI:  request.RedirectURI,
		ButtonName:   request.ButtonName,
		Issuer:       request.Issuer,
		TeamID:       request.TeamID,
		KeyID:        request.KeyID,
	}
	if err := validateOIDCClient(&client); err != nil {
		handleBadRequest(c, err, "Invalid OIDC client")
		return
	}

	if err := db.CreateOIDCClient(dbConn, &client); err != nil {
		handleInternalError(c, err, "Failed to create OIDC client")
		return
	}

	c.JSON(http.StatusCreated, toOIDCClientResponse(&client))
}

func UpdateOIDCClient(c *gin.Context) {
	var request OIDCClientUpdateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		handleBadRequest(c, err, "Failed to parse request body")
		return
	}

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	client := &db.OidcClient{
		Name:         c.Param("name"),
		ClientID:     request.ClientID,
		ClientSecret: request.ClientSecret,
		RedirectURI:  request.RedirectURI,
		ButtonName:   request.ButtonName,
		Issuer:       request.Issuer,
		TeamID:       request.TeamID,
		KeyID:        request.KeyID,
	}
	if err := validateOIDCClient(client); err != nil {
		handleBadRequest(c, err, "Invalid OIDC client")
		return
	}

	if err := db.UpdateOIDCClient(dbConn, client); err != nil {
		handleInternalError(c, err, "Failed to update OIDC client")
		return
	}

	c.JSON(http.StatusOK, toOIDCClientResponse(client))
}

func DeleteOIDCClient(c *gin.Context) {
	name := c.Param("name")

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	if err := db.DeleteOIDCClient(dbConn, name); err != nil {
		handleInternalError(c, err, "Failed to delete OIDC client")
		return
	}

	c.Status(http.StatusOK)
}

func toOIDCClientResponse(client *db.OidcClient) OIDCClientResponse {
	return OIDCClientResponse{
		Name:        client.Name,
		ClientID:    client.ClientID,
		RedirectURI: client.RedirectURI,
		ButtonName:  client.ButtonName,
		Issuer:      client.Issuer,
		TeamID:      client.TeamID,
		KeyID:       client.KeyID,
	}
}
