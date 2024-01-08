package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/helper/authhelper"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const OIDC_START_ENDPOINT = "start"
const OIDC_CALLBACK_ENDPOINT = "callback"

const lengthStateStr = 32
const pkceChallengeMethod = "S256"

type OIDCProvider string

const (
	Google    OIDCProvider = "google"
	Facebook  OIDCProvider = "facebook"
	Microsoft OIDCProvider = "microsoft"
	Instagram OIDCProvider = "instagram"
)

func RedirectToOIDCEndpoint(c *gin.Context) {
	if c.Param("action") != "signin" && c.Param("action") != "signup" {
		c.Status(http.StatusNotFound)
		return
	}

	oidcName := c.Param("oidc_name")

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

	oauthConfig, err := getOAuthConfig(oidcClient)
	if err != nil {
		handleInternalError(c, err, "Unable to get OAuth configuration")
		return
	}

	state, err := authhelper.GenerateState(lengthStateStr)
	if err != nil {
		handleInternalError(c, err, "Unable to generate state")
		return
	}
	codeVerifier := authhelper.GeneratePKCEVerifier()
	codeChallenge := authhelper.GeneratePKCEChallenge(codeVerifier)
	authOpts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", pkceChallengeMethod),
	}

	redirectURL := oauthConfig.AuthCodeURL(state, authOpts...)

	if err := setOIDCSession(c, oidcName, state, pkceChallengeMethod, codeChallenge, codeVerifier, c.Query("redirect_uri"), c.Param("action") == "signup"); err != nil {
		handleInternalError(c, err, "Unable to save OIDC session")
		return
	}

	slog.Info(
		"Redirecting to OIDC endpoint",
		slog.String("endpoint", redirectURL),
	)

	c.Redirect(http.StatusFound, redirectURL)
}

func OIDCCallback(c *gin.Context) {
	oidcName := c.Param("oidc_name")

	// originState, originCodeChallengeMethod, originCodeChallenge, originalCodeVerifier, redirectURI, isSignUp, err := getOIDCSession(c, oidcName)
	originState, _, _, originalCodeVerifier, redirectURI, isSignUp, err := getOIDCSession(c, oidcName)
	if err != nil {
		handleInternalError(c, err, "Unable to get OIDC session")
		return
	}

	state := c.Query("state")

	if c.Query("state") != originState {
		handleBadRequest(c, fmt.Errorf("expected state [%s] but got [%s]", originState, state), "Invalid state")
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

	errorParam := c.Query("error")
	if errorParam != "" {
		if errorDescription := c.Query("error_description"); errorDescription != "" {
			err = fmt.Errorf("%s: %s", errorParam, errorDescription)
			handleBadRequest(c, err, "Error from OIDC provider")
			return
		}
		err = fmt.Errorf("%s", errorParam)
		handleBadRequest(c, err, "Error from OIDC provider")
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
	oauthConfig, err := getOAuthConfig(oidcClient)
	if err != nil {
		handleInternalError(c, err, "Unable to get OAuth configuration")
		return
	}

	authOpts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", originalCodeVerifier),
		oauth2.SetAuthURLParam("code_challenge_method", pkceChallengeMethod),
	}

	token, err := oauthConfig.Exchange(
		c.Request.Context(),
		c.Query("code"),
		authOpts...,
	)
	if err != nil {
		handleInternalError(c, err, "Unable to exchange token")
		return
	}

	email, err := getUserInformationFromOIDCProviderCallback(oidcClient, token, c)
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
	if user == nil || isSignUp {
		if !isSignUp {
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

		user = &db.User{
			Email:        email,
			PasswordHash: getPasswordHash(password),
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
		viewModels = append(viewModels, OIDCClientResponse{
			Name:        c.Name,
			ClientID:    c.ClientID,
			RedirectURI: c.RedirectURI,
			ButtonName:  c.ButtonName,
		})
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
	}

	if err := db.CreateOIDCClient(dbConn, &client); err != nil {
		handleInternalError(c, err, "Failed to create OIDC client")
		return
	}

	c.JSON(http.StatusCreated, OIDCClientResponse{
		Name:        client.Name,
		ClientID:    client.ClientID,
		RedirectURI: client.RedirectURI,
		ButtonName:  client.ButtonName,
	})
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
	}

	if err := db.UpdateOIDCClient(dbConn, client); err != nil {
		handleInternalError(c, err, "Failed to update OIDC client")
		return
	}

	c.JSON(http.StatusOK, OIDCClientResponse{
		Name:        client.Name,
		ClientID:    client.ClientID,
		RedirectURI: client.RedirectURI,
		ButtonName:  client.ButtonName,
	})
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

func getOAuthConfig(oidcClient *db.OidcClient) (*oauth2.Config, error) {
	var config *oauth2.Config
	provider := OIDCProvider(oidcClient.Name)
	switch provider {
	case Google:
		config = &oauth2.Config{
			Endpoint: google.Endpoint,
			Scopes:   []string{"openid", "profile", "email"},
		}
	case Facebook:
		// config = &oauth2.Config{
		// 	Endpoint: facebook.Endpoint,
		// 	Scopes:   []string{"public_profile", "email"},
		// }
		return nil, fmt.Errorf("not implemented")
	case Microsoft:
		// config = &oauth2.Config{
		// 	Endpoint: microsoft.LiveConnectEndpoint,
		// 	Scopes:   []string{"wl.basic", "wl.emails"},
		// }
		return nil, fmt.Errorf("not implemented")
	case Instagram:
		// config = &oauth2.Config{
		// 	Endpoint: instagram.Endpoint,
		// 	Scopes:   []string{"basic"},
		// }
		return nil, fmt.Errorf("not implemented")
	default:
		return nil, fmt.Errorf("unsupported OIDC client: %s", oidcClient.Name)
	}

	config.ClientID = oidcClient.ClientID
	config.ClientSecret = oidcClient.ClientSecret
	config.RedirectURL = oidcClient.RedirectURI
	return config, nil
}

func getUserInformationFromOIDCProviderCallback(oidcClient *db.OidcClient, token *oauth2.Token, c *gin.Context) (string, error) {
	switch OIDCProvider(oidcClient.Name) {
	case Google:
		idTokenString, ok := token.Extra("id_token").(string)
		if !ok {
			return "", fmt.Errorf("unable to get ID token")
		}
		provider, err := oidc.NewProvider(c.Request.Context(), "https://accounts.google.com")
		if err != nil {
			return "", fmt.Errorf("unable to get ID token provider: %w", err)
		}
		verifier := provider.Verifier(&oidc.Config{ClientID: oidcClient.ClientID})
		idToken, err := verifier.Verify(c.Request.Context(), idTokenString)
		if err != nil {
			return "", fmt.Errorf("unable to verify ID token: %w", err)
		}

		var claims struct {
			Email string `json:"email"`
		}
		if err := idToken.Claims(&claims); err != nil {
			return "", fmt.Errorf("unable to get claims from ID token: %w", err)
		}
		return claims.Email, nil
	case Facebook:
		slog.Info("Facebook",
			slog.Any("token", token),
		)
		return "", fmt.Errorf("not implemented")
	case Microsoft:
		slog.Info("Microsoft",
			slog.Any("token", token),
		)
		return "", fmt.Errorf("not implemented")
	case Instagram:
		slog.Info("Instagram",
			slog.Any("token", token),
		)
		return "", fmt.Errorf("not implemented")
	default:
		return "", fmt.Errorf("unsupported OIDC client: %s", oidcClient.Name)
	}
}
