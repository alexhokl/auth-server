package api

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/helper/jsonhelper"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"
)

type FidoService struct {
	W *webauthn.WebAuthn
}

func NewFidoService(w *webauthn.WebAuthn) *FidoService {
	return &FidoService{
		W: w,
	}
}

// RegisterChallenge serves a challenge for registering a new credential
//
//	@Summary		Serves a challenge for registering a new credential
//	@Description	This starts the dance for registering a new credential
//	@Tags			user
//	@Produce		json
//	@Router			/fido/register/challenge [post]
func (s *FidoService) RegisterChallenge(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	email := getAuthenticatedEmailFromGinContext(c)
	user, err := db.GetUser(dbConn, email)
	if err != nil {
		handleInternalError(c, err, "Failed to get user")
		return
	}
	if user == nil {
		slog.Warn(
			"User not found",
			slog.String("email", email),
		)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	credentialExclusions, err := db.GetCredentialDescriptors(dbConn, email)
	if err != nil {
		slog.Error(
			"Failed to get existing credentials",
			slog.String("error", err.Error()),
			slog.String("email", email),
		)
		// continue on without throwing an error
	}

	creation, webAuthnSession, err := s.W.BeginRegistration(
		user,
		webauthn.WithExclusions(credentialExclusions),
	)
	if err != nil {
		handleInternalError(c, err, "Failed to begin registration")
		return
	}
	if err := setWebAuthnSession(c, webAuthnSession); err != nil {
		handleInternalError(c, err, "Failed to set webauthn session")
		return
	}
	c.JSON(http.StatusOK, creation)
}

// Register verifies and creates a new credential
//
//	@Summary		Verifies and creates a new credential
//	@Description	This completes the dance for registering a new credential
//	@Tags			user
//	@Accept			json
//	@Produce		json
//	@Param			body	body	DummyCredentialCreationData	true	"Credential creation request"
//	@Router			/fido/register [post]
func (s *FidoService) Register(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	res, err := protocol.ParseCredentialCreationResponseBody(c.Request.Body)
	if err != nil {
		if protocolErr, ok := err.(*protocol.Error); ok {
			slog.Warn(
				"Failed to parse credential creation response body",
				slog.String("error", protocolErr.Details),
				slog.String("reason", protocolErr.DevInfo),
			)
		} else {
			slog.Warn(
				"Failed to parse credential creation response body",
				slog.String("error", err.Error()),
			)
		}
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	email := getAuthenticatedEmailFromGinContext(c)
	user, err := db.GetUser(dbConn, email)
	if err != nil {
		handleInternalError(c, err, "Failed to get user")
		return
	}
	if user == nil {
		slog.Warn(
			"User not found",
			slog.String("email", email),
		)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	webAuthnSession, err := getWebAuthnSession(c)
	if err != nil {
		handleInternalError(c, err, "Failed to get webauthn session")
		return
	}

	// chanllenge generated previously is just a random string
	// the challenge returned from client is base64url encoded
	// thus, conversion is required for comparison purpose
	webAuthnSession.Challenge = base64.RawURLEncoding.EncodeToString([]byte(webAuthnSession.Challenge))

	credential, err := s.W.CreateCredential(user, *webAuthnSession, res)
	if err != nil {
		if protocolErr, ok := err.(*protocol.Error); ok {
			slog.Warn(
				"Failed to create credential",
				slog.String("error", protocolErr.Details),
				slog.String("reason", protocolErr.DevInfo),
			)
		} else {
			slog.Warn(
				"Failed to create credential",
				slog.String("error", err.Error()),
			)
		}
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	existingCredentialNames, err := db.GetCredentialNames(dbConn, email)
	if err != nil {
		handleInternalError(c, err, "Failed to get existing credential names")
		return
	}
	keyName := generateUniqueCredentialName(existingCredentialNames)
	if err := db.CreateCredential(dbConn, db.NewUserCredential(email, keyName, credential)); err != nil {
		handleInternalError(c, err, "Failed to save a created credential")
		return
	}

	c.Status(http.StatusOK)
}

// LoginChallenge serves a challenge for starting a login dance
//
//	@Summary		Serves a challenge for starting a login dance
//	@Description	This starts the dance for sign in
//	@Tags			user
//	@Produce		json
//	@Router			/fido/signin/challenge [post]
func (s *FidoService) LoginChallenge(c *gin.Context) {
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

	credentialAssertion, webAuthnSession, err := s.W.BeginLogin(user)
	if err != nil {
		handleInternalError(c, err, "Failed to begin registration")
		return
	}
	sessionJSON, err := jsonhelper.GetJSONString(webAuthnSession)
	if err != nil {
		handleInternalError(c, err, "Failed to serialise webauthn session")
		return
	}
	err = setValuesToSession(c, map[string]interface{}{
		sessionWebAuthnSessionKey: sessionJSON,
		sessionRedirectURLKey:     redirectURL,
	})
	if err != nil {
		handleInternalError(c, err, "Failed to set webauthn session")
		return
	}
	c.JSON(http.StatusOK, credentialAssertion)
}

// Login verifies user credential and sign in
//
//	@Summary		Verifies user credential and sign in
//	@Description	This completes the dance for sign in
//	@Tags			user
//	@Accept			json
//	@Produce		json
//	@Param			body	body	DummyCredentialAssertionData	true	"Credential assertion request"
//	@Router			/fido/signin [post]
func (s *FidoService) Login(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	res, err := protocol.ParseCredentialRequestResponseBody(c.Request.Body)
	if err != nil {
		if protocolErr, ok := err.(*protocol.Error); ok {
			slog.Warn(
				"Failed to parse credential request response body",
				slog.String("error", protocolErr.Details),
				slog.String("reason", protocolErr.DevInfo),
			)
		} else {
			slog.Warn(
				"Failed to parse credential request response body",
				slog.String("error", err.Error()),
			)
		}
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	email := getEmailFromSession(c)
	if email == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	user, err := db.GetUser(dbConn, email)
	if err != nil {
		handleInternalError(c, err, "Failed to get user")
		return
	}
	if user == nil {
		slog.Warn(
			"User not found",
			slog.String("email", email),
		)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	webAuthnSession, err := getWebAuthnSession(c)
	if err != nil {
		slog.Error(
			"WebAuthn session not found",
			slog.String("error", err.Error()),
			slog.String("email", email),
		)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// chanllenge generated previously is just a random string
	// the challenge returned from client is base64url encoded
	// thus, conversion is required for comparison purpose
	webAuthnSession.Challenge = base64.RawURLEncoding.EncodeToString([]byte(webAuthnSession.Challenge))

	credential, err := s.W.ValidateLogin(user, *webAuthnSession, res)
	if err != nil {
		slog.Warn(
			"Failed to validate credential",
			slog.String("error", err.Error()),
			slog.String("credential", fmt.Sprintf("%#v", credential)),
		)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if err := setAuthenticationToSession(c, true); err != nil {
		handleInternalError(c, err, "Unable to save cookie session")
		return
	}

	redirectURLValue, ok := getValueFromSession(c, sessionRedirectURLKey)
	if !ok {
		c.Status(http.StatusOK)
		return
	}
	redirectURL := redirectURLValue.(string)
	if redirectURL == "" {
		c.Status(http.StatusOK)
		return
	}

	c.Redirect(http.StatusFound, redirectURL)
}

func (s *FidoService) GetCredentials(c *gin.Context) {
	email := getAuthenticatedEmailFromGinContext(c)
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}
	credentials, err := db.GetCredentials(dbConn, email)
	if err != nil {
		handleInternalError(c, err, "Unable to get credentials")
		return
	}

	var viewModels []CredentialInfo
	for _, credential := range credentials {
		viewModels = append(viewModels, CredentialInfo{
			ID:   credential.ID,
			Name: credential.FriendlyName,
		})
	}
	c.JSON(http.StatusOK, viewModels)
}

func (s *FidoService) DeleteCredential(c *gin.Context) {
	email := getAuthenticatedEmailFromGinContext(c)
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}
	id := c.Param("id")
	// convert id from string to []byte
	idBytes, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		handleInternalError(c, err, "Unable to decode credential ID")
		return
	}

	if err := db.DeleteCredential(dbConn, email, idBytes); err != nil {
		handleInternalError(c, err, "Unable to delete credential")
		return
	}
	c.Status(http.StatusOK)
}

func (s *FidoService) UpdateCredential(c *gin.Context) {
	email := getAuthenticatedEmailFromGinContext(c)
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}
	id := c.Param("id")
	// convert id from string to []byte
	idBytes, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		handleInternalError(c, err, "Unable to decode credential ID")
		return
	}
	var req CredentialNameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		handleInternalError(c, err, "Unable to bind JSON")
		return
	}
	if err := db.UpdateCredential(dbConn, email, idBytes, req.Name); err != nil {
		if err == gorm.ErrDuplicatedKey {
			handleBadRequest(c, err, "Name already exists")
			return
		}
		handleInternalError(c, err, "Unable to update credential")
		return
	}
	c.Status(http.StatusOK)
}
