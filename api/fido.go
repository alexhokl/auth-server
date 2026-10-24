package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/helper/jsonhelper"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const contentTypeJSON = "application/json"

// errSignInBlocked is returned by the user handler of a passkey sign-in when
// the resolved user has too many failed sign-ins.
var errSignInBlocked = errors.New("too many failed sign-ins")

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
//	@Accept			json
//	@Produce		json
//	@Failure		400
//	@Failure		401	"Invalid email or password"
//	@Failure		429	"Too many failed sign-ins"
//	@Router			/fido/signin/challenge [post]
func (s *FidoService) LoginChallenge(c *gin.Context) {
	if !requireJSONRequest(c) {
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

	if isMaliciousRequest(c, email) {
		c.AbortWithStatus(http.StatusTooManyRequests)
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
		recordFailedSignIn(c, email)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}
	if user == nil {
		logger.Warn(
			"User not found",
			slog.String("email", email),
		)
		recordFailedSignIn(c, email)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}
	if !user.IsEnabled {
		logger.Warn("User is disabled")
		recordFailedSignIn(c, email)
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
//	@Failure		401
//	@Failure		429	"Too many failed sign-ins"
//	@Router			/fido/signin [post]
func (s *FidoService) Login(c *gin.Context) {
	if !requireJSONRequest(c) {
		return
	}

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	res, ok := parseCredentialRequestResponseBody(c)
	if !ok {
		return
	}
	email := getEmailFromSession(c)
	if email == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if isMaliciousRequest(c, email) {
		c.AbortWithStatus(http.StatusTooManyRequests)
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
		recordFailedSignIn(c, email)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if !user.IsEnabled {
		slog.Warn(
			"User is disabled",
			slog.String("email", email),
		)
		recordFailedSignIn(c, email)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	webAuthnSession, ok := consumeWebAuthnSession(c)
	if !ok {
		return
	}

	credential, err := s.W.ValidateLogin(user, *webAuthnSession, res)
	if err != nil {
		slog.Warn(
			"Failed to validate credential",
			slog.String("error", err.Error()),
			slog.String("credential", fmt.Sprintf("%#v", credential)),
		)
		recordFailedSignIn(c, email)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	completeLogin(c, dbConn, email, credential)
}

// PasskeyLoginChallenge serves a challenge for signing in with a passkey
//
//	@Summary		Serves a challenge for signing in with a passkey
//	@Description	This starts the dance for sign in without an email address
//	@Tags			user
//	@Accept			json
//	@Produce		json
//	@Failure		400
//	@Failure		429	"Too many failed sign-ins"
//	@Router			/fido/signin/passkey/challenge [post]
func (s *FidoService) PasskeyLoginChallenge(c *gin.Context) {
	if !requireJSONRequest(c) {
		return
	}

	redirectURL := c.Query(queryParamRedirectURL)

	if !isSafeRedirectURL(redirectURL) {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// the user is unknown until an assertion is posted, thus only the IP
	// address is checked
	if isMaliciousRequest(c, "") {
		c.AbortWithStatus(http.StatusTooManyRequests)
		return
	}

	credentialAssertion, webAuthnSession, err := s.W.BeginDiscoverableLogin()
	if err != nil {
		handleInternalError(c, err, "Failed to begin discoverable login")
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

// PasskeyLogin verifies a passkey and sign in
//
//	@Summary		Verifies a passkey and sign in
//	@Description	This completes the dance for sign in without an email address
//	@Tags			user
//	@Accept			json
//	@Produce		json
//	@Param			body	body	DummyCredentialAssertionData	true	"Credential assertion request"
//	@Failure		400
//	@Failure		401
//	@Failure		429	"Too many failed sign-ins"
//	@Router			/fido/signin/passkey [post]
func (s *FidoService) PasskeyLogin(c *gin.Context) {
	if !requireJSONRequest(c) {
		return
	}

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	res, ok := parseCredentialRequestResponseBody(c)
	if !ok {
		return
	}
	// the user is unknown until the user handle is resolved, thus only the IP
	// address is checked here
	if isMaliciousRequest(c, "") {
		c.AbortWithStatus(http.StatusTooManyRequests)
		return
	}
	webAuthnSession, ok := consumeWebAuthnSession(c)
	if !ok {
		return
	}

	// the library returns no user on any error, thus the resolved user is kept
	// so that a failure can be counted against its email address
	var user *db.User
	var dbErr error
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		webAuthnUserID, err := uuid.ParseBytes(userHandle)
		if err != nil {
			return nil, fmt.Errorf("invalid user handle: %w", err)
		}
		// users without a WebAuthn user ID would share the nil handle
		if webAuthnUserID == uuid.Nil {
			return nil, errors.New("user not found")
		}
		found, err := db.GetUserByWebAuthnID(dbConn, webAuthnUserID)
		if err != nil {
			dbErr = err
			return nil, err
		}
		if found == nil {
			return nil, errors.New("user not found")
		}
		user = found
		if isMaliciousRequest(c, found.Email) {
			return nil, errSignInBlocked
		}
		if !found.IsEnabled {
			return nil, errors.New("user is disabled")
		}
		return found, nil
	}

	_, credential, err := s.W.ValidatePasskeyLogin(handler, *webAuthnSession, res)
	if err != nil {
		if dbErr != nil {
			handleInternalError(c, dbErr, "Failed to get user")
			return
		}
		if errors.Is(err, errSignInBlocked) {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		email := ""
		if user != nil {
			email = user.Email
		}
		slog.Warn(
			"Failed to validate passkey",
			slog.String("error", err.Error()),
			slog.String("email", email),
		)
		recordFailedSignIn(c, email)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	completeLogin(c, dbConn, user.Email, credential)
}

// requireJSONRequest rejects a request whose body is not JSON with 400. A
// cross-site request can only be sent with this content type after a CORS
// preflight, which is never granted, so that a third-party page cannot post to
// the sign-in endpoints with the cookie of a user.
func requireJSONRequest(c *gin.Context) bool {
	if c.ContentType() != contentTypeJSON {
		c.AbortWithStatus(http.StatusBadRequest)
		return false
	}
	return true
}

func parseCredentialRequestResponseBody(c *gin.Context) (*protocol.ParsedCredentialAssertionData, bool) {
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
		return nil, false
	}
	return res, true
}

// consumeWebAuthnSession returns the WebAuthn session of a sign-in and removes
// it from the cookie session, so that its challenge is used at most once
// whether the validation succeeds or not.
func consumeWebAuthnSession(c *gin.Context) (*webauthn.SessionData, bool) {
	webAuthnSession, err := getWebAuthnSession(c)
	if err != nil {
		slog.Warn(
			"WebAuthn session not found",
			slog.String("error", err.Error()),
		)
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, false
	}
	if err := unsetWebAuthnSession(c); err != nil {
		handleInternalError(c, err, "Failed to remove webauthn session")
		return nil, false
	}

	// chanllenge generated previously is just a random string
	// the challenge returned from client is base64url encoded
	// thus, conversion is required for comparison purpose
	webAuthnSession.Challenge = base64.RawURLEncoding.EncodeToString([]byte(webAuthnSession.Challenge))

	return webAuthnSession, true
}

// completeLogin writes back the state of the credential used to sign in and,
// unless the credential may have been cloned, marks the session as
// authenticated.
func completeLogin(c *gin.Context, dbConn *gorm.DB, email string, credential *webauthn.Credential) {
	if err := db.UpdateCredentialAuthenticator(dbConn, email, credential); err != nil {
		handleInternalError(c, err, "Failed to update credential")
		return
	}

	// the warning is kept once it is set, thus the credential cannot be used
	// until it is deleted and registered again
	if credential.Authenticator.CloneWarning {
		slog.Warn(
			"Sign counter of credential indicates that it may have been cloned",
			slog.String("email", email),
			slog.String("credential_id", base64.RawURLEncoding.EncodeToString(credential.ID)),
		)
		recordFailedSignIn(c, email)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	recordSuccessfulSignIn(c, email)

	if err := setAuthenticatedEmailToSession(c, email); err != nil {
		handleInternalError(c, err, "Unable to save cookie session")
		return
	}

	redirectURLValue, ok := getValueFromSession(c, sessionRedirectURLKey)
	if !ok {
		c.Status(http.StatusOK)
		return
	}
	redirectURL, _ := redirectURLValue.(string)
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
			ID:             credential.ID,
			Name:           credential.FriendlyName,
			BackupEligible: credential.BackupEligible,
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
		handleBadRequest(c, err, "Unable to decode credential ID")
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
		handleBadRequest(c, err, "Unable to decode credential ID")
		return
	}
	var req CredentialNameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		handleBadRequest(c, err, "Unable to bind JSON")
		return
	}
	if err := db.UpdateCredential(dbConn, email, idBytes, req.Name); err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			handleBadRequest(c, err, "Name already exists")
			return
		}
		handleInternalError(c, err, "Unable to update credential")
		return
	}
	c.Status(http.StatusOK)
}
