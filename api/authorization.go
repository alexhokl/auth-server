package api

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/helper/httphelper"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

const ContentTypeJrdJSON = "application/jrd+json"

func HandleInternalError(err error) (re *errors.Response) {
	switch err {
	case errors.ErrInvalidRedirectURI:
		fallthrough
	case errors.ErrInvalidAuthorizeCode:
		fallthrough
	case errors.ErrInvalidAccessToken:
		fallthrough
	case errors.ErrInvalidRefreshToken:
		fallthrough
	case errors.ErrExpiredAccessToken:
		fallthrough
	case errors.ErrExpiredRefreshToken:
		fallthrough
	case errors.ErrMissingCodeVerifier:
		fallthrough
	case errors.ErrMissingCodeChallenge:
		fallthrough
	case errors.ErrInvalidCodeChallenge:
		return &errors.Response{
			Error:       err,
			Description: err.Error(),
			StatusCode:  http.StatusBadRequest,
		}
	}
	slog.Error(
		"Unhandled InternalError",
		slog.String("error", err.Error()),
	)
	return &errors.Response{
		Error:       err,
		Description: err.Error(),
		StatusCode:  http.StatusInternalServerError,
	}
}

func HandleErrorResponse(re *errors.Response) {
	// TODO: implement
}

// GetOpenIDConfiguration OpenID configuration endpoint
//
//	@summary	OpenID configuration endpoint
//	@Tags		OpenID
//	@Produce	application/json
//	@Router		/.well-known/openid-configuration [get]
func GetOpenIDConfiguration(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}
	issuer := httphelper.GetBaseURL(c.Request)
	oauthConfig := &OpenIDConfiguration{
		Issuer:                            issuer,
		AuthorizationEndpoint:             fmt.Sprintf("%s/authorize", issuer),
		TokenEndpoint:                     fmt.Sprintf("%s/token", issuer),
		JwksUri:                           fmt.Sprintf("%s/.well-known/openid-configuration/jwks", issuer),
		ScopesSupported:                   getScopes(dbConn),
		ResponseTypesSupported:            getResponseTypes(),
		GrantTypesSupported:               getGrantTypes(),
		TokenEndpointAuthMethodsSupported: getTokenEndpointSupportedAuthMethods(),
		CodeChallengeMethodsSupported:     getCodeChallengeMethodsSupported(),
	}
	c.JSON(http.StatusOK, oauthConfig)
}

// GetJSONWebKeySetHandler JSON web key set endpoint
//
//	@summary	JSON web key set endpoint
//	@Tags		OpenID
//	@Produce	application/json
//	@Router		/.well-known/openid-configuration/jwks [get]
func GetJSONWebKeySetHandler(privateKey *ecdsa.PrivateKey) func(c *gin.Context) {
	return func(c *gin.Context) {
		key := JSONWebKey{
			Kty: "EC",
			Alg: fmt.Sprintf("ES%d", privateKey.Params().BitSize),
			Crv: privateKey.Params().Name,
			X:   base64.URLEncoding.EncodeToString(privateKey.X.Bytes()),
			Y:   base64.URLEncoding.EncodeToString(privateKey.Y.Bytes()),
		}
		set := JSONWebKeySet{
			Keys: []JSONWebKey{key},
		}
		c.JSON(http.StatusOK, set)
	}
}

// GetWebFingerConfiguration WebFinger endpoint
//
//	@summary	WebFinger endpoint
//	@Tags		OpenID
//	@Produce	application/jrd+json
//	@Router		/.well-known/webfinger [get]
func GetWebFingerConfiguration(c *gin.Context) {
	issuer := httphelper.GetBaseURL(c.Request)
	links := []WebFingerLinks{
		{
			Rel:  "http://openid.net/specs/connect/1.0/issuer",
			Href: issuer,
		},
	}
	webFingerConfig := &WebFingerConfiguration{
		Subject: fmt.Sprintf("acct:%s", viper.GetString("webfinger_email")),
		Links:   links,
	}

	// header has to be set before c.JSON
	c.Header("Content-Type", ContentTypeJrdJSON)

	c.JSON(http.StatusOK, webFingerConfig)
}

// GetAuthorizationRequestHandler Authorizes and redirects to the redirect_uri
//
//	@summary	Authorize and redirect to the redirect_uri
//	@Tags		OAuth
//	@Accept		x-www-form-urlencoded
//	@Produce	json
//	@Param		response_type	query	string	true	"Response type (e.g. code)"
//	@Param		client_id		query	string	true	"Client ID"
//	@Param		redirect_uri	query	string	true	"Redirect URI"
//	@Router		/authorize [get]
func GetAuthorizationRequestHandler(srv *server.Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := srv.HandleAuthorizeRequest(w, r); err != nil {
			slog.Error(
				"Unable to handle authorization request",
				slog.String("error", err.Error()),
			)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
}

// GetTokenRequestHandler Issues a token
//
//	@summary	Issues a token
//	@Tags		OAuth
//	@Accept		x-www-form-urlencoded
//	@Produce	json
//	@Param		body	formData	TokenRequest	true	"Token request"
//	@Router		/token [post]
func GetTokenRequestHandler(srv *server.Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := srv.HandleTokenRequest(w, r); err != nil {
			slog.Error(
				"Unable to handle token request",
				slog.String("error", err.Error()),
			)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
}

func GetUserIdInAuthorizationRequest(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	// session check has been done in the middleware
	email := getAuthenticatedEmail(w, r)
	if email == "" {
		return "", errors.ErrInvalidRequest
	}
	return email, nil
}

func HandleClientInfoInTokenRequest(r *http.Request) (string, string, error) {
	clientID, clientSecret, err := server.ClientBasicHandler(r)
	if err != nil {
		clientID, clientSecret, err = server.ClientFormHandler(r)
		if err != nil {
			return "", "", err
		}
	}
	return clientID, clientSecret, nil
}

func getResponseTypes() []string {
	return []string{
		"code",
		"token",
	}
}

func getScopes(dbConn *gorm.DB) []string {
	scopes, _ := db.ListScopes(dbConn)
	return scopes
}

func getGrantTypes() []string {
	return []string{
		"authorization_code",
		"refresh_token",
	}
}

func getTokenEndpointSupportedAuthMethods() []string {
	return []string{
		"client_secret_basic",
		"client_secret_post",
	}
}

func getCodeChallengeMethodsSupported() []string {
	return []string{
		"S256",
	}
}
