package api

import (
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/auth-server/jwthelper"
	"github.com/alexhokl/helper/httphelper"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt/v5"
)

const (
	scopeOpenID  = "openid"
	scopeProfile = "profile"
	scopeEmail   = "email"

	extensionIssuer = "iss"
	extensionNonce  = "nonce"

	idTokenField = "id_token"
)

// IDTokenSigner signs OpenID Connect ID tokens.
type IDTokenSigner interface {
	IDToken(claims *jwthelper.IDTokenClaims) (string, error)
}

// ExtractTokenExtension records the issuer and the nonce of an authorization
// code request on the authorization code so that they are available when the
// code is exchanged for tokens. go-oauth2 copies the extension of the code to
// the access token, and to the tokens refreshed from it.
func ExtractTokenExtension(tgr *oauth2.TokenGenerateRequest, ti oauth2.ExtendableTokenInfo) {
	if tgr.Request == nil || tgr.Request.FormValue("response_type") != string(oauth2.Code) {
		return
	}
	extension := ti.GetExtension()
	if extension == nil {
		extension = make(map[string][]string)
		ti.SetExtension(extension)
	}
	extension.Set(extensionIssuer, httphelper.GetBaseURL(tgr.Request))
	if nonce := tgr.Request.FormValue(extensionNonce); nonce != "" {
		extension.Set(extensionNonce, nonce)
	}
}

// GetIDTokenExtensionFieldsHandler returns a handler which adds an ID token to
// a token response of a user who granted scope openid through an
// authorization code.
func GetIDTokenExtensionFieldsHandler(signer IDTokenSigner) server.ExtensionFieldsHandler {
	return func(ti oauth2.TokenInfo) map[string]interface{} {
		if ti.GetUserID() == "" || !hasScope(ti.GetScope(), scopeOpenID) {
			return nil
		}
		eti, ok := ti.(oauth2.ExtendableTokenInfo)
		if !ok {
			return nil
		}
		extension := eti.GetExtension()
		issuer := extension.Get(extensionIssuer)
		if issuer == "" {
			return nil
		}

		claims := &jwthelper.IDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   ti.GetUserID(),
				Audience:  jwt.ClaimStrings{ti.GetClientID()},
				IssuedAt:  jwt.NewNumericDate(ti.GetAccessCreateAt()),
				ExpiresAt: jwt.NewNumericDate(ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn())),
			},
			Nonce:           extension.Get(extensionNonce),
			AuthorizedParty: ti.GetClientID(),
		}
		if hasScope(ti.GetScope(), scopeEmail) {
			claims.Email = ti.GetUserID()
		}

		idToken, err := signer.IDToken(claims)
		if err != nil {
			slog.Error(
				"Unable to sign ID token",
				slog.String("error", err.Error()),
				slog.String("client_id", ti.GetClientID()),
			)
			return nil
		}
		return map[string]interface{}{idTokenField: idToken}
	}
}

// GetUserInfoHandler OpenID Connect userinfo endpoint
//
//	@summary	OpenID Connect userinfo endpoint
//	@Tags		OpenID
//	@Produce	json
//	@Param		Authorization	header		string	true	"Bearer access token"
//	@Success	200				{object}	UserInfo
//	@Router		/userinfo [get]
//	@Router		/userinfo [post]
func GetUserInfoHandler(srv *server.Server) func(c *gin.Context) {
	return func(c *gin.Context) {
		ti, err := srv.ValidationBearerToken(c.Request)
		if err != nil {
			slog.Warn(
				"Invalid access token in userinfo request",
				slog.String("error", err.Error()),
			)
			abortWithBearerError(c, http.StatusUnauthorized, "invalid_token")
			return
		}
		if ti.GetUserID() == "" || !hasScope(ti.GetScope(), scopeOpenID) {
			abortWithBearerError(c, http.StatusForbidden, "insufficient_scope")
			return
		}

		dbConn, ok := getDatabaseConnectionFromContext(c)
		if !ok {
			handleInternalError(c, nil, "Missing configuration for database")
			return
		}
		user, err := db.GetUser(dbConn, ti.GetUserID())
		if err != nil {
			handleInternalError(c, err, "Failed to get user")
			return
		}
		if user == nil || !user.IsEnabled {
			slog.Warn(
				"User of access token not found or disabled",
				slog.String("email", ti.GetUserID()),
			)
			abortWithBearerError(c, http.StatusUnauthorized, "invalid_token")
			return
		}

		userInfo := UserInfo{Subject: user.Email}
		if hasScope(ti.GetScope(), scopeEmail) {
			userInfo.Email = user.Email
			// only users with a confirmed email address are enabled
			userInfo.EmailVerified = true
		}
		if hasScope(ti.GetScope(), scopeProfile) {
			userInfo.Name = user.DisplayName
		}
		c.JSON(http.StatusOK, userInfo)
	}
}

// abortWithBearerError responds with an error of a bearer token request (RFC
// 6750 section 3).
func abortWithBearerError(c *gin.Context, statusCode int, errorCode string) {
	c.Header("WWW-Authenticate", `Bearer error="`+errorCode+`"`)
	c.AbortWithStatus(statusCode)
}

func hasScope(scope string, name string) bool {
	return slices.Contains(strings.Fields(scope), name)
}
