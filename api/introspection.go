package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/alexhokl/helper/httphelper"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/server"
)

const (
	tokenTypeHintAccessToken  = "access_token"
	tokenTypeHintRefreshToken = "refresh_token"
)

// GetIntrospectionHandler OAuth 2.0 token introspection endpoint
//
//	@Summary		OAuth 2.0 token introspection endpoint (RFC 7662)
//	@Description	Tells whether an access token or a refresh token is active; a token is inactive if it is unknown, has expired, or was issued to a user who has since been disabled or deleted. The caller authenticates as a confidential client with client_secret_basic or client_secret_post.
//	@Tags			OAuth
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Param			token			formData	string	true	"Token to introspect"
//	@Param			token_type_hint	formData	string	false	"access_token or refresh_token"
//	@Success		200				{object}	IntrospectionResponse
//	@Failure		400
//	@Failure		401
//	@Router			/introspect [post]
func GetIntrospectionHandler(srv *server.Server) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")

		// client_secret_post reads the client from the parsed form
		if err := c.Request.ParseForm(); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": oauth2errors.ErrInvalidRequest.Error()})
			return
		}
		if !isConfidentialClient(c.Request.Context(), srv, c.Request) {
			c.Header("WWW-Authenticate", `Basic realm="introspect"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": oauth2errors.ErrInvalidClient.Error()})
			return
		}

		token := c.PostForm("token")
		if token == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": oauth2errors.ErrInvalidRequest.Error()})
			return
		}

		response, err := introspect(c.Request.Context(), srv, token, c.PostForm("token_type_hint"))
		if err != nil {
			slog.Error(
				"Unable to introspect token",
				slog.String("error", err.Error()),
			)
		}
		if response == nil {
			c.JSON(http.StatusOK, IntrospectionResponse{Active: false})
			return
		}
		response.Issuer = httphelper.GetBaseURL(c.Request)
		c.JSON(http.StatusOK, response)
	}
}

// isConfidentialClient returns true if the request is authenticated by a
// client holding a secret (RFC 7662 section 2.1).
func isConfidentialClient(ctx context.Context, srv *server.Server, r *http.Request) bool {
	clientID, clientSecret, err := HandleClientInfoInTokenRequest(r)
	if err != nil || clientID == "" || clientSecret == "" {
		return false
	}
	client, err := srv.Manager.GetClient(ctx, clientID)
	if err != nil || client == nil || client.IsPublic() || client.GetSecret() == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(client.GetSecret()), []byte(clientSecret)) == 1
}

// introspect returns the description of an active token, trying the type of
// hint first, or nil if the token is not active. An error is returned only if
// a token could not be looked up for a reason other than being invalid.
func introspect(ctx context.Context, srv *server.Server, token string, hint string) (*IntrospectionResponse, error) {
	lookups := []func(context.Context, *server.Server, string) (*IntrospectionResponse, error){
		introspectAccessToken,
		introspectRefreshToken,
	}
	if hint == tokenTypeHintRefreshToken {
		lookups[0], lookups[1] = lookups[1], lookups[0]
	}
	var lookupErr error
	for _, lookup := range lookups {
		response, err := lookup(ctx, srv, token)
		if response != nil {
			return response, nil
		}
		if err != nil && !isInvalidTokenError(err) {
			lookupErr = err
		}
	}
	return nil, lookupErr
}

func introspectAccessToken(ctx context.Context, srv *server.Server, token string) (*IntrospectionResponse, error) {
	ti, err := srv.Manager.LoadAccessToken(ctx, token)
	if err != nil || ti == nil {
		return nil, err
	}
	return newIntrospectionResponse(ti, "Bearer", ti.GetAccessCreateAt(), ti.GetAccessExpiresIn()), nil
}

func introspectRefreshToken(ctx context.Context, srv *server.Server, token string) (*IntrospectionResponse, error) {
	ti, err := srv.Manager.LoadRefreshToken(ctx, token)
	if err != nil || ti == nil {
		return nil, err
	}
	return newIntrospectionResponse(ti, tokenTypeHintRefreshToken, ti.GetRefreshCreateAt(), ti.GetRefreshExpiresIn()), nil
}

func newIntrospectionResponse(ti oauth2.TokenInfo, tokenType string, issuedAt time.Time, expiresIn time.Duration) *IntrospectionResponse {
	response := &IntrospectionResponse{
		Active:    true,
		Scope:     ti.GetScope(),
		ClientID:  ti.GetClientID(),
		Username:  ti.GetUserID(),
		Subject:   ti.GetUserID(),
		TokenType: tokenType,
		IssuedAt:  issuedAt.Unix(),
		Audience:  ti.GetClientID(),
	}
	// a token without an expiry never expires
	if expiresIn != 0 {
		response.ExpiresAt = issuedAt.Add(expiresIn).Unix()
	}
	return response
}

func isInvalidTokenError(err error) bool {
	return errors.Is(err, oauth2errors.ErrInvalidAccessToken) ||
		errors.Is(err, oauth2errors.ErrInvalidRefreshToken) ||
		errors.Is(err, oauth2errors.ErrExpiredAccessToken) ||
		errors.Is(err, oauth2errors.ErrExpiredRefreshToken)
}
