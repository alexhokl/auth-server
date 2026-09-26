package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
)

// runInSession runs the given function within a request which carries the
// cookie of an established session.
//
// Note that a session has to be established by a preceding request. Calling
// session.Start without a session cookie creates a session which is not
// persisted until it is saved, and the session ID of that unsaved session is
// added to the request. Any read before the first write would therefore be
// made against a different session than the subsequent writes.
func runInSession(t *testing.T, fn func(c *gin.Context)) *httptest.ResponseRecorder {
	t.Helper()

	router := gin.New()
	router.GET("/establish", func(c *gin.Context) {
		assert.NoError(t, setValuesToSession(c, map[string]interface{}{
			"established": true,
		}))
	})
	router.GET("/", func(c *gin.Context) {
		fn(c)
	})

	establish := httptest.NewRecorder()
	establishReq, _ := http.NewRequest(http.MethodGet, "/establish", nil)
	router.ServeHTTP(establish, establishReq)

	cookies := establish.Result().Cookies()
	assert.NotEmpty(t, cookies, "no session cookie was issued")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	router.ServeHTTP(w, req)

	return w
}

func TestSetAndGetValueFromSession(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		assert.NoError(t, setValuesToSession(c, map[string]interface{}{
			"some_key": "some value",
		}))

		value, ok := getValueFromSession(c, "some_key")
		assert.True(t, ok)
		assert.Equal(t, "some value", value)
	})
}

func TestGetValueFromSession_MissingKey(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		value, ok := getValueFromSession(c, "missing_key")
		assert.False(t, ok)
		assert.Nil(t, value)
	})
}

func TestIsKeyExistInSession(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		assert.False(t, isKeyExistInSession(c, sessionEmailKey))

		assert.NoError(t, setEmailToSession(c, "user@test.com"))

		assert.True(t, isKeyExistInSession(c, sessionEmailKey))
	})
}

func TestSetEmailToSession(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		assert.NoError(t, setEmailToSession(c, "user@test.com"))

		assert.Equal(t, "user@test.com", getEmailFromSession(c))
	})
}

// Authentication cannot be set before the mail address as the mail address
// identifies the user being authenticated.
func TestSetAuthenticationToSession_RequiresEmail(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		err := setAuthenticationToSession(c, true)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "email is not set in session")
	})
}

func TestIsAuthenticated(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		assert.False(t, isAuthenticated(c))

		assert.NoError(t, setEmailToSession(c, "user@test.com"))
		assert.False(t, isAuthenticated(c))

		assert.NoError(t, setAuthenticationToSession(c, true))
		assert.True(t, isAuthenticated(c))
	})
}

func TestGetAuthenticatedEmail(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		assert.Empty(t, getAuthenticatedEmailFromGinContext(c))

		assert.NoError(t, setEmailToSession(c, "user@test.com"))
		// not authenticated yet and thus no mail address is returned
		assert.Empty(t, getAuthenticatedEmailFromGinContext(c))

		assert.NoError(t, setAuthenticationToSession(c, true))
		assert.Equal(t, "user@test.com", getAuthenticatedEmailFromGinContext(c))
	})
}

func TestUnsetAuthenticatedEmail(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		assert.NoError(t, setEmailToSession(c, "user@test.com"))
		assert.NoError(t, setAuthenticationToSession(c, true))
		assert.Equal(t, "user@test.com", getAuthenticatedEmailFromGinContext(c))

		assert.NoError(t, unsetAuthenticatedEmail(c))

		assert.Empty(t, getEmailFromSession(c))
		assert.False(t, isAuthenticated(c))
		assert.False(t, isKeyExistInSession(c, sessionIsAuthenticatedKey))
	})
}

func TestSetAndGetWebAuthnSession(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		sessionData := &webauthn.SessionData{
			Challenge: "some-challenge",
			UserID:    []byte("some-user-id"),
		}

		assert.NoError(t, setWebAuthnSession(c, sessionData))

		stored, err := getWebAuthnSession(c)
		assert.NoError(t, err)
		assert.Equal(t, "some-challenge", stored.Challenge)
		assert.Equal(t, []byte("some-user-id"), stored.UserID)
	})
}

func TestGetWebAuthnSession_NotSet(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		stored, err := getWebAuthnSession(c)

		assert.Error(t, err)
		assert.Nil(t, stored)
		assert.Contains(t, err.Error(), "webauthn session is not set")
	})
}

func TestSetAndGetOIDCSession(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		assert.NoError(t, setOIDCSession(
			c,
			"google",
			"some-state",
			"S256",
			"some-challenge",
			"some-verifier",
			"https://auth.example.com/callback",
			true,
		))

		state, method, challenge, verifier, redirectURI, isSignUp, err := getOIDCSession(c, "google")

		assert.NoError(t, err)
		assert.Equal(t, "some-state", state)
		assert.Equal(t, "S256", method)
		assert.Equal(t, "some-challenge", challenge)
		assert.Equal(t, "some-verifier", verifier)
		assert.Equal(t, "https://auth.example.com/callback", redirectURI)
		assert.True(t, isSignUp)
	})
}

func TestGetOIDCSession_NotSet(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		_, _, _, _, _, _, err := getOIDCSession(c, "google")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is not set")
	})
}
