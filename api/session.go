package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/alexhokl/helper/jsonhelper"
	"github.com/gin-gonic/gin"
	session "github.com/go-session/session/v3"
	"github.com/go-webauthn/webauthn/webauthn"
)

type oidcSession struct {
	State                   string `json:"state"`
	PKCECodeChallengeMethod string `json:"pkce_code_challenge_method"`
	PKCECodeChallenge       string `json:"pkce_code_challenge"`
	PKCECodeVerifier        string `json:"pkce_code_verifier"`
	RedirectURI             string `json:"redirect_uri"`
	IsSignUp                bool   `json:"is_sign_up"`
}

const sessionEmailKey = "email"
const sessionIsAuthenticatedKey = "is_authenticated"
const sessionWebAuthnSessionKey = "webauthn_session"
const sessionRedirectURLKey = "redirect_uri"
const sessionOIDCKey = "oidc"

func getEmailFromSession(c *gin.Context) string {
	return getEmailFromSessionFromRequest(c.Writer, c.Request)
}

func getEmailFromSessionFromRequest(w http.ResponseWriter, r *http.Request) string {
	email, ok := getValueFromSessionFromRequest(w, r, sessionEmailKey)
	if !ok {
		return ""
	}
	return email.(string)
}

func getAuthenticatedEmailFromGinContext(c *gin.Context) string {
	return getAuthenticatedEmail(c.Writer, c.Request)
}

func getAuthenticatedEmail(w http.ResponseWriter, r *http.Request) string {
	emailFromSession := getEmailFromSessionFromRequest(w, r)
	if emailFromSession == "" {
		return ""
	}
	authenticatedValue, ok := getValueFromSessionFromRequest(w, r, sessionIsAuthenticatedKey)
	if !ok {
		return ""
	}
	authenticated := authenticatedValue.(bool)
	if !authenticated {
		return ""
	}
	return emailFromSession
}

func isAuthenticated(c *gin.Context) bool {
	emailFromSession := getEmailFromSession(c)
	if emailFromSession == "" {
		return false
	}
	authenticated, ok := getValueFromSession(c, sessionIsAuthenticatedKey)
	if !ok {
		return false
	}
	return authenticated.(bool)
}

func setAuthenticationToSession(c *gin.Context, isAuthenticated bool) error {
	if !isKeyExistInSession(c, sessionEmailKey) {
		return fmt.Errorf("email is not set in session")
	}
	return setValuesToSession(c, map[string]interface{}{
		sessionIsAuthenticatedKey: isAuthenticated,
	})
}

func setEmailToSession(c *gin.Context, email string) error {
	return setValuesToSession(c, map[string]interface{}{
		sessionEmailKey: email,
	})
}

func unsetAuthenticatedEmail(c *gin.Context) error {
	store, err := getSessionStoreFromRequest(c.Writer, c.Request)
	if err != nil {
		return err
	}
	store.Delete(sessionEmailKey)
	store.Delete(sessionIsAuthenticatedKey)
	if err := store.Save(); err != nil {
		return err
	}
	return nil
}

func setWebAuthnSession(c *gin.Context, webAuthnSession *webauthn.SessionData) error {
	json, err := jsonhelper.GetJSONString(webAuthnSession)
	if err != nil {
		return err
	}
	return setValuesToSession(c, map[string]interface{}{
		sessionWebAuthnSessionKey: json,
	})
}

func getWebAuthnSession(c *gin.Context) (*webauthn.SessionData, error) {
	webAuthnSessionValue, ok := getValueFromSession(c, sessionWebAuthnSessionKey)
	if !ok {
		return nil, fmt.Errorf("webauthn session is not set")
	}
	sessionValueString, ok := webAuthnSessionValue.(string)
	if !ok {
		return nil, fmt.Errorf("webauthn session is not a string")
	}
	var session webauthn.SessionData
	jsonhelper.ParseJSONString(sessionValueString, &session)
	return &session, nil
}

func setOIDCSession(c *gin.Context, _ string, state string, pkceCodeChallengeMethod string, pkceCodeChallenge string, pkceCodeVerifier string, redirectURI string, isSignUp bool) error {
	oidcSession := &oidcSession{
		State:                   state,
		PKCECodeChallengeMethod: pkceCodeChallengeMethod,
		PKCECodeChallenge:       pkceCodeChallenge,
		PKCECodeVerifier:        pkceCodeVerifier,
		RedirectURI:             redirectURI,
		IsSignUp:                isSignUp,
	}
	json, err := jsonhelper.GetJSONString(oidcSession)
	if err != nil {
		return err
	}
	return setValuesToSession(c, map[string]interface{}{
		sessionOIDCKey: json,
	})
}

func getOIDCSession(c *gin.Context, _ string) (state string, pkceCodeChallengeMethod string, pkceCodeChallenge string, pkceCodeVerifier string, redirectURI string, isSignUp bool, err error) {
	oidcSessionValue, ok := getValueFromSession(c, sessionOIDCKey)
	if !ok {
		err = fmt.Errorf("session [%s] is not set", sessionOIDCKey)
		return
	}
	sessionValueString, ok := oidcSessionValue.(string)
	if !ok {
		err = fmt.Errorf("session [%s] is not a string", sessionOIDCKey)
		return
	}
	var session oidcSession
	jsonhelper.ParseJSONString(sessionValueString, &session)
	state = session.State
	pkceCodeChallengeMethod = session.PKCECodeChallengeMethod
	pkceCodeChallenge = session.PKCECodeChallenge
	pkceCodeVerifier = session.PKCECodeVerifier
	redirectURI = session.RedirectURI
	isSignUp = session.IsSignUp
	return
}

func deleteOIDCSession(c *gin.Context, oidcName string) error {
	store, err := getSessionStoreFromRequest(c.Writer, c.Request)
	if err != nil {
		return err
	}
	store.Delete(fmt.Sprintf("oidc_%s", oidcName))
	if err := store.Save(); err != nil {
		return err
	}
	return nil
}

func setValuesToSession(c *gin.Context, keyValues map[string]interface{}) error {
	store, err := getSessionStoreFromRequest(c.Writer, c.Request)
	if err != nil {
		return err
	}
	for key, value := range keyValues {
		store.Set(key, value)
	}
	if err := store.Save(); err != nil {
		return err
	}
	return nil
}

func getValueFromSession(c *gin.Context, key string) (interface{}, bool) {
	return getValueFromSessionFromRequest(c.Writer, c.Request, key)
}

func getValueFromSessionFromRequest(w http.ResponseWriter, r *http.Request, key string) (interface{}, bool) {
	store, err := getSessionStoreFromRequest(w, r)
	if err != nil {
		return nil, false
	}
	return store.Get(key)
}

func isKeyExistInSession(c *gin.Context, key string) bool {
	_, ok := getValueFromSession(c, key)
	return ok
}

func getSessionStoreFromRequest(w http.ResponseWriter, r *http.Request) (session.Store, error) {
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		slog.Error(
			"failed to get session store",
			slog.String("error", err.Error()),
		)
	}
	return store, err
}
