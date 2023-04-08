package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	session "github.com/go-session/session/v3"
	"golang.org/x/exp/slog"
)

const sessionEmailKey = "email"
const sessionIsAuthenticatedKey = "is_authenticated"

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
	store, _ := getSessionStoreFromRequest(c.Writer, c.Request)
	return setToSession(store, sessionIsAuthenticatedKey, isAuthenticated)
}


func setEmailToSession(c *gin.Context, email string) error {
	store, err := getSessionStoreFromRequest(c.Writer, c.Request)
	if err != nil {
		return err
	}
	return setToSession(store, sessionEmailKey, email)
}

func setToSession(store session.Store, key string, value interface{}) error {
	store.Set(key, value)
	if err := store.Save(); err != nil {
		return err
	}
	return nil
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
