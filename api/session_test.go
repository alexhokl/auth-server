package api

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	session "github.com/go-session/session/v3"
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

// mwInvalidSessionCookie is a session cookie which cannot be decoded and thus
// every attempt to start a session from it fails.
var mwInvalidSessionCookie = &http.Cookie{Name: "go_session_id", Value: "invalid"}

// mwRunWithInvalidSessionCookie runs the given function within a request which
// carries an invalid session cookie.
func mwRunWithInvalidSessionCookie(t *testing.T, fn func(c *gin.Context)) {
	t.Helper()

	router := gin.New()
	router.GET("/", fn)

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(mwInvalidSessionCookie)
	router.ServeHTTP(httptest.NewRecorder(), req)
}

func TestDeleteOIDCSession_DeletesOIDCSession(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		assert.NoError(t, setOIDCSession(c, "google", "state", "S256", "challenge", "verifier", "/authorize", false))
		assert.NoError(t, setEmailToSession(c, "alex@test.com"))

		assert.NoError(t, deleteOIDCSession(c, "google"))

		assert.False(t, isKeyExistInSession(c, sessionOIDCKey))
		assert.True(t, isKeyExistInSession(c, sessionEmailKey))
		_, _, _, _, _, _, err := getOIDCSession(c, "google")
		assert.Error(t, err)
	})
}

func TestDeleteOIDCSession_InvalidSessionCookie_ReturnsError(t *testing.T) {
	mwRunWithInvalidSessionCookie(t, func(c *gin.Context) {
		assert.Error(t, deleteOIDCSession(c, "google"))
	})
}

func TestUnsetAuthenticatedEmail_InvalidSessionCookie_ReturnsError(t *testing.T) {
	mwRunWithInvalidSessionCookie(t, func(c *gin.Context) {
		assert.Error(t, unsetAuthenticatedEmail(c))
	})
}

func TestSetValuesToSession_InvalidSessionCookie_ReturnsError(t *testing.T) {
	mwRunWithInvalidSessionCookie(t, func(c *gin.Context) {
		assert.Error(t, setValuesToSession(c, map[string]interface{}{
			"some_key": "some value",
		}))
	})
}

func TestSetWebAuthnSession_InvalidSessionCookie_ReturnsError(t *testing.T) {
	mwRunWithInvalidSessionCookie(t, func(c *gin.Context) {
		assert.Error(t, setWebAuthnSession(c, &webauthn.SessionData{Challenge: "some-challenge"}))
	})
}

func TestGetValueFromSession_InvalidSessionCookie_ReturnsFalse(t *testing.T) {
	mwRunWithInvalidSessionCookie(t, func(c *gin.Context) {
		value, ok := getValueFromSession(c, sessionEmailKey)

		assert.False(t, ok)
		assert.Nil(t, value)
		assert.Empty(t, getEmailFromSession(c))
		assert.False(t, isAuthenticated(c))
	})
}

func TestGetWebAuthnSession_NotAString_ReturnsError(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		assert.NoError(t, setValuesToSession(c, map[string]interface{}{
			sessionWebAuthnSessionKey: 123,
		}))

		stored, err := getWebAuthnSession(c)

		assert.Error(t, err)
		assert.Nil(t, stored)
		assert.Contains(t, err.Error(), "webauthn session is not a string")
	})
}

func TestGetOIDCSession_NotAString_ReturnsError(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		assert.NoError(t, setValuesToSession(c, map[string]interface{}{
			sessionOIDCKey: 123,
		}))

		_, _, _, _, _, _, err := getOIDCSession(c, "google")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is not a string")
	})
}

func TestGetAuthenticatedEmail_NotAuthenticated_ReturnsEmpty(t *testing.T) {
	runInSession(t, func(c *gin.Context) {
		assert.NoError(t, setEmailToSession(c, "user@test.com"))
		assert.NoError(t, setAuthenticationToSession(c, false))

		assert.Empty(t, getAuthenticatedEmailFromGinContext(c))
		assert.False(t, isAuthenticated(c))
	})
}

// The in-memory session store of go-session, which is used when no store is
// configured, garbage collects expired sessions every second in a goroutine
// which reads the expiry time of sessions without synchronisation with
// session updates. The race detector reports it whenever a garbage collection
// happens between the creation and an update of a session in a test. A store
// without garbage collection is used instead in tests.
func init() {
	session.InitManager(session.SetStore(&mwSessionStore{data: map[string]map[string]interface{}{}}))
}

// mwSessionStore is an in-memory session store without garbage collection.
type mwSessionStore struct {
	mu   sync.Mutex
	data map[string]map[string]interface{}
}

func (s *mwSessionStore) load(sid string) (map[string]interface{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	values, ok := s.data[sid]
	return maps.Clone(values), ok
}

func (s *mwSessionStore) save(sid string, values map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[sid] = maps.Clone(values)
}

func (s *mwSessionStore) newStore(ctx context.Context, sid string) *mwSession {
	values, ok := s.load(sid)
	if !ok {
		values = map[string]interface{}{}
	}
	return &mwSession{managerStore: s, ctx: ctx, sid: sid, values: values}
}

func (s *mwSessionStore) Check(_ context.Context, sid string) (bool, error) {
	_, ok := s.load(sid)
	return ok, nil
}

func (s *mwSessionStore) Create(ctx context.Context, sid string, _ int64) (session.Store, error) {
	return &mwSession{managerStore: s, ctx: ctx, sid: sid, values: map[string]interface{}{}}, nil
}

func (s *mwSessionStore) Update(ctx context.Context, sid string, _ int64) (session.Store, error) {
	return s.newStore(ctx, sid), nil
}

func (s *mwSessionStore) Delete(_ context.Context, sid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, sid)
	return nil
}

func (s *mwSessionStore) Refresh(ctx context.Context, oldsid, sid string, _ int64) (session.Store, error) {
	values, _ := s.load(oldsid)
	s.save(sid, values)
	_ = s.Delete(ctx, oldsid)
	return s.newStore(ctx, sid), nil
}

func (s *mwSessionStore) Close() error {
	return nil
}

type mwSession struct {
	mu           sync.RWMutex
	managerStore *mwSessionStore
	ctx          context.Context
	sid          string
	values       map[string]interface{}
}

func (s *mwSession) Context() context.Context {
	return s.ctx
}

func (s *mwSession) SessionID() string {
	return s.sid
}

func (s *mwSession) Set(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = value
}

func (s *mwSession) Get(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.values[key]
	return value, ok
}

func (s *mwSession) Delete(key string) interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	value := s.values[key]
	delete(s.values, key)
	return value
}

func (s *mwSession) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.managerStore.save(s.sid, s.values)
	return nil
}

func (s *mwSession) Flush() error {
	s.mu.Lock()
	s.values = map[string]interface{}{}
	s.mu.Unlock()
	return s.Save()
}
