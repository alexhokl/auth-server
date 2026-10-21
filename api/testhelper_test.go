package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/resendlabs/resend-go"
	"github.com/stretchr/testify/assert"
)

const establishSessionPath = "/__establish_session"

// serveInSession establishes a session holding sessionValues and then serves
// req with the cookie of that session.
func serveInSession(t *testing.T, router *gin.Engine, sessionValues map[string]interface{}, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	router.GET(establishSessionPath, func(c *gin.Context) {
		values := map[string]interface{}{"established": true}
		for key, value := range sessionValues {
			values[key] = value
		}
		assert.NoError(t, setValuesToSession(c, values))
	})

	establish := httptest.NewRecorder()
	establishReq, _ := http.NewRequest(http.MethodGet, establishSessionPath, nil)
	router.ServeHTTP(establish, establishReq)

	cookies := establish.Result().Cookies()
	assert.NotEmpty(t, cookies, "no session cookie was issued")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// authenticatedSession returns session values of a signed in user.
func authenticatedSession(email string) map[string]interface{} {
	return map[string]interface{}{
		sessionEmailKey:           email,
		sessionIsAuthenticatedKey: true,
		sessionAuthenticatedAtKey: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// expectActiveUser expects the check of a session against its user by
// db.IsIssuedForActiveUser, and returns the user with the given state.
func expectActiveUser(mock sqlmock.Sqlmock, email string, isEnabled bool, revokedAt *time.Time) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs(email, 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "is_enabled", "created_at", "revoked_at"}).
			AddRow(email, isEnabled, time.Now().Add(-time.Hour), revokedAt))
}

type testMailServer struct {
	mu       sync.Mutex
	requests []resend.SendEmailRequest
}

func (s *testMailServer) Requests() []resend.SendEmailRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]resend.SendEmailRequest{}, s.requests...)
}

// useTestMailServer makes emails to be sent to a local server which responds
// with the given status code.
func useTestMailServer(t *testing.T, statusCode int) *testMailServer {
	t.Helper()

	mailServer := &testMailServer{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req resend.SendEmailRequest
		_ = json.Unmarshal(body, &req)
		mailServer.mu.Lock()
		mailServer.requests = append(mailServer.requests, req)
		mailServer.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			_, _ = w.Write([]byte(`{"id":"test-email-id"}`))
			return
		}
		_, _ = w.Write([]byte(`{"statusCode":500,"name":"internal_server_error","message":"failed"}`))
	}))
	t.Cleanup(server.Close)

	original := newMailClient
	newMailClient = func(apiKey string) *resend.Client {
		client := original(apiKey)
		baseURL, _ := url.Parse(server.URL + "/")
		client.BaseURL = baseURL
		return client
	}
	t.Cleanup(func() { newMailClient = original })

	return mailServer
}
