package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alexhokl/auth-server/server"
	"github.com/alexhokl/helper/database"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

//	func TestLoginPage(t *testing.T) {
//		router := getRouter()
//		w := httptest.NewRecorder()
//		req, _ := http.NewRequest(http.MethodGet, "/signin", nil)
//		router.ServeHTTP(w, req)
//
//		assert.Equal(t, http.StatusOK, w.Code)
//		// assert.Equal(t, "", w.Body.String())
//	}
func TestSignUp(t *testing.T) {
	router, _ := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signup", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	// assert.Equal(
	// 	t,
	// 	"{\"error\":\"invalid request\"}",
	// 	w.Body.String(),
	// )
}

func TestSignIn(t *testing.T) {
	router, _ := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signin", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	// assert.Equal(t, "", w.Body.String())
}

func TestSignOut(t *testing.T) {
	router, _ := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signout", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "", w.Body.String())
}

func TestClientCreate(t *testing.T) {
	router, _ := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	// assert.Equal(t, "", w.Body.String())
}

func TestClientPatch(t *testing.T) {
	router, dbMock := getRouter()
	dbMock.ExpectQuery("SELECT (.+) FROM \"clients\"").WillReturnRows(sqlmock.NewRows([]string{"id", "secret", "redirect_uri", "is_public", "user_email"}))
	dbMock.ExpectExec("UPDATE \"clients\" SET (.+) WHERE \"clients\".\"id\" = (.+)").WillReturnResult(sqlmock.NewResult(1, 1))
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPatch, "/clients/web", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	// assert.Equal(t, "", w.Body.String())
}

func TestClientList(t *testing.T) {
	router, dbMock := getRouter()
	dbMock.ExpectQuery("SELECT (.+) FROM \"clients\"").WillReturnRows(sqlmock.NewRows([]string{"id", "secret", "redirect_uri", "is_public", "user_email"}))
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/clients", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	// assert.Equal(t, "", w.Body.String())
}

func TestUserAdministrationRoutes(t *testing.T) {
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/users"},
		{http.MethodGet, "/users/alex@test.com"},
		{http.MethodPatch, "/users/alex@test.com"},
		{http.MethodDelete, "/users/alex@test.com"},
		{http.MethodPost, "/users/alex@test.com/roles"},
		{http.MethodDelete, "/users/alex@test.com/roles/admin"},
	}
	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			router, _ := getRouter()
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(route.method, route.path, nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusForbidden, w.Code)
		})
	}
}

func TestUserInfoWithoutAccessToken(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		router, _ := getRouter()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(method, "/userinfo", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
	}
}

func TestIntrospectionWithoutClientAuthentication(t *testing.T) {
	router, _ := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/introspect", strings.NewReader("token=abc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestOIDCRoutes(t *testing.T) {
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/signin/google/start"},
		{http.MethodGet, "/signin/google/callback"},
		// Apple posts the callback as a form
		{http.MethodPost, "/signin/apple/callback"},
	}
	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			disabledRouter, _ := getRouterWithOIDC(false)
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(route.method, route.path, nil)
			disabledRouter.ServeHTTP(w, req)
			assert.Equal(t, http.StatusNotFound, w.Code)

			// without an OIDC session or a client, the request is rejected
			// by the handler rather than the router
			enabledRouter, _ := getRouterWithOIDC(true)
			w = httptest.NewRecorder()
			req, _ = http.NewRequest(route.method, route.path, nil)
			enabledRouter.ServeHTTP(w, req)
			assert.Equal(t, http.StatusInternalServerError, w.Code)
		})
	}
}

func TestPasskeyRoutes(t *testing.T) {
	paths := []string{
		"/fido/signin/passkey/challenge",
		"/fido/signin/passkey",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			router, _ := getRouter()
			w := httptest.NewRecorder()
			// without a JSON content type, the request is rejected by the
			// handler rather than the router
			req, _ := http.NewRequest(http.MethodPost, path, nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestSwaggerJson(t *testing.T) {
	router, _ := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/swagger/doc.json", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetRouter_InvalidTrustedProxy_ReturnsError(t *testing.T) {
	mockDB, _, _ := sqlmock.New()
	dialector := database.GetDatabaseDialectorFromConnection(mockDB)

	_, err := server.GetRouter(dialector, nil, nil, nil, nil, server.RouterConfig{
		TrustedProxies: []string{"not-an-ip"},
	})

	assert.Error(t, err)
}

func getRouter() (*gin.Engine, sqlmock.Sqlmock) {
	return getRouterWithOIDC(false)
}

func getRouterWithOIDC(enableOIDC bool) (*gin.Engine, sqlmock.Sqlmock) {
	mockDB, mock, _ := sqlmock.New()
	dialector := database.GetDatabaseDialectorFromConnection(mockDB)
	router, err := server.GetRouter(
		dialector,
		nil,
		nil,
		nil,
		nil,
		server.RouterConfig{
			EnableFrontendEndpoints:   true,
			EnableOIDC:                enableOIDC,
			ExpirationPeriod:          3600,
			Domain:                    "test.com",
			SessionCookieName:         "auth-server",
			KeyID:                     "test-key-id",
			TrustedProxies:            []string{"127.0.0.1"},
			SignInMaxFailuresPerEmail: 5,
			SignInMaxFailuresPerIP:    20,
			SignInFailureWindow:       time.Minute,
			Mail: server.MailConfig{
				From:                   "user@test.com",
				FromName:               "Test User",
				ConfirmationSubject:    "Confirming your registration",
				PasswordChangedSubject: "Your password has been changed",
				PasswordResetSubject:   "Password reset requested",
			},
		},
	)
	if err != nil {
		panic(err)
	}
	return router, mock
}
