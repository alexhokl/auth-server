package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexhokl/auth-server/server"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/manage"
	oauthserver "github.com/go-oauth2/oauth2/v4/server"
	"github.com/stretchr/testify/assert"
)

// func TestLoginPage(t *testing.T) {
// 	router := getRouter()
// 	w := httptest.NewRecorder()
// 	req, _ := http.NewRequest(http.MethodGet, "/signin", nil)
// 	router.ServeHTTP(w, req)
//
// 	assert.Equal(t, http.StatusOK, w.Code)
// 	// assert.Equal(t, "", w.Body.String())
// }
//
func TestSignUp(t *testing.T) {
	router := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signup", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(
		t,
		"{\"error\":\"invalid request\"}",
		w.Body.String(),
	)
}

func TestSignIn(t *testing.T) {
	router := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signin", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	// assert.Equal(t, "", w.Body.String())
}

func TestSignOut(t *testing.T) {
	router := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/signout", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "", w.Body.String())
}

func TestClientCreate(t *testing.T) {
	router := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "", w.Body.String())
}

func TestClientPatch(t *testing.T) {
	router := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPatch, "/clients/web", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "", w.Body.String())
}

func TestClientList(t *testing.T) {
	router := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/clients", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "", w.Body.String())
}

func TestSwaggerJson(t *testing.T) {
	router := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/swagger/doc.json", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func getRouter() *gin.Engine {
	manager := manage.NewDefaultManager()
	srv := oauthserver.NewDefaultServer(manager)
	return server.GetRouter(srv)
}
