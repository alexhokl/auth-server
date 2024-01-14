package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alexhokl/auth-server/server"
	"github.com/alexhokl/helper/database"
	"github.com/gin-gonic/gin"
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

func TestSwaggerJson(t *testing.T) {
	router, _ := getRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/swagger/doc.json", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func getRouter() (*gin.Engine, sqlmock.Sqlmock) {
	mockDB, mock, _ := sqlmock.New()
	dialector := database.GetDatabaseDialectorFromConnection(mockDB)
	router, err := server.GetRouter(dialector, nil, "", "", "", "", false, nil, nil, true, 3600, "", "user@test.com", "Test User", "Confirming your registration", "test.com", "Your password has been changed", "Password reset requested", false, "auth-server")
	if err != nil {
		panic(err)
	}
	return router, mock
}
