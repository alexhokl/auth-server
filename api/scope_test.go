package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// CreateScope Tests

func TestCreateScope_MissingRequestBody_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/scopes", CreateScope)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/scopes", nil)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateScope_InvalidJSON_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/scopes", CreateScope)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/scopes", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateScope_MissingScopeName_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/scopes", CreateScope)

	body := `{}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/scopes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateScope_NoDatabaseConnection_ReturnsInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Don't set db in context
	router.POST("/scopes", CreateScope)

	body := `{"name": "read"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/scopes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateScope_ScopeAlreadyExists_ReturnsConflict(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/scopes", CreateScope)

	// Scope already exists
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "scopes" WHERE name = $1`)).
		WithArgs("read").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	body := `{"name": "read"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/scopes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Scope already exists", response["error"])
}

func TestCreateScope_Success_ReturnsCreated(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/scopes", CreateScope)

	// Scope doesn't exist
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "scopes" WHERE name = $1`)).
		WithArgs("newscope").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Create scope
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "scopes" ("name") VALUES ($1)`)).
		WithArgs("newscope").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	body := `{"name": "newscope"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/scopes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateScope_DatabaseError_ReturnsInternalError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/scopes", CreateScope)

	// Database error when checking if scope exists
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "scopes" WHERE name = $1`)).
		WithArgs("read").
		WillReturnError(sqlmock.ErrCancelled)

	body := `{"name": "read"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/scopes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// DeleteScope Tests

func TestDeleteScope_NoDatabaseConnection_ReturnsInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Don't set db in context
	router.DELETE("/scopes/:scope", DeleteScope)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/scopes/read", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteScope_ScopeInUse_ReturnsConflict(t *testing.T) {
	router, _, mock := getTestRouter()
	router.DELETE("/scopes/:scope", DeleteScope)

	// Scope is in use
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "client_scopes" WHERE scope_name = $1`)).
		WithArgs("read").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/scopes/read", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Scope is in use", response["error"])
}

func TestDeleteScope_Success_ReturnsNoContent(t *testing.T) {
	router, _, mock := getTestRouter()
	router.DELETE("/scopes/:scope", DeleteScope)

	// Scope is not in use
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "client_scopes" WHERE scope_name = $1`)).
		WithArgs("read").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Delete scope
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "scopes" WHERE name = $1`)).
		WithArgs("read").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/scopes/read", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteScope_DatabaseErrorCheckingUsage_ReturnsInternalError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.DELETE("/scopes/:scope", DeleteScope)

	// Database error when checking if scope is in use
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "client_scopes" WHERE scope_name = $1`)).
		WithArgs("read").
		WillReturnError(sqlmock.ErrCancelled)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/scopes/read", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteScope_DatabaseErrorDeleting_ReturnsInternalError(t *testing.T) {
	router, _, mock := getTestRouter()
	router.DELETE("/scopes/:scope", DeleteScope)

	// Scope is not in use
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "client_scopes" WHERE scope_name = $1`)).
		WithArgs("read").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// Database error when deleting
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "scopes" WHERE name = $1`)).
		WithArgs("read").
		WillReturnError(sqlmock.ErrCancelled)
	mock.ExpectRollback()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/scopes/read", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
