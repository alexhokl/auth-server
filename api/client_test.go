package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

// CreateClient Tests

func TestCreateClient_MissingRequestBody_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/clients", CreateClient)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients", nil)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateClient_InvalidJSON_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/clients", CreateClient)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateClient_MissingClientID_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/clients", CreateClient)

	body := `{"client_secret": "secret", "redirect_uri": "http://localhost/callback", "user_email": "alex@test.com"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateClient_MissingClientSecret_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/clients", CreateClient)

	body := `{"client_id": "test-client", "redirect_uri": "http://localhost/callback", "user_email": "alex@test.com"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateClient_MissingRedirectUri_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/clients", CreateClient)

	body := `{"client_id": "test-client", "client_secret": "secret", "user_email": "alex@test.com"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateClient_MissingUserEmail_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/clients", CreateClient)

	body := `{"client_id": "test-client", "client_secret": "secret", "redirect_uri": "http://localhost/callback"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateClient_NoDatabaseConnection_ReturnsInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Don't set db in context
	router.POST("/clients", CreateClient)

	body := `{"client_id": "test-client", "client_secret": "secret", "redirect_uri": "http://localhost/callback", "user_email": "alex@test.com"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateClient_UserNotFound_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/clients", CreateClient)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("notfound@test.com", 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}))

	body := `{"client_id": "test-client", "client_secret": "secret", "redirect_uri": "http://localhost/callback", "user_email": "notfound@test.com"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateClient_ClientAlreadyExists_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/clients", CreateClient)

	// User exists
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("alex@test.com", 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}).
			AddRow("alex@test.com", []byte("hash"), "Alex", nil, true))
	// Preloads for user
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE "user_credentials"."user_email" = $1`)).
		WithArgs("alex@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "friendly_name"}))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_email" = $1`)).
		WithArgs("alex@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "role_name"}))

	// Client already exists
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("test-client", 1).
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "user_email", "is_public"}).
			AddRow("test-client", "existing-secret", "http://existing/callback", "alex@test.com", false))

	body := `{"client_id": "test-client", "client_secret": "secret", "redirect_uri": "http://localhost/callback", "user_email": "alex@test.com"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Client already exists", response["error"])
}

func TestCreateClient_Success_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/clients", CreateClient)

	// User exists
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("alex@test.com", 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}).
			AddRow("alex@test.com", []byte("hash"), "Alex", nil, true))
	// Preloads for user
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE "user_credentials"."user_email" = $1`)).
		WithArgs("alex@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email", "friendly_name"}))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_email" = $1`)).
		WithArgs("alex@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "role_name"}))

	// Client doesn't exist
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("new-client", 1).
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "user_email", "is_public"}))

	// Create client - GORM column order: client_id, client_secret, redirect_uri, is_public, user_email
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "clients" ("client_id","client_secret","redirect_uri","is_public","user_email") VALUES ($1,$2,$3,$4,$5)`)).
		WithArgs("new-client", "secret", "http://localhost/callback", false, "alex@test.com").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	body := `{"client_id": "new-client", "client_secret": "secret", "redirect_uri": "http://localhost/callback", "user_email": "alex@test.com"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// UpdateClient Tests

func TestUpdateClient_NoDatabaseConnection_ReturnsInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Don't set db in context
	router.PATCH("/clients/:client_id", UpdateClient)

	body := `{"client_secret": "newsecret"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPatch, "/clients/test-client", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateClient_DatabaseError_ReturnsNotFound(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/clients/:client_id", UpdateClient)

	// Return a database error (not ErrRecordNotFound which is caught by GetClient)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("nonexistent", 1).
		WillReturnError(gorm.ErrInvalidDB)

	body := `{"client_secret": "newsecret"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPatch, "/clients/nonexistent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Handler returns 404 for any database error when fetching client
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateClient_ClientNotFound_ReturnsNotFound(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/clients/:client_id", UpdateClient)

	// Return empty result (client not found)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("nonexistent", 1).
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "user_email", "is_public"}))

	body := `{"client_secret": "newsecret"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPatch, "/clients/nonexistent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateClient_InvalidJSON_ReturnsBadRequest(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/clients/:client_id", UpdateClient)

	// Client exists
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("test-client", 1).
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "user_email", "is_public"}).
			AddRow("test-client", "secret", "http://localhost/callback", "alex@test.com", false))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPatch, "/clients/test-client", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateClient_UpdateSecret_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/clients/:client_id", UpdateClient)

	// Client exists
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("test-client", 1).
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "user_email", "is_public"}).
			AddRow("test-client", "oldsecret", "http://localhost/callback", "alex@test.com", false))

	// Update client - GORM column order: client_secret, redirect_uri, is_public, user_email
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "clients" SET "client_secret"=$1,"redirect_uri"=$2,"is_public"=$3,"user_email"=$4 WHERE "client_id" = $5`)).
		WithArgs("newsecret", "http://localhost/callback", false, "alex@test.com", "test-client").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	body := `{"client_secret": "newsecret"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPatch, "/clients/test-client", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())

	var response ClientResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "test-client", response.ClientID)
	assert.Equal(t, "http://localhost/callback", response.RedirectUri)
	assert.Equal(t, "alex@test.com", response.UserEmail)
}

func TestUpdateClient_UpdateRedirectUri_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/clients/:client_id", UpdateClient)

	// Client exists
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("test-client", 1).
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "user_email", "is_public"}).
			AddRow("test-client", "secret", "http://old/callback", "alex@test.com", false))

	// Update client - GORM column order: client_secret, redirect_uri, is_public, user_email
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "clients" SET "client_secret"=$1,"redirect_uri"=$2,"is_public"=$3,"user_email"=$4 WHERE "client_id" = $5`)).
		WithArgs("secret", "http://new/callback", false, "alex@test.com", "test-client").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	body := `{"redirect_uri": "http://new/callback"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPatch, "/clients/test-client", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ClientResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "http://new/callback", response.RedirectUri)
}

func TestUpdateClient_UpdateUserEmail_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.PATCH("/clients/:client_id", UpdateClient)

	// Client exists
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("test-client", 1).
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "user_email", "is_public"}).
			AddRow("test-client", "secret", "http://localhost/callback", "old@test.com", false))

	// Update client - GORM column order: client_secret, redirect_uri, is_public, user_email
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "clients" SET "client_secret"=$1,"redirect_uri"=$2,"is_public"=$3,"user_email"=$4 WHERE "client_id" = $5`)).
		WithArgs("secret", "http://localhost/callback", false, "new@test.com", "test-client").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	body := `{"user_email": "new@test.com"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPatch, "/clients/test-client", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ClientResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "new@test.com", response.UserEmail)
}

// ListClients Tests

func TestListClients_NoDatabaseConnection_ReturnsInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Don't set db in context
	router.GET("/clients", ListClients)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/clients", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListClients_EmptyList_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/clients", ListClients)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients"`)).
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "user_email", "is_public"}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/clients", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var clients []ClientResponse
	err := json.Unmarshal(w.Body.Bytes(), &clients)
	assert.NoError(t, err)
	assert.Len(t, clients, 0)
}

func TestListClients_WithClients_ReturnsClientList(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/clients", ListClients)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients"`)).
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "user_email", "is_public"}).
			AddRow("client1", "secret1", "http://localhost:8080/callback", "alex@test.com", false).
			AddRow("client2", "secret2", "http://localhost:8081/callback", "bob@test.com", true))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/clients", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var clients []ClientResponse
	err := json.Unmarshal(w.Body.Bytes(), &clients)
	assert.NoError(t, err)
	assert.Len(t, clients, 2)
	assert.Equal(t, "client1", clients[0].ClientID)
	assert.Equal(t, "http://localhost:8080/callback", clients[0].RedirectUri)
	assert.Equal(t, "alex@test.com", clients[0].UserEmail)
	assert.Equal(t, "client2", clients[1].ClientID)
}

// ListClientScopes Tests

func TestListClientScopes_NoDatabaseConnection_ReturnsInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Don't set db in context
	router.GET("/clients/:client_id/scopes", ListClientScopes)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/clients/test-client/scopes", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListClientScopes_EmptyList_ReturnsOK(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/clients/:client_id/scopes", ListClientScopes)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "client_scopes" WHERE client_id = $1`)).
		WithArgs("test-client").
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "scope_name"}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/clients/test-client/scopes", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListClientScopes_WithScopes_ReturnsScopeList(t *testing.T) {
	router, _, mock := getTestRouter()
	router.GET("/clients/:client_id/scopes", ListClientScopes)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "client_scopes" WHERE client_id = $1`)).
		WithArgs("test-client").
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "scope_name"}).
			AddRow("test-client", "read").
			AddRow("test-client", "write"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/clients/test-client/scopes", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// CreateClientScope Tests

func TestCreateClientScope_MissingRequestBody_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/clients/:client_id/scopes", CreateClientScope)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients/test-client/scopes", nil)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateClientScope_InvalidJSON_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/clients/:client_id/scopes", CreateClientScope)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients/test-client/scopes", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateClientScope_MissingScopeName_ReturnsBadRequest(t *testing.T) {
	router, _, _ := getTestRouter()
	router.POST("/clients/:client_id/scopes", CreateClientScope)

	body := `{}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients/test-client/scopes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateClientScope_NoDatabaseConnection_ReturnsInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Don't set db in context
	router.POST("/clients/:client_id/scopes", CreateClientScope)

	body := `{"name": "read"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients/test-client/scopes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateClientScope_ScopeNotExists_ReturnsConflict(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/clients/:client_id/scopes", CreateClientScope)

	// Scope doesn't exist
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "scopes" WHERE name = $1`)).
		WithArgs("nonexistent").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	body := `{"name": "nonexistent"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients/test-client/scopes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Scope does not exist", response["error"])
}

func TestCreateClientScope_Success_ReturnsCreated(t *testing.T) {
	router, _, mock := getTestRouter()
	router.POST("/clients/:client_id/scopes", CreateClientScope)

	// Scope exists
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "scopes" WHERE name = $1`)).
		WithArgs("read").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Create client scope
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "client_scopes" ("client_id","scope_name") VALUES ($1,$2)`)).
		WithArgs("test-client", "read").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	body := `{"name": "read"}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/clients/test-client/scopes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// DeleteClientScope Tests

func TestDeleteClientScope_NoDatabaseConnection_ReturnsInternalError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Don't set db in context
	router.DELETE("/clients/:client_id/scopes/:scope", DeleteClientScope)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/clients/test-client/scopes/read", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteClientScope_Success_ReturnsNoContent(t *testing.T) {
	router, _, mock := getTestRouter()
	router.DELETE("/clients/:client_id/scopes/:scope", DeleteClientScope)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "client_scopes" WHERE client_id = $1 AND scope_name = $2`)).
		WithArgs("test-client", "read").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/clients/test-client/scopes/read", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ClientCreateRequest Tests

func TestClientCreateRequest_JSONBinding(t *testing.T) {
	jsonData := `{"client_id": "cli", "client_secret": "P@ssw0rd", "redirect_uri": "http://localhost:8080/callback", "user_email": "alex@test.com"}`

	var req ClientCreateRequest
	err := json.Unmarshal([]byte(jsonData), &req)

	assert.NoError(t, err)
	assert.Equal(t, "cli", req.ClientID)
	assert.Equal(t, "P@ssw0rd", req.ClientSecret)
	assert.Equal(t, "http://localhost:8080/callback", req.RedirectUri)
	assert.Equal(t, "alex@test.com", req.UserEmail)
}

func TestClientUpdateRequest_JSONBinding_PartialUpdate(t *testing.T) {
	jsonData := `{"client_secret": "newSecret"}`

	var req ClientUpdateRequest
	err := json.Unmarshal([]byte(jsonData), &req)

	assert.NoError(t, err)
	assert.NotNil(t, req.ClientSecret)
	assert.Equal(t, "newSecret", *req.ClientSecret)
	assert.Nil(t, req.RedirectUri)
	assert.Nil(t, req.UserEmail)
}

func TestClientResponse_JSONSerialization(t *testing.T) {
	response := ClientResponse{
		ClientID:    "cli",
		RedirectUri: "http://localhost:8080/callback",
		UserEmail:   "alex@test.com",
	}

	data, err := json.Marshal(response)
	assert.NoError(t, err)

	var decoded ClientResponse
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, response.ClientID, decoded.ClientID)
	assert.Equal(t, response.RedirectUri, decoded.RedirectUri)
	assert.Equal(t, response.UserEmail, decoded.UserEmail)
}

// Helper function to create JSON request body
func createJSONBody(data interface{}) *bytes.Buffer {
	body, _ := json.Marshal(data)
	return bytes.NewBuffer(body)
}
