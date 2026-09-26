package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alexhokl/helper/database"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func getTestOpenIDConfiguration(t *testing.T, scopes []string) (*httptest.ResponseRecorder, OpenIDConfiguration) {
	t.Helper()

	dbConn, mock := getTestDBConnection()

	rows := sqlmock.NewRows([]string{"name"})
	for _, s := range scopes {
		rows = rows.AddRow(s)
	}
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "scopes"`)).WillReturnRows(rows)

	router := gin.New()
	router.GET(
		"/.well-known/openid-configuration",
		func(c *gin.Context) {
			c.Set("db", dbConn)
			c.Next()
		},
		GetOpenIDConfiguration,
	)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(
		http.MethodGet,
		"http://auth.example.com/.well-known/openid-configuration",
		nil,
	)
	router.ServeHTTP(w, req)

	var config OpenIDConfiguration
	if w.Code == http.StatusOK {
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &config))
	}

	return w, config
}

func TestGetOpenIDConfiguration_EndpointsAreDerivedFromIssuer(t *testing.T) {
	w, config := getTestOpenIDConfiguration(t, []string{"openid"})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://auth.example.com", config.Issuer)
	assert.Equal(t, "http://auth.example.com/authorize", config.AuthorizationEndpoint)
	assert.Equal(t, "http://auth.example.com/token", config.TokenEndpoint)
	assert.Equal(
		t,
		"http://auth.example.com/.well-known/openid-configuration/jwks",
		config.JwksUri,
	)
}

func TestGetOpenIDConfiguration_ContainsSupportedValues(t *testing.T) {
	_, config := getTestOpenIDConfiguration(t, []string{"openid", "profile"})

	assert.Equal(t, []string{"openid", "profile"}, config.ScopesSupported)
	assert.Equal(t, getResponseTypes(), config.ResponseTypesSupported)
	assert.Equal(t, getGrantTypes(), config.GrantTypesSupported)
	assert.Equal(
		t,
		getTokenEndpointSupportedAuthMethods(),
		config.TokenEndpointAuthMethodsSupported,
	)
	assert.Equal(
		t,
		getCodeChallengeMethodsSupported(),
		config.CodeChallengeMethodsSupported,
	)
}

func TestGetOpenIDConfiguration_WithoutDatabaseConnection(t *testing.T) {
	router := gin.New()
	router.GET("/.well-known/openid-configuration", GetOpenIDConfiguration)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(
		http.MethodGet,
		"http://auth.example.com/.well-known/openid-configuration",
		nil,
	)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// WithDatabaseConnection Tests

func TestWithDatabaseConnection_MiddlewareConnectsAndInjects(t *testing.T) {
	mockDB, _, err := sqlmock.New()
	assert.NoError(t, err)
	defer mockDB.Close()

	dialector := database.GetDatabaseDialectorFromConnection(mockDB)

	var dbConn *gorm.DB
	var ok bool

	router := gin.New()
	router.GET("/", WithDatabaseConnection(dialector), func(c *gin.Context) {
		dbConn, ok = getDatabaseConnectionFromContext(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, ok)
	assert.NotNil(t, dbConn)
}
