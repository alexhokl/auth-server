package db_test

import (
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/helper/database"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func getDBConnection() (*gorm.DB, sqlmock.Sqlmock) {
	mockDB, mock, _ := sqlmock.New()
	dialector := database.GetDatabaseDialectorFromConnection(mockDB)
	dbConn, _ := gorm.Open(dialector, &gorm.Config{})
	return dbConn, mock
}

// User Tests

func TestListUsers_Empty(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users"`)).
		WillReturnRows(sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}))

	users, err := db.ListUsers(dbConn)

	assert.NoError(t, err)
	assert.Empty(t, users)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListUsers_WithUsers(t *testing.T) {
	dbConn, mock := getDBConnection()

	userID := uuid.New()
	rows := sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}).
		AddRow("alex@test.com", []byte("hash"), "Alex", userID, true).
		AddRow("bob@test.com", []byte("hash2"), "Bob", uuid.New(), false)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users"`)).WillReturnRows(rows)
	// GORM preloads credentials first
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE "user_credentials"."user_email" IN ($1,$2)`)).
		WithArgs("alex@test.com", "bob@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email"}))
	// GORM preloads roles via user_roles join table
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_email" IN ($1,$2)`)).
		WithArgs("alex@test.com", "bob@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "role_name"}))

	users, err := db.ListUsers(dbConn)

	assert.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, "alex@test.com", users[0].Email)
	assert.Equal(t, "bob@test.com", users[1].Email)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUser_Found(t *testing.T) {
	dbConn, mock := getDBConnection()

	userID := uuid.New()
	rows := sqlmock.NewRows([]string{"email", "password_hash", "display_name", "web_authn_user_id", "is_enabled"}).
		AddRow("alex@test.com", []byte("hash"), "Alex", userID, true)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1`)).
		WithArgs("alex@test.com").
		WillReturnRows(rows)
	// GORM clause.Associations preloads all associations
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE "user_credentials"."user_email" = $1`)).
		WithArgs("alex@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_email"}))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_roles" WHERE "user_roles"."user_email" = $1`)).
		WithArgs("alex@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"user_email", "role_name"}))

	user, err := db.GetUser(dbConn, "alex@test.com")

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "alex@test.com", user.Email)
	assert.Equal(t, "Alex", user.DisplayName)
	assert.True(t, user.IsEnabled)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUser_NotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1`)).
		WithArgs("notfound@test.com").
		WillReturnError(gorm.ErrRecordNotFound)

	user, err := db.GetUser(dbConn, "notfound@test.com")

	assert.NoError(t, err)
	assert.Nil(t, user)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestHasUsers_True(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "users"`)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	hasUsers, err := db.HasUsers(dbConn)

	assert.NoError(t, err)
	assert.True(t, hasUsers)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestHasUsers_False(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "users"`)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	hasUsers, err := db.HasUsers(dbConn)

	assert.NoError(t, err)
	assert.False(t, hasUsers)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateUser_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	user := &db.User{
		Email:        "newuser@test.com",
		PasswordHash: []byte("hash"),
		DisplayName:  "New User",
		IsEnabled:    false,
	}

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "users"`)).
		WithArgs(user.Email, user.PasswordHash, user.DisplayName, user.IsEnabled).
		WillReturnRows(sqlmock.NewRows([]string{"web_authn_user_id"}).AddRow(uuid.New()))
	mock.ExpectCommit()

	err := db.CreateUser(dbConn, user)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// Client Tests

func TestGetClients_Empty(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients"`)).
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "is_public", "user_email"}))

	clients, err := db.GetClients(dbConn)

	assert.NoError(t, err)
	assert.Empty(t, clients)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetClients_WithClients(t *testing.T) {
	dbConn, mock := getDBConnection()

	rows := sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "is_public", "user_email"}).
		AddRow("cli1", "secret1", "http://localhost:8080", false, "alex@test.com").
		AddRow("cli2", "secret2", "http://localhost:9090", true, "bob@test.com")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients"`)).WillReturnRows(rows)

	clients, err := db.GetClients(dbConn)

	assert.NoError(t, err)
	assert.Len(t, clients, 2)
	assert.Equal(t, "cli1", clients[0].ClientID)
	assert.Equal(t, "cli2", clients[1].ClientID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetClient_Found(t *testing.T) {
	dbConn, mock := getDBConnection()

	rows := sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "is_public", "user_email"}).
		AddRow("cli1", "secret1", "http://localhost:8080", false, "alex@test.com")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1`)).
		WithArgs("cli1").
		WillReturnRows(rows)

	client, err := db.GetClient(dbConn, "cli1")

	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "cli1", client.ClientID)
	assert.Equal(t, "secret1", client.ClientSecret)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetClient_NotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1`)).
		WithArgs("notfound").
		WillReturnError(gorm.ErrRecordNotFound)

	client, err := db.GetClient(dbConn, "notfound")

	assert.NoError(t, err)
	assert.Nil(t, client)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateClient_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	client := &db.Client{
		ClientID:     "newclient",
		ClientSecret: "newsecret",
		RedirectURI:  "http://localhost:8080",
		IsPublic:     false,
		UserEmail:    "alex@test.com",
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "clients"`)).
		WithArgs(client.ClientID, client.ClientSecret, client.RedirectURI, client.IsPublic, client.UserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.CreateClient(dbConn, client)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// Credential Tests

func TestGetCredentials_Empty(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "public_key", "user_email", "friendly_name"}))

	credentials, err := db.GetCredentials(dbConn, "alex@test.com")

	assert.NoError(t, err)
	assert.Empty(t, credentials)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetCredentials_WithCredentials(t *testing.T) {
	dbConn, mock := getDBConnection()

	rows := sqlmock.NewRows([]string{"id", "public_key", "attestation_type", "user_present", "user_verified", "backup_eligible", "backup_state", "aaguid", "sign_count", "clone_warning", "attachment", "user_email", "friendly_name"}).
		AddRow([]byte("cred1"), []byte("pubkey1"), "direct", true, true, false, false, []byte("aaguid1"), 0, false, "cross-platform", "alex@test.com", "key 0").
		AddRow([]byte("cred2"), []byte("pubkey2"), "direct", true, true, false, false, []byte("aaguid2"), 0, false, "cross-platform", "alex@test.com", "key 1")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnRows(rows)

	credentials, err := db.GetCredentials(dbConn, "alex@test.com")

	assert.NoError(t, err)
	assert.Len(t, credentials, 2)
	assert.Equal(t, "key 0", credentials[0].FriendlyName)
	assert.Equal(t, "key 1", credentials[1].FriendlyName)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetCredentialNames(t *testing.T) {
	dbConn, mock := getDBConnection()

	rows := sqlmock.NewRows([]string{"id", "public_key", "attestation_type", "user_present", "user_verified", "backup_eligible", "backup_state", "aaguid", "sign_count", "clone_warning", "attachment", "user_email", "friendly_name"}).
		AddRow([]byte("cred1"), []byte("pubkey1"), "direct", true, true, false, false, []byte("aaguid1"), 0, false, "cross-platform", "alex@test.com", "key 0").
		AddRow([]byte("cred2"), []byte("pubkey2"), "direct", true, true, false, false, []byte("aaguid2"), 0, false, "cross-platform", "alex@test.com", "My YubiKey")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnRows(rows)

	names, err := db.GetCredentialNames(dbConn, "alex@test.com")

	assert.NoError(t, err)
	assert.Len(t, names, 2)
	assert.Contains(t, names, "key 0")
	assert.Contains(t, names, "My YubiKey")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// Role Tests

func TestCreateRole_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	role := &db.Role{Name: "admin"}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "roles"`)).
		WithArgs(role.Name).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.CreateRole(dbConn, role)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestHasRole_True(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "user_roles" WHERE user_email = $1 AND role_name = $2`)).
		WithArgs("alex@test.com", "admin").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	hasRole := db.HasRole(dbConn, "alex@test.com", "admin")

	assert.True(t, hasRole)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestHasRole_False(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "user_roles" WHERE user_email = $1 AND role_name = $2`)).
		WithArgs("alex@test.com", "admin").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	hasRole := db.HasRole(dbConn, "alex@test.com", "admin")

	assert.False(t, hasRole)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// Scope Tests

func TestListScopes_Empty(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "scopes"`)).
		WillReturnRows(sqlmock.NewRows([]string{"name"}))

	scopes, err := db.ListScopes(dbConn)

	assert.NoError(t, err)
	assert.Empty(t, scopes)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListScopes_WithScopes(t *testing.T) {
	dbConn, mock := getDBConnection()

	rows := sqlmock.NewRows([]string{"name"}).
		AddRow("openid").
		AddRow("profile").
		AddRow("email")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "scopes"`)).WillReturnRows(rows)

	scopes, err := db.ListScopes(dbConn)

	assert.NoError(t, err)
	assert.Len(t, scopes, 3)
	assert.Contains(t, scopes, "openid")
	assert.Contains(t, scopes, "profile")
	assert.Contains(t, scopes, "email")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIsScopeExist_True(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "scopes" WHERE name = $1`)).
		WithArgs("openid").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	exists, err := db.IsScopeExist(dbConn, "openid")

	assert.NoError(t, err)
	assert.True(t, exists)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIsScopeExist_False(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "scopes" WHERE name = $1`)).
		WithArgs("custom").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	exists, err := db.IsScopeExist(dbConn, "custom")

	assert.NoError(t, err)
	assert.False(t, exists)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// Confirmation Tests

func TestGetConfirmation_Found(t *testing.T) {
	dbConn, mock := getDBConnection()

	otp := "abc123"
	expiryTime := time.Now().Add(1 * time.Hour).Unix()

	rows := sqlmock.NewRows([]string{"user_email", "one_time_password", "expiry_time", "confirmed_time"}).
		AddRow("alex@test.com", otp, expiryTime, 0)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1`)).
		WithArgs(otp).
		WillReturnRows(rows)

	confirmation, err := db.GetConfirmation(dbConn, otp)

	assert.NoError(t, err)
	assert.NotNil(t, confirmation)
	assert.Equal(t, "alex@test.com", confirmation.UserEmail)
	assert.Equal(t, otp, confirmation.OneTimePassword)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetConfirmation_NotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1`)).
		WithArgs("invalid").
		WillReturnError(gorm.ErrRecordNotFound)

	confirmation, err := db.GetConfirmation(dbConn, "invalid")

	assert.NoError(t, err)
	assert.Nil(t, confirmation)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// OIDC Client Tests

func TestListOIDCClients_Empty(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients"`)).
		WillReturnRows(sqlmock.NewRows([]string{"name", "client_id", "client_secret", "redirect_uri", "button_name"}))

	clients, err := db.ListOIDCClients(dbConn)

	assert.NoError(t, err)
	assert.Empty(t, clients)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListOIDCClients_WithClients(t *testing.T) {
	dbConn, mock := getDBConnection()

	rows := sqlmock.NewRows([]string{"name", "client_id", "client_secret", "redirect_uri", "button_name"}).
		AddRow("google", "google-client-id", "google-secret", "http://localhost/callback", "Sign in with Google")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients"`)).WillReturnRows(rows)

	clients, err := db.ListOIDCClients(dbConn)

	assert.NoError(t, err)
	assert.Len(t, clients, 1)
	assert.Equal(t, "google", clients[0].Name)
	assert.Equal(t, "Sign in with Google", clients[0].ButtonName)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetOIDCClient_Found(t *testing.T) {
	dbConn, mock := getDBConnection()

	rows := sqlmock.NewRows([]string{"name", "client_id", "client_secret", "redirect_uri", "button_name"}).
		AddRow("google", "google-client-id", "google-secret", "http://localhost/callback", "Sign in with Google")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients" WHERE name = $1`)).
		WithArgs("google").
		WillReturnRows(rows)

	client, err := db.GetOIDCClient(dbConn, "google")

	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "google", client.Name)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetOIDCClient_NotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients" WHERE name = $1`)).
		WithArgs("notfound").
		WillReturnError(gorm.ErrRecordNotFound)

	client, err := db.GetOIDCClient(dbConn, "notfound")

	assert.NoError(t, err)
	assert.Nil(t, client)
	assert.NoError(t, mock.ExpectationsWereMet())
}
