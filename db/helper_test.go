package db_test

import (
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/helper/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
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

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("alex@test.com", 1).
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

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("notfound@test.com", 1).
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
		WithArgs(user.Email, user.PasswordHash, user.DisplayName, user.IsEnabled, sqlmock.AnyArg(), nil).
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

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("cli1", 1).
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

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("notfound", 1).
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

	hasRole, err := db.HasRole(dbConn, "alex@test.com", "admin")

	assert.NoError(t, err)
	assert.True(t, hasRole)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestHasRole_False(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "user_roles" WHERE user_email = $1 AND role_name = $2`)).
		WithArgs("alex@test.com", "admin").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	hasRole, err := db.HasRole(dbConn, "alex@test.com", "admin")

	assert.NoError(t, err)
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

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1 AND purpose = $2 ORDER BY "user_confirmations"."user_email" LIMIT $3`)).
		WithArgs(otp, db.ConfirmationPurposeSignUp, 1).
		WillReturnRows(rows)

	confirmation, err := db.GetConfirmation(dbConn, otp, db.ConfirmationPurposeSignUp)

	assert.NoError(t, err)
	assert.NotNil(t, confirmation)
	assert.Equal(t, "alex@test.com", confirmation.UserEmail)
	assert.Equal(t, otp, confirmation.OneTimePassword)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetConfirmation_NotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1 AND purpose = $2 ORDER BY "user_confirmations"."user_email" LIMIT $3`)).
		WithArgs("invalid", db.ConfirmationPurposeSignUp, 1).
		WillReturnError(gorm.ErrRecordNotFound)

	confirmation, err := db.GetConfirmation(dbConn, "invalid", db.ConfirmationPurposeSignUp)

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

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients" WHERE name = $1 ORDER BY "oidc_clients"."name" LIMIT $2`)).
		WithArgs("google", 1).
		WillReturnRows(rows)

	client, err := db.GetOIDCClient(dbConn, "google")

	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "google", client.Name)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetOIDCClient_NotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients" WHERE name = $1 ORDER BY "oidc_clients"."name" LIMIT $2`)).
		WithArgs("notfound", 1).
		WillReturnError(gorm.ErrRecordNotFound)

	client, err := db.GetOIDCClient(dbConn, "notfound")

	assert.NoError(t, err)
	assert.Nil(t, client)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ChangePassword Tests

func TestChangePassword_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	newPasswordHash := []byte("newhash")

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "password_hash"=$1 WHERE email = $2`)).
		WithArgs(newPasswordHash, "alex@test.com").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.ChangePassword(dbConn, "alex@test.com", newPasswordHash)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// CreateCredential Tests

func TestCreateCredential_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	credential := &db.UserCredential{
		ID:              []byte("cred123"),
		PublicKey:       []byte("pubkey"),
		AttestationType: "direct",
		UserPresent:     true,
		UserVerified:    true,
		BackupEligible:  false,
		BackupState:     false,
		AAGUID:          []byte("aaguid"),
		SignCount:       0,
		CloneWarning:    false,
		Attachment:      "cross-platform",
		UserEmail:       "alex@test.com",
		FriendlyName:    "key 0",
	}

	// Note: Transport is (NULL) in the query and doesn't count as a placeholder argument
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "user_credentials"`)).
		WithArgs(
			credential.ID,
			credential.PublicKey,
			credential.AttestationType,
			// Transport is (NULL) - no placeholder
			credential.UserPresent,
			credential.UserVerified,
			credential.BackupEligible,
			credential.BackupState,
			credential.AAGUID,
			credential.SignCount,
			credential.CloneWarning,
			credential.Attachment,
			credential.UserEmail,
			credential.FriendlyName,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.CreateCredential(dbConn, credential)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// DeleteCredential Tests

func TestDeleteCredential_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	credID := []byte("cred123")

	// First, search for the credential
	rows := sqlmock.NewRows([]string{"id", "public_key", "attestation_type", "user_present", "user_verified", "backup_eligible", "backup_state", "aaguid", "sign_count", "clone_warning", "attachment", "user_email", "friendly_name"}).
		AddRow(credID, []byte("pubkey"), "direct", true, true, false, false, []byte("aaguid"), 0, false, "cross-platform", "alex@test.com", "key 0")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1 AND id = $2 ORDER BY "user_credentials"."id" LIMIT $3`)).
		WithArgs("alex@test.com", credID, 1).
		WillReturnRows(rows)

	// Then, delete the credential
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "user_credentials" WHERE "user_credentials"."id" = $1`)).
		WithArgs(credID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.DeleteCredential(dbConn, "alex@test.com", credID)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteCredential_NotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	credID := []byte("notfound")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1 AND id = $2 ORDER BY "user_credentials"."id" LIMIT $3`)).
		WithArgs("alex@test.com", credID, 1).
		WillReturnError(gorm.ErrRecordNotFound)

	err := db.DeleteCredential(dbConn, "alex@test.com", credID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential not found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// UpdateCredential Tests

func TestUpdateCredential_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	credID := []byte("cred123")

	// First, search for the credential
	rows := sqlmock.NewRows([]string{"id", "public_key", "attestation_type", "user_present", "user_verified", "backup_eligible", "backup_state", "aaguid", "sign_count", "clone_warning", "attachment", "user_email", "friendly_name"}).
		AddRow(credID, []byte("pubkey"), "direct", true, true, false, false, []byte("aaguid"), 0, false, "cross-platform", "alex@test.com", "key 0")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1 AND id = $2 ORDER BY "user_credentials"."id" LIMIT $3`)).
		WithArgs("alex@test.com", credID, 1).
		WillReturnRows(rows)

	// Then, update the credential - use AnyArg() for all arguments since GORM generates all fields
	// Note: transport is (NULL) in the query and doesn't count as a placeholder argument
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_credentials" SET`)).
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // public_key
			sqlmock.AnyArg(), // attestation_type
			// transport is (NULL) - no placeholder
			sqlmock.AnyArg(), // user_present
			sqlmock.AnyArg(), // user_verified
			sqlmock.AnyArg(), // backup_eligible
			sqlmock.AnyArg(), // backup_state
			sqlmock.AnyArg(), // aaguid
			sqlmock.AnyArg(), // sign_count
			sqlmock.AnyArg(), // clone_warning
			sqlmock.AnyArg(), // attachment
			sqlmock.AnyArg(), // user_email
			sqlmock.AnyArg(), // friendly_name
			sqlmock.AnyArg(), // WHERE id = ?
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.UpdateCredential(dbConn, "alex@test.com", credID, "My YubiKey")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateCredential_NotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	credID := []byte("notfound")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1 AND id = $2 ORDER BY "user_credentials"."id" LIMIT $3`)).
		WithArgs("alex@test.com", credID, 1).
		WillReturnError(gorm.ErrRecordNotFound)

	err := db.UpdateCredential(dbConn, "alex@test.com", credID, "New Name")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential not found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// GetCredentialDescriptors Tests

func TestGetCredentialDescriptors_Empty(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "public_key", "user_email"}))

	descriptors, err := db.GetCredentialDescriptors(dbConn, "alex@test.com")

	assert.NoError(t, err)
	assert.Empty(t, descriptors)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetCredentialDescriptors_WithCredentials(t *testing.T) {
	dbConn, mock := getDBConnection()

	rows := sqlmock.NewRows([]string{"id", "public_key", "attestation_type", "user_present", "user_verified", "backup_eligible", "backup_state", "aaguid", "sign_count", "clone_warning", "attachment", "user_email", "friendly_name"}).
		AddRow([]byte("cred1"), []byte("pubkey1"), "direct", true, true, false, false, []byte("aaguid1"), 0, false, "cross-platform", "alex@test.com", "key 0").
		AddRow([]byte("cred2"), []byte("pubkey2"), "direct", true, true, false, false, []byte("aaguid2"), 0, false, "cross-platform", "alex@test.com", "key 1")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnRows(rows)

	descriptors, err := db.GetCredentialDescriptors(dbConn, "alex@test.com")

	assert.NoError(t, err)
	assert.Len(t, descriptors, 2)
	assert.Equal(t, []byte("cred1"), []byte(descriptors[0].CredentialID))
	assert.Equal(t, []byte("cred2"), []byte(descriptors[1].CredentialID))
	assert.NoError(t, mock.ExpectationsWereMet())
}

// UpdateClient Tests

func TestUpdateClient_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	client := &db.Client{
		ClientID:     "cli1",
		ClientSecret: "updatedsecret",
		RedirectURI:  "http://localhost:9090",
		IsPublic:     true,
		UserEmail:    "alex@test.com",
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "clients" SET`)).
		WithArgs(
			client.ClientSecret,
			client.RedirectURI,
			client.IsPublic,
			client.UserEmail,
			client.ClientID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.UpdateClient(dbConn, client)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// CreateScope Tests

func TestCreateScope_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "scopes"`)).
		WithArgs("custom_scope").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.CreateScope(dbConn, "custom_scope")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// DeleteScope Tests

func TestDeleteScope_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "scopes" WHERE name = $1`)).
		WithArgs("custom_scope").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.DeleteScope(dbConn, "custom_scope")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// IsScopeInUse Tests

func TestIsScopeInUse_True(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "client_scopes" WHERE scope_name = $1`)).
		WithArgs("openid").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	inUse, err := db.IsScopeInUse(dbConn, "openid")

	assert.NoError(t, err)
	assert.True(t, inUse)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIsScopeInUse_False(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "client_scopes" WHERE scope_name = $1`)).
		WithArgs("unused").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	inUse, err := db.IsScopeInUse(dbConn, "unused")

	assert.NoError(t, err)
	assert.False(t, inUse)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// CreateClientScope Tests

func TestCreateClientScope_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "client_scopes"`)).
		WithArgs("cli1", "openid").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.CreateClientScope(dbConn, "cli1", "openid")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ListClientScopes Tests

func TestListClientScopes_Empty(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "client_scopes" WHERE client_id = $1`)).
		WithArgs("cli1").
		WillReturnRows(sqlmock.NewRows([]string{"client_id", "scope_name"}))

	scopes, err := db.ListClientScopes(dbConn, "cli1")

	assert.NoError(t, err)
	assert.Empty(t, scopes)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListClientScopes_WithScopes(t *testing.T) {
	dbConn, mock := getDBConnection()

	rows := sqlmock.NewRows([]string{"client_id", "scope_name"}).
		AddRow("cli1", "openid").
		AddRow("cli1", "profile").
		AddRow("cli1", "email")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "client_scopes" WHERE client_id = $1`)).
		WithArgs("cli1").
		WillReturnRows(rows)

	scopes, err := db.ListClientScopes(dbConn, "cli1")

	assert.NoError(t, err)
	assert.Len(t, scopes, 3)
	assert.Contains(t, scopes, "openid")
	assert.Contains(t, scopes, "profile")
	assert.Contains(t, scopes, "email")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// DeleteClientScope Tests

func TestDeleteClientScope_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "client_scopes" WHERE client_id = $1 AND scope_name = $2`)).
		WithArgs("cli1", "openid").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.DeleteClientScope(dbConn, "cli1", "openid")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// CreateConfirmation Tests

func TestCreateConfirmation_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	confirmation := &db.UserConfirmation{
		UserEmail:       "alex@test.com",
		OneTimePassword: "abc123",
		ExpiryTime:      time.Now().Add(1 * time.Hour).Unix(),
		ConfirmedTime:   0,
		Purpose:         db.ConfirmationPurposeResetPassword,
	}

	mock.ExpectBegin()
	// replaces the existing confirmation of the user
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "user_confirmations" ("user_email","one_time_password","expiry_time","confirmed_time","purpose") VALUES ($1,$2,$3,$4,$5) ON CONFLICT ("user_email") DO UPDATE SET "one_time_password"="excluded"."one_time_password","expiry_time"="excluded"."expiry_time","confirmed_time"="excluded"."confirmed_time","purpose"="excluded"."purpose"`)).
		WithArgs(confirmation.UserEmail, confirmation.OneTimePassword, confirmation.ExpiryTime, confirmation.ConfirmedTime, confirmation.Purpose).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.CreateConfirmation(dbConn, confirmation)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ConfirmUser Tests

func TestConfirmUser_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	confirmation := &db.UserConfirmation{
		UserEmail:       "alex@test.com",
		OneTimePassword: "abc123",
		Purpose:         db.ConfirmationPurposeSignUp,
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_confirmations" SET "confirmed_time"=$1 WHERE one_time_password = $2 AND purpose = $3 AND confirmed_time = $4`)).
		WithArgs(sqlmock.AnyArg(), confirmation.OneTimePassword, db.ConfirmationPurposeSignUp, 0).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "is_enabled"=$1 WHERE email = $2`)).
		WithArgs(true, confirmation.UserEmail).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.ConfirmUser(dbConn, confirmation)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConfirmUser_ConfirmationUsed(t *testing.T) {
	dbConn, mock := getDBConnection()

	confirmation := &db.UserConfirmation{
		UserEmail:       "alex@test.com",
		OneTimePassword: "abc123",
		Purpose:         db.ConfirmationPurposeSignUp,
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_confirmations" SET "confirmed_time"=$1 WHERE one_time_password = $2 AND purpose = $3 AND confirmed_time = $4`)).
		WithArgs(sqlmock.AnyArg(), confirmation.OneTimePassword, db.ConfirmationPurposeSignUp, 0).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err := db.ConfirmUser(dbConn, confirmation)

	assert.ErrorIs(t, err, db.ErrConfirmationUsed)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ResetPassword Tests

func getResetPasswordConfirmation() *db.UserConfirmation {
	return &db.UserConfirmation{
		UserEmail:       "alex@test.com",
		OneTimePassword: "abc123",
		Purpose:         db.ConfirmationPurposeResetPassword,
	}
}

func expectUseResetPasswordConfirmation(mock sqlmock.Sqlmock, rowsAffected int64) {
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_confirmations" SET "confirmed_time"=$1 WHERE one_time_password = $2 AND purpose = $3 AND confirmed_time = $4`)).
		WithArgs(sqlmock.AnyArg(), "abc123", db.ConfirmationPurposeResetPassword, 0).
		WillReturnResult(sqlmock.NewResult(0, rowsAffected))
}

func TestResetPassword_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	expectUseResetPasswordConfirmation(mock, 1)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "password_hash"=$1 WHERE email = $2`)).
		WithArgs([]byte("newhash"), "alex@test.com").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.ResetPassword(dbConn, getResetPasswordConfirmation(), []byte("newhash"))

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestResetPassword_ConfirmationUsed(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	expectUseResetPasswordConfirmation(mock, 0)
	mock.ExpectRollback()

	err := db.ResetPassword(dbConn, getResetPasswordConfirmation(), []byte("newhash"))

	assert.ErrorIs(t, err, db.ErrConfirmationUsed)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestResetPassword_ConfirmationUpdateDatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_confirmations"`)).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.ResetPassword(dbConn, getResetPasswordConfirmation(), []byte("newhash"))

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestResetPassword_PasswordUpdateDatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	expectUseResetPasswordConfirmation(mock, 1)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "password_hash"=$1 WHERE email = $2`)).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.ResetPassword(dbConn, getResetPasswordConfirmation(), []byte("newhash"))

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// ExpireAllConfirmation Tests

func TestExpireAllConfirmation_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_confirmations" SET "confirmed_time"=$1 WHERE user_email = $2 AND confirmed_time = $3`)).
		WithArgs(sqlmock.AnyArg(), "alex@test.com", int64(0)).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()

	err := db.ExpireAllConfirmation(dbConn, "alex@test.com")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// CreateOIDCClient Tests

func TestCreateOIDCClient_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	client := &db.OidcClient{
		Name:         "okta",
		ClientID:     "okta-client-id",
		ClientSecret: "okta-secret",
		RedirectURI:  "http://localhost/callback",
		ButtonName:   "Sign in with Okta",
		Issuer:       "https://acme.okta.com/oauth2/default",
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "oidc_clients"`)).
		WithArgs(client.Name, client.ClientID, client.ClientSecret, client.RedirectURI, client.ButtonName, client.Issuer, client.TeamID, client.KeyID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.CreateOIDCClient(dbConn, client)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// UpdateOIDCClient Tests

func TestUpdateOIDCClient_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	client := &db.OidcClient{
		Name:         "google",
		ClientID:     "new-google-client-id",
		ClientSecret: "new-google-secret",
		RedirectURI:  "http://localhost/newcallback",
		ButtonName:   "Login with Google",
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "oidc_clients" SET`)).
		WithArgs(
			client.ClientID,
			client.ClientSecret,
			client.RedirectURI,
			client.ButtonName,
			client.Name, // WHERE name = ?
			client.Name, // AND "name" = ?
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.UpdateOIDCClient(dbConn, client)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// DeleteOIDCClient Tests

func TestDeleteOIDCClient_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "oidc_clients" WHERE name = $1`)).
		WithArgs("google").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.DeleteOIDCClient(dbConn, "google")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// Database error tests

var errDatabase = errors.New("database error")

func TestListUsers_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users"`)).
		WillReturnError(errDatabase)

	users, err := db.ListUsers(dbConn)

	assert.ErrorIs(t, err, errDatabase)
	assert.Nil(t, users)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListUsers_RecordNotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users"`)).
		WillReturnError(gorm.ErrRecordNotFound)

	users, err := db.ListUsers(dbConn)

	assert.NoError(t, err)
	assert.Empty(t, users)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUser_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("alex@test.com", 1).
		WillReturnError(errDatabase)

	user, err := db.GetUser(dbConn, "alex@test.com")

	assert.ErrorIs(t, err, errDatabase)
	assert.Nil(t, user)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestHasUsers_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "users"`)).
		WillReturnError(errDatabase)

	hasUsers, err := db.HasUsers(dbConn)

	assert.ErrorIs(t, err, errDatabase)
	assert.False(t, hasUsers)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateUser_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	user := &db.User{
		Email:        "newuser@test.com",
		PasswordHash: []byte("hash"),
		DisplayName:  "New User",
	}

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`INSERT INTO "users"`)).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.CreateUser(dbConn, user)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateCredential_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	credential := &db.UserCredential{
		ID:           []byte("cred123"),
		PublicKey:    []byte("pubkey"),
		UserEmail:    "alex@test.com",
		FriendlyName: "key 0",
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "user_credentials"`)).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.CreateCredential(dbConn, credential)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetCredentialDescriptors_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnError(errDatabase)

	descriptors, err := db.GetCredentialDescriptors(dbConn, "alex@test.com")

	assert.ErrorIs(t, err, errDatabase)
	assert.Nil(t, descriptors)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetCredentialDescriptors_RecordNotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnError(gorm.ErrRecordNotFound)

	descriptors, err := db.GetCredentialDescriptors(dbConn, "alex@test.com")

	assert.NoError(t, err)
	assert.Nil(t, descriptors)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetCredentials_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnError(errDatabase)

	credentials, err := db.GetCredentials(dbConn, "alex@test.com")

	assert.ErrorIs(t, err, errDatabase)
	assert.Nil(t, credentials)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetCredentials_RecordNotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnError(gorm.ErrRecordNotFound)

	credentials, err := db.GetCredentials(dbConn, "alex@test.com")

	assert.NoError(t, err)
	assert.Nil(t, credentials)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetCredentialNames_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnError(errDatabase)

	names, err := db.GetCredentialNames(dbConn, "alex@test.com")

	assert.ErrorIs(t, err, errDatabase)
	assert.Nil(t, names)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetCredentialNames_RecordNotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnError(gorm.ErrRecordNotFound)

	names, err := db.GetCredentialNames(dbConn, "alex@test.com")

	assert.NoError(t, err)
	assert.Nil(t, names)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteCredential_SearchDatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	credID := []byte("cred123")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1 AND id = $2 ORDER BY "user_credentials"."id" LIMIT $3`)).
		WithArgs("alex@test.com", credID, 1).
		WillReturnError(errDatabase)

	err := db.DeleteCredential(dbConn, "alex@test.com", credID)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteCredential_DeleteDatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	credID := []byte("cred123")

	rows := sqlmock.NewRows([]string{"id", "public_key", "attestation_type", "user_present", "user_verified", "backup_eligible", "backup_state", "aaguid", "sign_count", "clone_warning", "attachment", "user_email", "friendly_name"}).
		AddRow(credID, []byte("pubkey"), "direct", true, true, false, false, []byte("aaguid"), 0, false, "cross-platform", "alex@test.com", "key 0")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1 AND id = $2 ORDER BY "user_credentials"."id" LIMIT $3`)).
		WithArgs("alex@test.com", credID, 1).
		WillReturnRows(rows)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "user_credentials" WHERE "user_credentials"."id" = $1`)).
		WithArgs(credID).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.DeleteCredential(dbConn, "alex@test.com", credID)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateCredential_SearchDatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	credID := []byte("cred123")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1 AND id = $2 ORDER BY "user_credentials"."id" LIMIT $3`)).
		WithArgs("alex@test.com", credID, 1).
		WillReturnError(errDatabase)

	err := db.UpdateCredential(dbConn, "alex@test.com", credID, "New Name")

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateCredential_UpdateDatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	credID := []byte("cred123")

	rows := sqlmock.NewRows([]string{"id", "public_key", "attestation_type", "user_present", "user_verified", "backup_eligible", "backup_state", "aaguid", "sign_count", "clone_warning", "attachment", "user_email", "friendly_name"}).
		AddRow(credID, []byte("pubkey"), "direct", true, true, false, false, []byte("aaguid"), 0, false, "cross-platform", "alex@test.com", "key 0")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1 AND id = $2 ORDER BY "user_credentials"."id" LIMIT $3`)).
		WithArgs("alex@test.com", credID, 1).
		WillReturnRows(rows)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_credentials" SET`)).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.UpdateCredential(dbConn, "alex@test.com", credID, "New Name")

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateCredential_DuplicatedName_ReturnsErrDuplicatedKey(t *testing.T) {
	dbConn, mock := getDBConnection()

	credID := []byte("cred123")

	rows := sqlmock.NewRows([]string{"id", "public_key", "attestation_type", "user_present", "user_verified", "backup_eligible", "backup_state", "aaguid", "sign_count", "clone_warning", "attachment", "user_email", "friendly_name"}).
		AddRow(credID, []byte("pubkey"), "direct", true, true, false, false, []byte("aaguid"), 0, false, "cross-platform", "alex@test.com", "key 0")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_credentials" WHERE user_email = $1 AND id = $2 ORDER BY "user_credentials"."id" LIMIT $3`)).
		WithArgs("alex@test.com", credID, 1).
		WillReturnRows(rows)
	mock.ExpectBegin()
	// unique_violation of PostgreSQL
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_credentials" SET`)).
		WillReturnError(&pgconn.PgError{Code: "23505"})
	mock.ExpectRollback()

	err := db.UpdateCredential(dbConn, "alex@test.com", credID, "key 1")

	assert.ErrorIs(t, err, gorm.ErrDuplicatedKey)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateRole_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "roles"`)).
		WithArgs("admin").
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.CreateRole(dbConn, &db.Role{Name: "admin"})

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestHasRole_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "user_roles" WHERE user_email = $1 AND role_name = $2`)).
		WithArgs("alex@test.com", "admin").
		WillReturnError(errDatabase)

	hasRole, err := db.HasRole(dbConn, "alex@test.com", "admin")

	assert.ErrorIs(t, err, errDatabase)
	assert.False(t, hasRole)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetClients_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients"`)).
		WillReturnError(errDatabase)

	clients, err := db.GetClients(dbConn)

	assert.ErrorIs(t, err, errDatabase)
	assert.Nil(t, clients)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetClients_RecordNotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients"`)).
		WillReturnError(gorm.ErrRecordNotFound)

	clients, err := db.GetClients(dbConn)

	assert.NoError(t, err)
	assert.Nil(t, clients)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetClient_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("cli1", 1).
		WillReturnError(errDatabase)

	client, err := db.GetClient(dbConn, "cli1")

	assert.ErrorIs(t, err, errDatabase)
	assert.Nil(t, client)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateClient_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	client := &db.Client{
		ClientID:     "newclient",
		ClientSecret: "newsecret",
		RedirectURI:  "http://localhost:8080",
		UserEmail:    "alex@test.com",
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "clients"`)).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.CreateClient(dbConn, client)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateClient_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	client := &db.Client{
		ClientID:     "cli1",
		ClientSecret: "updatedsecret",
		RedirectURI:  "http://localhost:9090",
		UserEmail:    "alex@test.com",
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "clients" SET`)).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.UpdateClient(dbConn, client)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExpireAllConfirmation_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_confirmations" SET "confirmed_time"=$1 WHERE user_email = $2 AND confirmed_time = $3`)).
		WithArgs(sqlmock.AnyArg(), "alex@test.com", int64(0)).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.ExpireAllConfirmation(dbConn, "alex@test.com")

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateConfirmation_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	confirmation := &db.UserConfirmation{
		UserEmail:       "alex@test.com",
		OneTimePassword: "abc123",
		ExpiryTime:      time.Now().Add(1 * time.Hour).Unix(),
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "user_confirmations"`)).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.CreateConfirmation(dbConn, confirmation)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetConfirmation_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "user_confirmations" WHERE one_time_password = $1 AND purpose = $2 ORDER BY "user_confirmations"."user_email" LIMIT $3`)).
		WithArgs("abc123", db.ConfirmationPurposeSignUp, 1).
		WillReturnError(errDatabase)

	confirmation, err := db.GetConfirmation(dbConn, "abc123", db.ConfirmationPurposeSignUp)

	assert.ErrorIs(t, err, errDatabase)
	assert.Nil(t, confirmation)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConfirmUser_ConfirmationUpdateDatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	confirmation := &db.UserConfirmation{
		UserEmail:       "alex@test.com",
		OneTimePassword: "abc123",
		Purpose:         db.ConfirmationPurposeSignUp,
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_confirmations" SET "confirmed_time"=$1 WHERE one_time_password = $2 AND purpose = $3 AND confirmed_time = $4`)).
		WithArgs(sqlmock.AnyArg(), confirmation.OneTimePassword, db.ConfirmationPurposeSignUp, 0).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.ConfirmUser(dbConn, confirmation)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConfirmUser_UserUpdateDatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	confirmation := &db.UserConfirmation{
		UserEmail:       "alex@test.com",
		OneTimePassword: "abc123",
		Purpose:         db.ConfirmationPurposeSignUp,
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "user_confirmations" SET "confirmed_time"=$1 WHERE one_time_password = $2 AND purpose = $3 AND confirmed_time = $4`)).
		WithArgs(sqlmock.AnyArg(), confirmation.OneTimePassword, db.ConfirmationPurposeSignUp, 0).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "is_enabled"=$1 WHERE email = $2`)).
		WithArgs(true, confirmation.UserEmail).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.ConfirmUser(dbConn, confirmation)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestChangePassword_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	newPasswordHash := []byte("newhash")

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "password_hash"=$1 WHERE email = $2`)).
		WithArgs(newPasswordHash, "alex@test.com").
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.ChangePassword(dbConn, "alex@test.com", newPasswordHash)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateScope_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "scopes"`)).
		WithArgs("custom_scope").
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.CreateScope(dbConn, "custom_scope")

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListScopes_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "scopes"`)).
		WillReturnError(errDatabase)

	scopes, err := db.ListScopes(dbConn)

	assert.ErrorIs(t, err, errDatabase)
	assert.Nil(t, scopes)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListScopes_RecordNotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "scopes"`)).
		WillReturnError(gorm.ErrRecordNotFound)

	scopes, err := db.ListScopes(dbConn)

	assert.NoError(t, err)
	assert.NotNil(t, scopes)
	assert.Empty(t, scopes)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteScope_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "scopes" WHERE name = $1`)).
		WithArgs("custom_scope").
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.DeleteScope(dbConn, "custom_scope")

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIsScopeExist_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "scopes" WHERE name = $1`)).
		WithArgs("openid").
		WillReturnError(errDatabase)

	exists, err := db.IsScopeExist(dbConn, "openid")

	assert.ErrorIs(t, err, errDatabase)
	assert.False(t, exists)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIsScopeInUse_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "client_scopes" WHERE scope_name = $1`)).
		WithArgs("openid").
		WillReturnError(errDatabase)

	inUse, err := db.IsScopeInUse(dbConn, "openid")

	assert.ErrorIs(t, err, errDatabase)
	assert.False(t, inUse)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateClientScope_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "client_scopes"`)).
		WithArgs("cli1", "openid").
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.CreateClientScope(dbConn, "cli1", "openid")

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListClientScopes_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "client_scopes" WHERE client_id = $1`)).
		WithArgs("cli1").
		WillReturnError(errDatabase)

	scopes, err := db.ListClientScopes(dbConn, "cli1")

	assert.ErrorIs(t, err, errDatabase)
	assert.Nil(t, scopes)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListClientScopes_RecordNotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "client_scopes" WHERE client_id = $1`)).
		WithArgs("cli1").
		WillReturnError(gorm.ErrRecordNotFound)

	scopes, err := db.ListClientScopes(dbConn, "cli1")

	assert.NoError(t, err)
	assert.NotNil(t, scopes)
	assert.Empty(t, scopes)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteClientScope_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "client_scopes" WHERE client_id = $1 AND scope_name = $2`)).
		WithArgs("cli1", "openid").
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.DeleteClientScope(dbConn, "cli1", "openid")

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListOIDCClients_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients"`)).
		WillReturnError(errDatabase)

	clients, err := db.ListOIDCClients(dbConn)

	assert.ErrorIs(t, err, errDatabase)
	assert.Nil(t, clients)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestListOIDCClients_RecordNotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients"`)).
		WillReturnError(gorm.ErrRecordNotFound)

	clients, err := db.ListOIDCClients(dbConn)

	assert.NoError(t, err)
	assert.NotNil(t, clients)
	assert.Empty(t, clients)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetOIDCClient_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "oidc_clients" WHERE name = $1 ORDER BY "oidc_clients"."name" LIMIT $2`)).
		WithArgs("google", 1).
		WillReturnError(errDatabase)

	client, err := db.GetOIDCClient(dbConn, "google")

	assert.ErrorIs(t, err, errDatabase)
	assert.Nil(t, client)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateOIDCClient_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	client := &db.OidcClient{
		Name:         "google",
		ClientID:     "google-client-id",
		ClientSecret: "google-secret",
		RedirectURI:  "http://localhost/callback",
		ButtonName:   "Sign in with Google",
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "oidc_clients"`)).
		WithArgs(client.Name, client.ClientID, client.ClientSecret, client.RedirectURI, client.ButtonName, client.Issuer, client.TeamID, client.KeyID).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.CreateOIDCClient(dbConn, client)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateOIDCClient_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	client := &db.OidcClient{
		Name:         "google",
		ClientID:     "new-google-client-id",
		ClientSecret: "new-google-secret",
		RedirectURI:  "http://localhost/newcallback",
		ButtonName:   "Login with Google",
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "oidc_clients" SET`)).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.UpdateOIDCClient(dbConn, client)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteOIDCClient_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "oidc_clients" WHERE name = $1`)).
		WithArgs("google").
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.DeleteOIDCClient(dbConn, "google")

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// User administration Tests

func TestUpdateUser_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	displayName := "Alexander"
	isEnabled := false
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "display_name"=$1,"is_enabled"=$2,"revoked_at"=$3 WHERE email = $4`)).
		WithArgs(displayName, isEnabled, sqlmock.AnyArg(), "alex@test.com").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.UpdateUser(dbConn, "alex@test.com", &displayName, &isEnabled)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateUser_NothingToUpdate(t *testing.T) {
	dbConn, mock := getDBConnection()

	err := db.UpdateUser(dbConn, "alex@test.com", nil, nil)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateUser_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	isEnabled := true
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "is_enabled"=$1 WHERE email = $2`)).
		WithArgs(isEnabled, "alex@test.com").
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.UpdateUser(dbConn, "alex@test.com", nil, &isEnabled)

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateUser_Enable_DoesNotRevoke(t *testing.T) {
	dbConn, mock := getDBConnection()

	isEnabled := true
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE "users" SET "is_enabled"=$1 WHERE email = $2`)).
		WithArgs(isEnabled, "alex@test.com").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.UpdateUser(dbConn, "alex@test.com", nil, &isEnabled)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func expectIssuedForActiveUser(mock sqlmock.Sqlmock, isEnabled bool, createdAt, revokedAt *time.Time) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("alex@test.com", 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "is_enabled", "created_at", "revoked_at"}).
			AddRow("alex@test.com", isEnabled, createdAt, revokedAt))
}

func TestIsIssuedForActiveUser(t *testing.T) {
	issuedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	before := issuedAt.Add(-time.Minute)
	after := issuedAt.Add(time.Minute)

	tests := []struct {
		name      string
		isEnabled bool
		createdAt *time.Time
		revokedAt *time.Time
		expected  bool
	}{
		{"active user", true, &before, nil, true},
		{"user created before the column", true, nil, nil, true},
		{"disabled user", false, &before, nil, false},
		{"revoked before issued", true, &before, &before, true},
		{"revoked after issued", true, &before, &after, false},
		{"revoked when issued", true, &before, &issuedAt, false},
		{"re-created after issued", true, &after, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbConn, mock := getDBConnection()
			expectIssuedForActiveUser(mock, tt.isEnabled, tt.createdAt, tt.revokedAt)

			valid, err := db.IsIssuedForActiveUser(dbConn, "alex@test.com", issuedAt)

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, valid)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestIsIssuedForActiveUser_NotFound(t *testing.T) {
	dbConn, mock := getDBConnection()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("alex@test.com", 1).
		WillReturnError(gorm.ErrRecordNotFound)

	valid, err := db.IsIssuedForActiveUser(dbConn, "alex@test.com", time.Now())

	assert.NoError(t, err)
	assert.False(t, valid)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIsIssuedForActiveUser_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("alex@test.com", 1).
		WillReturnError(errDatabase)

	valid, err := db.IsIssuedForActiveUser(dbConn, "alex@test.com", time.Now())

	assert.ErrorIs(t, err, errDatabase)
	assert.False(t, valid)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteUser_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	for _, query := range []string{
		`DELETE FROM "user_credentials" WHERE user_email = $1`,
		`DELETE FROM "user_roles" WHERE user_email = $1`,
		`DELETE FROM "user_confirmations" WHERE user_email = $1`,
		`DELETE FROM "users" WHERE email = $1`,
	} {
		mock.ExpectExec(regexp.QuoteMeta(query)).
			WithArgs("alex@test.com").
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectCommit()

	err := db.DeleteUser(dbConn, "alex@test.com")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteUser_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "user_credentials" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "user_roles" WHERE user_email = $1`)).
		WithArgs("alex@test.com").
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.DeleteUser(dbConn, "alex@test.com")

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestHasClients(t *testing.T) {
	for _, count := range []int{0, 2} {
		dbConn, mock := getDBConnection()

		mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "clients" WHERE user_email = $1`)).
			WithArgs("alex@test.com").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(count))

		hasClients, err := db.HasClients(dbConn, "alex@test.com")

		assert.NoError(t, err)
		assert.Equal(t, count > 0, hasClients)
		assert.NoError(t, mock.ExpectationsWereMet())
	}
}

func TestHasClients_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "clients"`)).
		WillReturnError(errDatabase)

	_, err := db.HasClients(dbConn, "alex@test.com")

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAddUserRole_NewRole(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "roles" WHERE name = $1`)).
		WillReturnRows(sqlmock.NewRows([]string{"name"}))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "roles" ("name") VALUES ($1)`)).
		WithArgs("editor").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "user_roles" ("user_email","role_name") VALUES ($1,$2)`)).
		WithArgs("alex@test.com", "editor").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.AddUserRole(dbConn, "alex@test.com", "editor")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAddUserRole_ExistingRole(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "roles" WHERE name = $1`)).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("admin"))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "user_roles" ("user_email","role_name") VALUES ($1,$2)`)).
		WithArgs("alex@test.com", "admin").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := db.AddUserRole(dbConn, "alex@test.com", "admin")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAddUserRole_HeldAlready_ReturnsErrDuplicatedKey(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "roles" WHERE name = $1`)).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("admin"))
	// unique_violation of PostgreSQL
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "user_roles"`)).
		WillReturnError(&pgconn.PgError{Code: "23505"})
	mock.ExpectRollback()

	err := db.AddUserRole(dbConn, "alex@test.com", "admin")

	assert.ErrorIs(t, err, gorm.ErrDuplicatedKey)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAddUserRole_RoleQueryError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "roles"`)).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	err := db.AddUserRole(dbConn, "alex@test.com", "admin")

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRemoveUserRole(t *testing.T) {
	for _, rowsAffected := range []int64{0, 1} {
		dbConn, mock := getDBConnection()

		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "user_roles" WHERE user_email = $1 AND role_name = $2`)).
			WithArgs("alex@test.com", "admin").
			WillReturnResult(sqlmock.NewResult(0, rowsAffected))
		mock.ExpectCommit()

		removed, err := db.RemoveUserRole(dbConn, "alex@test.com", "admin")

		assert.NoError(t, err)
		assert.Equal(t, rowsAffected > 0, removed)
		assert.NoError(t, mock.ExpectationsWereMet())
	}
}

func TestRemoveUserRole_DatabaseError(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM "user_roles"`)).
		WillReturnError(errDatabase)
	mock.ExpectRollback()

	_, err := db.RemoveUserRole(dbConn, "alex@test.com", "admin")

	assert.ErrorIs(t, err, errDatabase)
	assert.NoError(t, mock.ExpectationsWereMet())
}
