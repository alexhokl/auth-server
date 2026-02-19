package store_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alexhokl/auth-server/store"
	"github.com/alexhokl/helper/database"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func getDBConnection() (*gorm.DB, sqlmock.Sqlmock) {
	mockDB, mock, _ := sqlmock.New()
	dialector := database.GetDatabaseDialectorFromConnection(mockDB)
	dbConn, _ := gorm.Open(dialector, &gorm.Config{})
	return dbConn, mock
}

func TestNewClientStore(t *testing.T) {
	dbConn, _ := getDBConnection()

	clientStore := store.NewClientStore(dbConn)

	assert.NotNil(t, clientStore)
}

func TestStore_GetByID_Found(t *testing.T) {
	dbConn, mock := getDBConnection()

	rows := sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "is_public", "user_email"}).
		AddRow("test-client", "secret123", "http://localhost:8080/callback", false, "user@test.com")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("test-client", 1).
		WillReturnRows(rows)

	clientStore := store.NewClientStore(dbConn)
	client, err := clientStore.GetByID(context.Background(), "test-client")

	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "test-client", client.GetID())
	assert.Equal(t, "secret123", client.GetSecret())
	assert.Equal(t, "http://localhost:8080/callback", client.GetDomain())
	assert.Equal(t, "user@test.com", client.GetUserID())
	assert.False(t, client.IsPublic())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestStore_GetByID_NotFound(t *testing.T) {
	dbConn, mock := getDBConnection()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("nonexistent", 1).
		WillReturnError(gorm.ErrRecordNotFound)

	clientStore := store.NewClientStore(dbConn)
	client, err := clientStore.GetByID(context.Background(), "nonexistent")

	assert.NoError(t, err)
	assert.Nil(t, client)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestStore_GetByID_PublicClient(t *testing.T) {
	dbConn, mock := getDBConnection()

	rows := sqlmock.NewRows([]string{"client_id", "client_secret", "redirect_uri", "is_public", "user_email"}).
		AddRow("public-client", "", "http://localhost:8080/callback", true, "user@test.com")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "clients" WHERE client_id = $1 ORDER BY "clients"."client_id" LIMIT $2`)).
		WithArgs("public-client", 1).
		WillReturnRows(rows)

	clientStore := store.NewClientStore(dbConn)
	client, err := clientStore.GetByID(context.Background(), "public-client")

	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.True(t, client.IsPublic())
	assert.Empty(t, client.GetSecret())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestStore_Create_Success(t *testing.T) {
	dbConn, mock := getDBConnection()

	client := store.NewClient("new-client", "new-secret", "http://localhost:9090/callback", "newuser@test.com", false)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "clients"`)).
		WithArgs("new-client", "new-secret", "http://localhost:9090/callback", false, "newuser@test.com").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	clientStore := store.NewClientStore(dbConn)
	err := clientStore.Create(context.Background(), client)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestStore_Create_PublicClient(t *testing.T) {
	dbConn, mock := getDBConnection()

	client := store.NewClient("public-new", "", "http://localhost:9090/callback", "newuser@test.com", true)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO "clients"`)).
		WithArgs("public-new", "", "http://localhost:9090/callback", true, "newuser@test.com").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	clientStore := store.NewClientStore(dbConn)
	err := clientStore.Create(context.Background(), client)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}
