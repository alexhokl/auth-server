package store_test

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alexhokl/auth-server/store"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/stretchr/testify/assert"
)

// fakeTokenStore returns the same token, or error, for any lookup.
type fakeTokenStore struct {
	oauth2.TokenStore
	token oauth2.TokenInfo
	err   error
}

func (s *fakeTokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	return s.token, s.err
}

func (s *fakeTokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	return s.token, s.err
}

func (s *fakeTokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	return s.token, s.err
}

var tokenIssuedAt = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func newTestToken(userID string) *models.Token {
	return &models.Token{
		UserID:          userID,
		CodeCreateAt:    tokenIssuedAt,
		AccessCreateAt:  tokenIssuedAt,
		RefreshCreateAt: tokenIssuedAt,
	}
}

func expectTokenUser(mock sqlmock.Sqlmock, isEnabled bool, revokedAt *time.Time) {
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("user@test.com", 1).
		WillReturnRows(sqlmock.NewRows([]string{"email", "is_enabled", "created_at", "revoked_at"}).
			AddRow("user@test.com", isEnabled, tokenIssuedAt.Add(-time.Hour), revokedAt))
}

// getters exercises each lookup of a token store.
var getters = map[string]func(oauth2.TokenStore) (oauth2.TokenInfo, error){
	"code": func(s oauth2.TokenStore) (oauth2.TokenInfo, error) {
		return s.GetByCode(context.Background(), "code")
	},
	"access": func(s oauth2.TokenStore) (oauth2.TokenInfo, error) {
		return s.GetByAccess(context.Background(), "access")
	},
	"refresh": func(s oauth2.TokenStore) (oauth2.TokenInfo, error) {
		return s.GetByRefresh(context.Background(), "refresh")
	},
}

func TestTokenStore_ActiveUser_ReturnsToken(t *testing.T) {
	for name, get := range getters {
		t.Run(name, func(t *testing.T) {
			dbConn, mock := getDBConnection()
			token := newTestToken("user@test.com")
			expectTokenUser(mock, true, nil)

			ti, err := get(store.NewTokenStore(dbConn, &fakeTokenStore{token: token}))

			assert.NoError(t, err)
			assert.Equal(t, token, ti)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestTokenStore_InactiveUser_ReturnsNil(t *testing.T) {
	revokedAt := tokenIssuedAt.Add(time.Minute)
	for name, get := range getters {
		t.Run(name+"/disabled", func(t *testing.T) {
			dbConn, mock := getDBConnection()
			expectTokenUser(mock, false, nil)

			ti, err := get(store.NewTokenStore(dbConn, &fakeTokenStore{token: newTestToken("user@test.com")}))

			assert.NoError(t, err)
			assert.Nil(t, ti)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
		t.Run(name+"/revoked", func(t *testing.T) {
			dbConn, mock := getDBConnection()
			expectTokenUser(mock, true, &revokedAt)

			ti, err := get(store.NewTokenStore(dbConn, &fakeTokenStore{token: newTestToken("user@test.com")}))

			assert.NoError(t, err)
			assert.Nil(t, ti)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// A token of client credentials grant has no user to check.
func TestTokenStore_WithoutUser_ReturnsToken(t *testing.T) {
	dbConn, mock := getDBConnection()
	token := newTestToken("")

	ti, err := store.NewTokenStore(dbConn, &fakeTokenStore{token: token}).GetByAccess(context.Background(), "access")

	assert.NoError(t, err)
	assert.Equal(t, token, ti)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenStore_NotFound_ReturnsNil(t *testing.T) {
	dbConn, mock := getDBConnection()

	ti, err := store.NewTokenStore(dbConn, &fakeTokenStore{}).GetByRefresh(context.Background(), "refresh")

	assert.NoError(t, err)
	assert.Nil(t, ti)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenStore_StoreError_ReturnsError(t *testing.T) {
	dbConn, mock := getDBConnection()
	storeErr := errors.New("redis error")

	_, err := store.NewTokenStore(dbConn, &fakeTokenStore{err: storeErr}).GetByCode(context.Background(), "code")

	assert.ErrorIs(t, err, storeErr)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestTokenStore_DatabaseError_ReturnsError(t *testing.T) {
	dbConn, mock := getDBConnection()
	dbErr := errors.New("database error")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "users" WHERE email = $1 ORDER BY "users"."email" LIMIT $2`)).
		WithArgs("user@test.com", 1).
		WillReturnError(dbErr)

	ti, err := store.NewTokenStore(dbConn, &fakeTokenStore{token: newTestToken("user@test.com")}).GetByAccess(context.Background(), "access")

	assert.ErrorIs(t, err, dbErr)
	assert.Nil(t, ti)
	assert.NoError(t, mock.ExpectationsWereMet())
}
