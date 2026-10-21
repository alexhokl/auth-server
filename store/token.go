package store

import (
	"context"
	"time"

	"github.com/alexhokl/auth-server/db"
	"github.com/go-oauth2/oauth2/v4"
	"gorm.io/gorm"
)

// TokenStore wraps a token store so that codes and tokens issued to a user
// who has since been disabled or deleted are not found.
type TokenStore struct {
	oauth2.TokenStore
	dbConn *gorm.DB
}

func NewTokenStore(dbConn *gorm.DB, tokenStore oauth2.TokenStore) *TokenStore {
	return &TokenStore{
		TokenStore: tokenStore,
		dbConn:     dbConn,
	}
}

func (s *TokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	ti, err := s.TokenStore.GetByCode(ctx, code)
	return s.filterRevoked(ti, err, oauth2.TokenInfo.GetCodeCreateAt)
}

func (s *TokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	ti, err := s.TokenStore.GetByAccess(ctx, access)
	return s.filterRevoked(ti, err, oauth2.TokenInfo.GetAccessCreateAt)
}

func (s *TokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	ti, err := s.TokenStore.GetByRefresh(ctx, refresh)
	return s.filterRevoked(ti, err, oauth2.TokenInfo.GetRefreshCreateAt)
}

// filterRevoked returns nil, which the manager treats as an invalid code or
// token, if ti has been issued to a user who is no longer active.
func (s *TokenStore) filterRevoked(ti oauth2.TokenInfo, err error, getIssuedAt func(oauth2.TokenInfo) time.Time) (oauth2.TokenInfo, error) {
	if err != nil || ti == nil {
		return ti, err
	}
	// tokens of client credentials grant have no user
	if ti.GetUserID() == "" {
		return ti, nil
	}
	valid, err := db.IsIssuedForActiveUser(s.dbConn, ti.GetUserID(), getIssuedAt(ti))
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, nil
	}
	return ti, nil
}
