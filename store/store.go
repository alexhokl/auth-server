package store

import (
	"context"

	"github.com/alexhokl/auth-server/db"
	"github.com/go-oauth2/oauth2/v4"
	"gorm.io/gorm"
)

type Store struct {
	dbConn *gorm.DB
}

func NewClientStore(dbConn *gorm.DB) *Store {
	return &Store{
		dbConn: dbConn,
	}
}

func (s *Store) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	client, err := db.GetClient(s.dbConn, id)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, nil
	}
	return toClientInfo(client), nil
}

func (s *Store) Create(ctx context.Context, client oauth2.ClientInfo) error {
	oauthClient := &db.Client{
		ClientID:     client.GetID(),
		ClientSecret: client.GetSecret(),
		RedirectURI:  client.GetDomain(),
		IsPublic:     client.IsPublic(),
		UserEmail:    client.GetUserID(),
	}

	return db.CreateClient(s.dbConn, oauthClient)
}

