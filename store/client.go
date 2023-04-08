package store

import (
	"github.com/alexhokl/auth-server/db"
	"github.com/go-oauth2/oauth2/v4"
)

type Client struct {
	id          string
	secret      string
	redirectURI string
	isPublic    bool
	userEmail   string
}

func NewClient(clientID, clientSecret, redirectURI, userEmail string, isPublic bool) *Client {
	return &Client{
		id:          clientID,
		secret:      clientSecret,
		redirectURI: redirectURI,
		isPublic:    isPublic,
		userEmail:   userEmail,
	}
}

func toClientInfo(c *db.Client) oauth2.ClientInfo {
	return &Client{
		id:          c.ClientID,
		secret:      c.ClientSecret,
		redirectURI: c.RedirectURI,
		isPublic:    c.IsPublic,
		userEmail:   c.UserEmail,
	}
}

func (c *Client) GetID() string {
	return c.id
}

func (c *Client) GetSecret() string {
	return c.secret
}

func (c *Client) GetDomain() string {
	return c.redirectURI
}

func (c *Client) GetUserID() string {
	return c.userEmail
}

func (c *Client) IsPublic() bool {
	return c.isPublic
}
