package api

import (
	"testing"

	"github.com/alexhokl/auth-server/db"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2/google"
)

func TestGetOAuthConfig_Google(t *testing.T) {
	client := &db.OidcClient{
		Name:         string(Google),
		ClientID:     "google-client-id",
		ClientSecret: "google-client-secret",
		RedirectURI:  "https://auth.example.com/signin/google/callback",
	}

	config, err := getOAuthConfig(client)

	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, google.Endpoint, config.Endpoint)
	assert.Equal(t, []string{"openid", "profile", "email"}, config.Scopes)
	assert.Equal(t, "google-client-id", config.ClientID)
	assert.Equal(t, "google-client-secret", config.ClientSecret)
	assert.Equal(
		t,
		"https://auth.example.com/signin/google/callback",
		config.RedirectURL,
	)
}

func TestGetOAuthConfig_NotImplementedProviders(t *testing.T) {
	notImplemented := []OIDCProvider{Facebook, Microsoft}

	for _, provider := range notImplemented {
		t.Run(string(provider), func(t *testing.T) {
			config, err := getOAuthConfig(&db.OidcClient{Name: string(provider)})

			assert.Error(t, err)
			assert.Nil(t, config)
			assert.Contains(t, err.Error(), "not implemented")
		})
	}
}

func TestGetOAuthConfig_UnsupportedProvider(t *testing.T) {
	config, err := getOAuthConfig(&db.OidcClient{Name: "some-provider"})

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "some-provider")
}
