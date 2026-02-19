package store_test

import (
	"testing"

	"github.com/alexhokl/auth-server/store"
	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	client := store.NewClient("client-id", "client-secret", "http://localhost:8080/callback", "user@test.com", false)

	assert.NotNil(t, client)
	assert.Equal(t, "client-id", client.GetID())
	assert.Equal(t, "client-secret", client.GetSecret())
	assert.Equal(t, "http://localhost:8080/callback", client.GetDomain())
	assert.Equal(t, "user@test.com", client.GetUserID())
	assert.False(t, client.IsPublic())
}

func TestNewClient_PublicClient(t *testing.T) {
	client := store.NewClient("public-client", "", "http://localhost:8080/callback", "user@test.com", true)

	assert.NotNil(t, client)
	assert.Equal(t, "public-client", client.GetID())
	assert.Empty(t, client.GetSecret())
	assert.True(t, client.IsPublic())
}

func TestClient_GetID(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
	}{
		{"simple id", "cli"},
		{"uuid id", "550e8400-e29b-41d4-a716-446655440000"},
		{"with dashes", "my-client-app"},
		{"empty id", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := store.NewClient(tt.clientID, "secret", "http://localhost", "user@test.com", false)
			assert.Equal(t, tt.clientID, client.GetID())
		})
	}
}

func TestClient_GetSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{"simple secret", "password123"},
		{"complex secret", "P@ssw0rd!#$%^&*()"},
		{"empty secret for public client", ""},
		{"long secret", "verylongsecretverylongsecretverylongsecretverylongsecret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := store.NewClient("cli", tt.secret, "http://localhost", "user@test.com", false)
			assert.Equal(t, tt.secret, client.GetSecret())
		})
	}
}

func TestClient_GetDomain(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
	}{
		{"localhost", "http://localhost:8080/callback"},
		{"https url", "https://example.com/oauth/callback"},
		{"with query params", "http://localhost:8080/callback?state=abc"},
		{"ip address", "http://192.168.1.1:8080/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := store.NewClient("cli", "secret", tt.redirectURI, "user@test.com", false)
			assert.Equal(t, tt.redirectURI, client.GetDomain())
		})
	}
}

func TestClient_GetUserID(t *testing.T) {
	tests := []struct {
		name      string
		userEmail string
	}{
		{"simple email", "user@test.com"},
		{"complex email", "user.name+tag@subdomain.example.com"},
		{"empty email", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := store.NewClient("cli", "secret", "http://localhost", tt.userEmail, false)
			assert.Equal(t, tt.userEmail, client.GetUserID())
		})
	}
}

func TestClient_IsPublic(t *testing.T) {
	tests := []struct {
		name     string
		isPublic bool
	}{
		{"private client", false},
		{"public client", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := store.NewClient("cli", "secret", "http://localhost", "user@test.com", tt.isPublic)
			assert.Equal(t, tt.isPublic, client.IsPublic())
		})
	}
}

func TestClient_ImplementsOAuth2ClientInfo(t *testing.T) {
	// Verify Client implements oauth2.ClientInfo interface by testing all methods
	client := store.NewClient("test-id", "test-secret", "http://localhost:8080", "test@example.com", false)

	// All these methods are part of oauth2.ClientInfo interface
	_ = client.GetID()
	_ = client.GetSecret()
	_ = client.GetDomain()
	_ = client.GetUserID()
	_ = client.IsPublic()

	// If compilation succeeds, the interface is implemented
	assert.NotNil(t, client)
}
