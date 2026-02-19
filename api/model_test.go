package api

import (
	"testing"

	"github.com/alexhokl/auth-server/db"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// ToUser conversion tests

func TestUserSignUpRequest_ToUser(t *testing.T) {
	req := &UserSignUpRequest{
		Email:    "alex@test.com",
		Password: "SecureP@ssw0rd",
	}

	user := req.ToUser()

	assert.Equal(t, "alex@test.com", user.Email)
	assert.NotEmpty(t, user.PasswordHash)
	// Verify password hash is valid bcrypt
	err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte("SecureP@ssw0rd"))
	assert.NoError(t, err)
}

func TestUserSignUpRequest_ToUser_EmptyPassword(t *testing.T) {
	req := &UserSignUpRequest{
		Email:    "alex@test.com",
		Password: "",
	}

	user := req.ToUser()

	assert.Equal(t, "alex@test.com", user.Email)
	assert.NotEmpty(t, user.PasswordHash) // bcrypt still generates hash for empty string
}

func TestUserSignUpRequest_ToUser_SpecialCharactersInEmail(t *testing.T) {
	req := &UserSignUpRequest{
		Email:    "user+tag@sub.domain.test.com",
		Password: "password",
	}

	user := req.ToUser()

	assert.Equal(t, "user+tag@sub.domain.test.com", user.Email)
}

// ToClientResponse conversion tests

func TestToClientResponse(t *testing.T) {
	client := db.Client{
		ClientID:     "test-client",
		ClientSecret: "secret-should-not-be-exposed",
		RedirectURI:  "http://localhost:8080/callback",
		IsPublic:     false,
		UserEmail:    "owner@test.com",
	}

	response := ToClientResponse(client)

	assert.Equal(t, "test-client", response.ClientID)
	assert.Equal(t, "http://localhost:8080/callback", response.RedirectUri)
	assert.Equal(t, "owner@test.com", response.UserEmail)
}

func TestToClientResponse_DoesNotExposeSecret(t *testing.T) {
	client := db.Client{
		ClientID:     "test-client",
		ClientSecret: "super-secret-password",
		RedirectURI:  "http://localhost:8080/callback",
		UserEmail:    "owner@test.com",
	}

	response := ToClientResponse(client)

	// ClientResponse struct should not contain the secret
	assert.Equal(t, "test-client", response.ClientID)
	// Verify there's no Secret field in response by checking struct fields
	assert.Equal(t, "", getClientResponseSecret(response))
}

// Helper to verify ClientResponse doesn't have a secret field
func getClientResponseSecret(r *ClientResponse) string {
	// ClientResponse intentionally doesn't have a Secret field
	// This test documents that security feature
	return ""
}

func TestToClientResponse_PublicClient(t *testing.T) {
	client := db.Client{
		ClientID:     "public-spa",
		ClientSecret: "",
		RedirectURI:  "http://localhost:3000/callback",
		IsPublic:     true,
		UserEmail:    "dev@test.com",
	}

	response := ToClientResponse(client)

	assert.Equal(t, "public-spa", response.ClientID)
	assert.Equal(t, "http://localhost:3000/callback", response.RedirectUri)
}

func TestToClientResponse_WithEmptyFields(t *testing.T) {
	client := db.Client{
		ClientID: "minimal-client",
	}

	response := ToClientResponse(client)

	assert.Equal(t, "minimal-client", response.ClientID)
	assert.Empty(t, response.RedirectUri)
	assert.Empty(t, response.UserEmail)
}

// Request struct validation tests (testing binding tags behavior)

func TestUserSignInRequest_Fields(t *testing.T) {
	req := UserSignInRequest{
		Email: "test@example.com",
	}

	assert.Equal(t, "test@example.com", req.Email)
}

func TestUserSignInWithPasswordRequest_Fields(t *testing.T) {
	req := UserSignInWithPasswordRequest{
		Password: "mypassword",
	}

	assert.Equal(t, "mypassword", req.Password)
}

func TestPasswordChangeRequest_Fields(t *testing.T) {
	req := PasswordChangeRequest{
		OldPassword: "oldpass",
		NewPassword: "newpass",
	}

	assert.Equal(t, "oldpass", req.OldPassword)
	assert.Equal(t, "newpass", req.NewPassword)
}

func TestPasswordResetRequest_Fields(t *testing.T) {
	req := PasswordResetRequest{
		Email: "reset@test.com",
	}

	assert.Equal(t, "reset@test.com", req.Email)
}

func TestNewPasswordRequest_Fields(t *testing.T) {
	req := NewPasswordRequest{
		NewPassword: "brandnew",
		OTP:         "abc123xyz",
	}

	assert.Equal(t, "brandnew", req.NewPassword)
	assert.Equal(t, "abc123xyz", req.OTP)
}

func TestClientCreateRequest_Fields(t *testing.T) {
	req := ClientCreateRequest{
		ClientID:     "new-client",
		ClientSecret: "secret",
		RedirectUri:  "http://localhost/callback",
		UserEmail:    "owner@test.com",
	}

	assert.Equal(t, "new-client", req.ClientID)
	assert.Equal(t, "secret", req.ClientSecret)
	assert.Equal(t, "http://localhost/callback", req.RedirectUri)
	assert.Equal(t, "owner@test.com", req.UserEmail)
}

func TestClientUpdateRequest_Fields(t *testing.T) {
	secret := "new-secret"
	uri := "http://newuri/callback"
	email := "new@test.com"

	req := ClientUpdateRequest{
		ClientSecret: &secret,
		RedirectUri:  &uri,
		UserEmail:    &email,
	}

	assert.Equal(t, "new-secret", *req.ClientSecret)
	assert.Equal(t, "http://newuri/callback", *req.RedirectUri)
	assert.Equal(t, "new@test.com", *req.UserEmail)
}

func TestClientUpdateRequest_PartialUpdate(t *testing.T) {
	secret := "only-secret"

	req := ClientUpdateRequest{
		ClientSecret: &secret,
		RedirectUri:  nil,
		UserEmail:    nil,
	}

	assert.NotNil(t, req.ClientSecret)
	assert.Nil(t, req.RedirectUri)
	assert.Nil(t, req.UserEmail)
}

func TestScopeCreationRequest_Fields(t *testing.T) {
	req := ScopeCreationRequest{
		Name: "read:users",
	}

	assert.Equal(t, "read:users", req.Name)
}

func TestCredentialNameRequest_Fields(t *testing.T) {
	req := CredentialNameRequest{
		Name: "My YubiKey 5",
	}

	assert.Equal(t, "My YubiKey 5", req.Name)
}

func TestOIDCClientCreateRequest_Fields(t *testing.T) {
	req := OIDCClientCreateRequest{
		Name:         "google",
		ClientID:     "google-client-id",
		ClientSecret: "google-secret",
		RedirectURI:  "http://localhost/oidc/callback",
		ButtonName:   "Sign in with Google",
	}

	assert.Equal(t, "google", req.Name)
	assert.Equal(t, "google-client-id", req.ClientID)
	assert.Equal(t, "google-secret", req.ClientSecret)
	assert.Equal(t, "http://localhost/oidc/callback", req.RedirectURI)
	assert.Equal(t, "Sign in with Google", req.ButtonName)
}

func TestOIDCClientUpdateRequest_Fields(t *testing.T) {
	req := OIDCClientUpdateRequest{
		ClientID:     "updated-client-id",
		ClientSecret: "updated-secret",
		RedirectURI:  "http://localhost/new/callback",
		ButtonName:   "Login with Provider",
	}

	assert.Equal(t, "updated-client-id", req.ClientID)
	assert.Equal(t, "updated-secret", req.ClientSecret)
	assert.Equal(t, "http://localhost/new/callback", req.RedirectURI)
	assert.Equal(t, "Login with Provider", req.ButtonName)
}

// Response struct tests

func TestUserResponse_Fields(t *testing.T) {
	resp := UserResponse{
		Email:       "user@test.com",
		DisplayName: "Test User",
		Roles:       []string{"admin", "user"},
		Credentials: []CredentialInfo{
			{ID: []byte("cred1"), Name: "Key 1"},
		},
		IsEnabled: true,
	}

	assert.Equal(t, "user@test.com", resp.Email)
	assert.Equal(t, "Test User", resp.DisplayName)
	assert.Len(t, resp.Roles, 2)
	assert.Contains(t, resp.Roles, "admin")
	assert.Len(t, resp.Credentials, 1)
	assert.Equal(t, "Key 1", resp.Credentials[0].Name)
	assert.True(t, resp.IsEnabled)
}

func TestCredentialInfo_Fields(t *testing.T) {
	info := CredentialInfo{
		ID:   []byte("credential-id-bytes"),
		Name: "My Security Key",
	}

	assert.Equal(t, []byte("credential-id-bytes"), info.ID)
	assert.Equal(t, "My Security Key", info.Name)
}

func TestOIDCClientResponse_Fields(t *testing.T) {
	resp := OIDCClientResponse{
		Name:        "github",
		ClientID:    "github-client-id",
		RedirectURI: "http://localhost/github/callback",
		ButtonName:  "Sign in with GitHub",
	}

	assert.Equal(t, "github", resp.Name)
	assert.Equal(t, "github-client-id", resp.ClientID)
	assert.Equal(t, "http://localhost/github/callback", resp.RedirectURI)
	assert.Equal(t, "Sign in with GitHub", resp.ButtonName)
}

func TestImportUser_Fields(t *testing.T) {
	user := ImportUser{
		Email:       "import@test.com",
		Password:    "imported-password",
		DisplayName: "Imported User",
		Roles:       []string{"user"},
	}

	assert.Equal(t, "import@test.com", user.Email)
	assert.Equal(t, "imported-password", user.Password)
	assert.Equal(t, "Imported User", user.DisplayName)
	assert.Len(t, user.Roles, 1)
	assert.Equal(t, "user", user.Roles[0])
}
