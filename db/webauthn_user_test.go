package db_test

import (
	"testing"

	"github.com/alexhokl/auth-server/db"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestUser_WebAuthnID(t *testing.T) {
	userID := uuid.New()
	user := &db.User{
		Email:          "alex@test.com",
		WebAuthnUserID: userID,
	}

	result := user.WebAuthnID()

	assert.Equal(t, []byte(userID.String()), result)
}

func TestUser_WebAuthnName(t *testing.T) {
	user := &db.User{
		Email:       "alex@test.com",
		DisplayName: "Alex",
	}

	result := user.WebAuthnName()

	assert.Equal(t, "alex@test.com", result)
}

func TestUser_WebAuthnDisplayName(t *testing.T) {
	user := &db.User{
		Email:       "alex@test.com",
		DisplayName: "Alex",
	}

	// Currently returns Email (see TODO in source)
	result := user.WebAuthnDisplayName()

	assert.Equal(t, "alex@test.com", result)
}

func TestUser_WebAuthnIcon(t *testing.T) {
	user := &db.User{
		Email: "alex@test.com",
	}

	result := user.WebAuthnIcon()

	assert.Empty(t, result)
}

func TestUser_WebAuthnCredentials_Empty(t *testing.T) {
	user := &db.User{
		Email:       "alex@test.com",
		Credentials: []db.UserCredential{},
	}

	result := user.WebAuthnCredentials()

	assert.Empty(t, result)
	assert.Len(t, result, 0)
}

func TestUser_WebAuthnCredentials_SingleCredential(t *testing.T) {
	credID := []byte("credential-id-1")
	publicKey := []byte("public-key-1")
	aaguid := []byte("aaguid-12345678")

	user := &db.User{
		Email: "alex@test.com",
		Credentials: []db.UserCredential{
			{
				ID:              credID,
				PublicKey:       publicKey,
				AttestationType: "direct",
				Transport:       []protocol.AuthenticatorTransport{protocol.USB},
				UserPresent:     true,
				UserVerified:    true,
				BackupEligible:  false,
				BackupState:     false,
				AAGUID:          aaguid,
				SignCount:       5,
				CloneWarning:    false,
				Attachment:      protocol.CrossPlatform,
				UserEmail:       "alex@test.com",
				FriendlyName:    "My YubiKey",
			},
		},
	}

	result := user.WebAuthnCredentials()

	assert.Len(t, result, 1)
	assert.Equal(t, credID, result[0].ID)
	assert.Equal(t, publicKey, result[0].PublicKey)
	assert.Equal(t, "direct", result[0].AttestationType)
	assert.Equal(t, []protocol.AuthenticatorTransport{protocol.USB}, result[0].Transport)
	assert.True(t, result[0].Flags.UserPresent)
	assert.True(t, result[0].Flags.UserVerified)
	assert.False(t, result[0].Flags.BackupEligible)
	assert.False(t, result[0].Flags.BackupState)
	assert.Equal(t, aaguid, result[0].Authenticator.AAGUID)
	assert.Equal(t, uint32(5), result[0].Authenticator.SignCount)
	assert.False(t, result[0].Authenticator.CloneWarning)
	assert.Equal(t, protocol.CrossPlatform, result[0].Authenticator.Attachment)
}

func TestUser_WebAuthnCredentials_MultipleCredentials(t *testing.T) {
	user := &db.User{
		Email: "alex@test.com",
		Credentials: []db.UserCredential{
			{
				ID:              []byte("cred-1"),
				PublicKey:       []byte("key-1"),
				AttestationType: "direct",
				UserPresent:     true,
				UserVerified:    true,
				AAGUID:          []byte("aaguid-1"),
				SignCount:       10,
				Attachment:      protocol.CrossPlatform,
				FriendlyName:    "Key 1",
			},
			{
				ID:              []byte("cred-2"),
				PublicKey:       []byte("key-2"),
				AttestationType: "indirect",
				UserPresent:     true,
				UserVerified:    false,
				AAGUID:          []byte("aaguid-2"),
				SignCount:       20,
				Attachment:      protocol.Platform,
				FriendlyName:    "Key 2",
			},
		},
	}

	result := user.WebAuthnCredentials()

	assert.Len(t, result, 2)
	assert.Equal(t, []byte("cred-1"), result[0].ID)
	assert.Equal(t, []byte("cred-2"), result[1].ID)
	assert.Equal(t, uint32(10), result[0].Authenticator.SignCount)
	assert.Equal(t, uint32(20), result[1].Authenticator.SignCount)
}

func TestNewUserCredential(t *testing.T) {
	credID := []byte("test-credential-id")
	publicKey := []byte("test-public-key")
	aaguid := []byte("test-aaguid-1234")

	webauthnCred := &webauthn.Credential{
		ID:              credID,
		PublicKey:       publicKey,
		AttestationType: "direct",
		Transport:       []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC},
		Flags: webauthn.CredentialFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupEligible: true,
			BackupState:    false,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       aaguid,
			SignCount:    100,
			CloneWarning: true,
			Attachment:   protocol.CrossPlatform,
		},
	}

	result := db.NewUserCredential("alex@test.com", "My Security Key", webauthnCred)

	assert.Equal(t, credID, result.ID)
	assert.Equal(t, publicKey, result.PublicKey)
	assert.Equal(t, "direct", result.AttestationType)
	assert.Equal(t, []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC}, result.Transport)
	assert.True(t, result.UserPresent)
	assert.True(t, result.UserVerified)
	assert.True(t, result.BackupEligible)
	assert.False(t, result.BackupState)
	assert.Equal(t, aaguid, result.AAGUID)
	assert.Equal(t, uint32(100), result.SignCount)
	assert.True(t, result.CloneWarning)
	assert.Equal(t, protocol.CrossPlatform, result.Attachment)
	assert.Equal(t, "alex@test.com", result.UserEmail)
	assert.Equal(t, "My Security Key", result.FriendlyName)
}

func TestNewUserCredential_MinimalCredential(t *testing.T) {
	webauthnCred := &webauthn.Credential{
		ID:        []byte("minimal-id"),
		PublicKey: []byte("minimal-key"),
	}

	result := db.NewUserCredential("user@test.com", "key 0", webauthnCred)

	assert.Equal(t, []byte("minimal-id"), result.ID)
	assert.Equal(t, []byte("minimal-key"), result.PublicKey)
	assert.Equal(t, "user@test.com", result.UserEmail)
	assert.Equal(t, "key 0", result.FriendlyName)
	assert.False(t, result.UserPresent)
	assert.False(t, result.UserVerified)
	assert.Equal(t, uint32(0), result.SignCount)
}

func TestUser_ImplementsWebAuthnUserInterface(t *testing.T) {
	// Verify User implements webauthn.User interface
	user := &db.User{
		Email:          "test@test.com",
		WebAuthnUserID: uuid.New(),
		Credentials:    []db.UserCredential{},
	}

	// All these methods are part of webauthn.User interface
	_ = user.WebAuthnID()
	_ = user.WebAuthnName()
	_ = user.WebAuthnDisplayName()
	_ = user.WebAuthnCredentials()
	_ = user.WebAuthnIcon()

	// If compilation succeeds, the interface is implemented
	assert.NotNil(t, user)
}

func TestUser_WebAuthnCredentials_WithBackupFlags(t *testing.T) {
	user := &db.User{
		Email: "alex@test.com",
		Credentials: []db.UserCredential{
			{
				ID:             []byte("backup-cred"),
				PublicKey:      []byte("backup-key"),
				BackupEligible: true,
				BackupState:    true,
				AAGUID:         []byte("backup-aaguid"),
			},
		},
	}

	result := user.WebAuthnCredentials()

	assert.Len(t, result, 1)
	assert.True(t, result[0].Flags.BackupEligible)
	assert.True(t, result[0].Flags.BackupState)
}
