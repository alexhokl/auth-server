package api

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// Password Hash Tests

func TestGetPasswordHash_ReturnsValidBcryptHash(t *testing.T) {
	password := "testPassword123"

	hash := getPasswordHash(password)

	assert.NotEmpty(t, hash)
	// Verify the hash can be compared with the original password
	err := bcrypt.CompareHashAndPassword(hash, []byte(password))
	assert.NoError(t, err)
}

func TestGetPasswordHash_DifferentPasswordsProduceDifferentHashes(t *testing.T) {
	password1 := "password1"
	password2 := "password2"

	hash1 := getPasswordHash(password1)
	hash2 := getPasswordHash(password2)

	assert.NotEqual(t, hash1, hash2)
}

func TestGetPasswordHash_SamePasswordProducesDifferentHashes(t *testing.T) {
	// bcrypt includes a random salt, so same password should produce different hashes
	password := "samePassword"

	hash1 := getPasswordHash(password)
	hash2 := getPasswordHash(password)

	// Hashes should be different due to random salt
	assert.NotEqual(t, string(hash1), string(hash2))
	// But both should validate against the original password
	assert.NoError(t, bcrypt.CompareHashAndPassword(hash1, []byte(password)))
	assert.NoError(t, bcrypt.CompareHashAndPassword(hash2, []byte(password)))
}

func TestGetPasswordHash_EmptyPassword(t *testing.T) {
	hash := getPasswordHash("")

	assert.NotEmpty(t, hash)
	err := bcrypt.CompareHashAndPassword(hash, []byte(""))
	assert.NoError(t, err)
}

// Unique Credential Name Tests

func TestGenerateUniqueCredentialName_EmptyList(t *testing.T) {
	existingNames := []string{}

	name := generateUniqueCredentialName(existingNames)

	assert.Equal(t, "key 0", name)
}

func TestGenerateUniqueCredentialName_FirstKeyExists(t *testing.T) {
	existingNames := []string{"key 0"}

	name := generateUniqueCredentialName(existingNames)

	assert.Equal(t, "key 1", name)
}

func TestGenerateUniqueCredentialName_MultipleKeysExist(t *testing.T) {
	existingNames := []string{"key 0", "key 1", "key 2"}

	name := generateUniqueCredentialName(existingNames)

	assert.Equal(t, "key 3", name)
}

func TestGenerateUniqueCredentialName_GapInSequence(t *testing.T) {
	// If key 1 is missing, it should fill the gap
	existingNames := []string{"key 0", "key 2", "key 3"}

	name := generateUniqueCredentialName(existingNames)

	assert.Equal(t, "key 1", name)
}

func TestGenerateUniqueCredentialName_CustomNamesDoNotAffectSequence(t *testing.T) {
	existingNames := []string{"My YubiKey", "Backup Key"}

	name := generateUniqueCredentialName(existingNames)

	assert.Equal(t, "key 0", name)
}

func TestGenerateUniqueCredentialName_MixedCustomAndSequentialNames(t *testing.T) {
	existingNames := []string{"key 0", "My YubiKey", "key 1"}

	name := generateUniqueCredentialName(existingNames)

	assert.Equal(t, "key 2", name)
}

func TestGenerateUniqueCredentialName_AllSlotsUsed(t *testing.T) {
	// Create a list with all 100 possible keys (key 0 through key 99)
	existingNames := make([]string, 100)
	for i := 0; i < 100; i++ {
		existingNames[i] = fmt.Sprintf("key %d", i)
	}

	name := generateUniqueCredentialName(existingNames)

	assert.Equal(t, "", name)
}

// Email Content Tests

func TestGetConfirmationMailContent(t *testing.T) {
	confirmationURL := "https://example.com/confirm/abc123"

	content := getConfirmationMailContent(confirmationURL)

	assert.Contains(t, content, confirmationURL)
	assert.Contains(t, content, "Click here to confirm your email address")
	assert.Contains(t, content, "<a href=")
}

func TestGetPasswordChangedMailContent(t *testing.T) {
	content := getPasswordChangedMailContent()

	assert.Contains(t, content, "Your password has been changed")
}

func TestGetResetPasswordMailContent(t *testing.T) {
	resetURL := "https://example.com/reset/xyz789"

	content := getResetPasswordMailContent(resetURL)

	assert.Contains(t, content, resetURL)
	assert.Contains(t, content, "Click here to reset your password")
	assert.Contains(t, content, "<a href=")
}

// isMaliciousRequest Tests (currently returns nil - placeholder test)

func TestIsMaliciousRequest_ReturnsNil(t *testing.T) {
	// This is a placeholder test since the function is not implemented yet
	// When implemented, this should be updated with proper test cases
	err := isMaliciousRequest(nil)

	assert.Nil(t, err)
}
