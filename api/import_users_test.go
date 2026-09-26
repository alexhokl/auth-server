package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func writeTestImportFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "import_users.json")
	assert.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

func TestGetSeedUsers_ReadsUsers(t *testing.T) {
	path := writeTestImportFile(t, `[
		{
			"email": "user@test.com",
			"password": "P@ssw0rd",
			"display_name": "Test User",
			"roles": ["admin"]
		}
	]`)

	users, roles, err := GetSeedUsers(path)

	assert.NoError(t, err)
	assert.Len(t, users, 1)
	assert.Equal(t, "user@test.com", users[0].Email)
	assert.Equal(t, "Test User", users[0].DisplayName)
	assert.Len(t, users[0].Roles, 1)
	assert.Equal(t, "admin", users[0].Roles[0].Name)
	assert.Len(t, roles, 1)
	assert.Equal(t, "admin", roles[0].Name)
}

// A seeded user has to be enabled as there is no confirmation of the mail
// address of such user.
func TestGetSeedUsers_UsersAreEnabled(t *testing.T) {
	path := writeTestImportFile(t, `[
		{"email": "user@test.com", "password": "P@ssw0rd", "roles": ["admin"]}
	]`)

	users, _, err := GetSeedUsers(path)

	assert.NoError(t, err)
	assert.Len(t, users, 1)
	assert.True(t, users[0].IsEnabled)
}

func TestGetSeedUsers_PasswordIsHashed(t *testing.T) {
	path := writeTestImportFile(t, `[
		{"email": "user@test.com", "password": "P@ssw0rd", "roles": ["admin"]}
	]`)

	users, _, err := GetSeedUsers(path)

	assert.NoError(t, err)
	assert.Len(t, users, 1)
	assert.NotEqual(t, "P@ssw0rd", string(users[0].PasswordHash))
	assert.NoError(
		t,
		bcrypt.CompareHashAndPassword(users[0].PasswordHash, []byte("P@ssw0rd")),
	)
}

func TestGetSeedUsers_RolesAreNotDuplicated(t *testing.T) {
	path := writeTestImportFile(t, `[
		{"email": "one@test.com", "password": "P@ssw0rd", "roles": ["admin", "user"]},
		{"email": "two@test.com", "password": "P@ssw0rd", "roles": ["admin"]}
	]`)

	users, roles, err := GetSeedUsers(path)

	assert.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Len(t, roles, 2)

	names := []string{roles[0].Name, roles[1].Name}
	assert.ElementsMatch(t, []string{"admin", "user"}, names)
}

func TestGetSeedUsers_UserWithoutRoles(t *testing.T) {
	path := writeTestImportFile(t, `[
		{"email": "user@test.com", "password": "P@ssw0rd"}
	]`)

	users, roles, err := GetSeedUsers(path)

	assert.NoError(t, err)
	assert.Len(t, users, 1)
	assert.Empty(t, users[0].Roles)
	assert.Empty(t, roles)
}

func TestGetSeedUsers_EmptyList(t *testing.T) {
	path := writeTestImportFile(t, `[]`)

	users, roles, err := GetSeedUsers(path)

	assert.NoError(t, err)
	assert.Empty(t, users)
	assert.Empty(t, roles)
}

func TestGetSeedUsers_NonExistentFile(t *testing.T) {
	users, roles, err := GetSeedUsers(filepath.Join(t.TempDir(), "missing.json"))

	assert.Error(t, err)
	assert.Nil(t, users)
	assert.Nil(t, roles)
}

func TestGetSeedUsers_MalformedJSON(t *testing.T) {
	path := writeTestImportFile(t, `{ this is not JSON`)

	users, roles, err := GetSeedUsers(path)

	assert.Error(t, err)
	assert.Nil(t, users)
	assert.Nil(t, roles)
}
