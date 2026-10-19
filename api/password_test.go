package api

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func init() {
	lowerArgon2idCost()
}

// lowerArgon2idCost makes hashing fast in tests; it is idempotent.
func lowerArgon2idCost() {
	argon2idMemoryKiB = 8
	argon2idTime = 1
}

func hashTestPassword(password string) []byte {
	lowerArgon2idCost()
	hash, err := hashPassword(password)
	if err != nil {
		panic(err)
	}
	return hash
}

func TestHashPassword_ReturnsArgon2idPHCString(t *testing.T) {
	hash, err := hashPassword("testPassword123")

	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(hash), "$argon2id$v=19$m=8,t=1,p=1$"))
}

func TestHashPassword_VerifiesWithOriginalPassword(t *testing.T) {
	hash, err := hashPassword("testPassword123")
	assert.NoError(t, err)

	matches, needsRehash, err := verifyPassword(hash, "testPassword123")

	assert.NoError(t, err)
	assert.True(t, matches)
	assert.False(t, needsRehash)
}

func TestHashPassword_DifferentPasswordDoesNotVerify(t *testing.T) {
	hash, err := hashPassword("password1")
	assert.NoError(t, err)

	matches, needsRehash, err := verifyPassword(hash, "password2")

	assert.NoError(t, err)
	assert.False(t, matches)
	assert.False(t, needsRehash)
}

func TestHashPassword_SamePasswordProducesDifferentHashes(t *testing.T) {
	hash1, err := hashPassword("samePassword")
	assert.NoError(t, err)
	hash2, err := hashPassword("samePassword")
	assert.NoError(t, err)

	assert.NotEqual(t, string(hash1), string(hash2))
}

func TestHashPassword_EmptyPassword(t *testing.T) {
	hash, err := hashPassword("")
	assert.NoError(t, err)

	matches, _, err := verifyPassword(hash, "")

	assert.NoError(t, err)
	assert.True(t, matches)
}

func TestHashPassword_LongPasswordIsNotTruncated(t *testing.T) {
	// a hash that truncates its input (such as bcrypt) would match
	base := strings.Repeat("a", 72)
	hash, err := hashPassword(base + "x")
	assert.NoError(t, err)

	matches, _, err := verifyPassword(hash, base+"y")

	assert.NoError(t, err)
	assert.False(t, matches)
}

func TestVerifyPassword_OutdatedParametersNeedRehash(t *testing.T) {
	hash, err := hashPassword("testPassword123")
	assert.NoError(t, err)
	argon2idMemoryKiB = 16
	defer lowerArgon2idCost()

	matches, needsRehash, err := verifyPassword(hash, "testPassword123")

	assert.NoError(t, err)
	assert.True(t, matches)
	assert.True(t, needsRehash)
}

func TestVerifyPassword_UnsupportedHash(t *testing.T) {
	for _, hash := range []string{
		"",
		"plain",
		"$2a$04$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234",
		"$argon2id$v=19$m=8,t=1,p=1$bad",
		"$argon2id$v=18$m=8,t=1,p=1$c2FsdHNhbHQ$a2V5",
		"$argon2id$v=19$m=x,t=1,p=1$c2FsdHNhbHQ$a2V5",
		"$argon2id$v=19$m=8,t=1,p=1$!!$a2V5",
	} {
		matches, _, err := verifyPassword([]byte(hash), "password")

		assert.ErrorIs(t, err, errUnsupportedPasswordHash, hash)
		assert.False(t, matches, hash)
	}
}
