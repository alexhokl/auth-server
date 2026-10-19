package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/alexhokl/auth-server/db"
	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"
)

const (
	argon2idSaltLength = 16
	argon2idKeyLength  = 32
)

// Parameters of Argon2id (64 MiB, 2 passes, 1 lane); they are variables so
// that tests can lower the cost.
var (
	argon2idMemoryKiB uint32 = 64 * 1024
	argon2idTime      uint32 = 2
	argon2idThreads   uint8  = 1
)

var errUnsupportedPasswordHash = errors.New("unsupported password hash")

// hashPassword hashes a password with Argon2id and returns the hash in the
// PHC string format, which records the parameters and the salt.
func hashPassword(password string) ([]byte, error) {
	salt := make([]byte, argon2idSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(password), salt, argon2idTime, argon2idMemoryKiB, argon2idThreads, argon2idKeyLength)
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2idMemoryKiB,
		argon2idTime,
		argon2idThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	return []byte(encoded), nil
}

// verifyPassword checks a password against an Argon2id hash in the PHC format.
// It returns whether the password matches and, if so, whether the hash should
// be replaced by a fresh one as its parameters are outdated.
func verifyPassword(hash []byte, password string) (matches bool, needsRehash bool, err error) {
	if !strings.HasPrefix(string(hash), "$argon2id$") {
		return false, false, errUnsupportedPasswordHash
	}
	return verifyArgon2id(string(hash), password)
}

func verifyArgon2id(encoded string, password string) (bool, bool, error) {
	// "", "argon2id", "v=19", "m=65536,t=2,p=1", salt, key
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return false, false, errUnsupportedPasswordHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, false, errUnsupportedPasswordHash
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, false, errUnsupportedPasswordHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, false, errUnsupportedPasswordHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return false, false, errUnsupportedPasswordHash
	}

	computed := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(key)))
	if subtle.ConstantTimeCompare(key, computed) != 1 {
		return false, false, nil
	}

	needsRehash := memory != argon2idMemoryKiB ||
		time != argon2idTime ||
		threads != argon2idThreads ||
		len(key) != argon2idKeyLength
	return true, needsRehash, nil
}

// upgradePasswordHash replaces the stored hash of a user, whose password has
// just been verified, with one using the current parameters. A failure is
// logged only as the user can still sign in with the existing hash.
func upgradePasswordHash(dbConn *gorm.DB, email string, password string) {
	hash, err := hashPassword(password)
	if err != nil {
		slog.Warn("Unable to rehash password", slog.String("error", err.Error()))
		return
	}
	if err := db.ChangePassword(dbConn, email, hash); err != nil {
		slog.Warn("Unable to save rehashed password", slog.String("error", err.Error()))
	}
}
