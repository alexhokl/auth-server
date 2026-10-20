package jwthelper_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/alexhokl/auth-server/jwthelper"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func generateApplePEMKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	assert.NoError(t, err)
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestParseApplePrivateKey_ValidKey_ReturnsKey(t *testing.T) {
	key, pemKey := generateApplePEMKey(t)

	parsed, err := jwthelper.ParseApplePrivateKey(pemKey)

	assert.NoError(t, err)
	assert.True(t, key.Equal(parsed))
}

func TestParseApplePrivateKey_NotPEM_ReturnsError(t *testing.T) {
	_, err := jwthelper.ParseApplePrivateKey([]byte("not a key"))

	assert.Error(t, err)
}

func TestParseApplePrivateKey_InvalidDER_ReturnsError(t *testing.T) {
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})

	_, err := jwthelper.ParseApplePrivateKey(pemKey)

	assert.Error(t, err)
}

func TestParseApplePrivateKey_RSAKey_ReturnsError(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	assert.NoError(t, err)

	_, err = jwthelper.ParseApplePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	assert.Error(t, err)
}

func TestAppleClientSecret_ContainsCorrectClaims(t *testing.T) {
	key, pemKey := generateApplePEMKey(t)
	now := time.Now().Truncate(time.Second)

	secret, err := jwthelper.AppleClientSecret("TEAM123", "KEY456", "com.example.signin", pemKey, now)
	assert.NoError(t, err)

	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(secret, claims, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)
	assert.Equal(t, "ES256", token.Header["alg"])
	assert.Equal(t, "KEY456", token.Header["kid"])
	assert.Equal(t, "TEAM123", claims.Issuer)
	assert.Equal(t, "com.example.signin", claims.Subject)
	assert.Equal(t, jwt.ClaimStrings{"https://appleid.apple.com"}, claims.Audience)
	assert.Equal(t, now.Unix(), claims.IssuedAt.Unix())
	assert.Equal(t, now.Add(5*time.Minute).Unix(), claims.ExpiresAt.Unix())
}

func TestAppleClientSecret_InvalidKey_ReturnsError(t *testing.T) {
	_, err := jwthelper.AppleClientSecret("TEAM123", "KEY456", "com.example.signin", []byte("not a key"), time.Now())

	assert.Error(t, err)
}
