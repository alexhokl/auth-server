package jwthelper

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const appleAudience = "https://appleid.apple.com"

// appleClientSecretLifetime is how long a generated client secret is valid;
// Apple accepts up to 6 months but a secret is generated per token request.
const appleClientSecretLifetime = 5 * time.Minute

// ParseApplePrivateKey parses the PEM encoded PKCS #8 private key (a .p8 file)
// of a Sign in with Apple key.
func ParseApplePrivateKey(pemKey []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in Apple private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse Apple private key: %w", err)
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Apple private key is not an ECDSA key")
	}
	return ecdsaKey, nil
}

// AppleClientSecret returns the client secret of a Sign in with Apple token
// request, which is a JWT signed with the private key of the developer team.
// See https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret
func AppleClientSecret(teamID string, keyID string, clientID string, pemKey []byte, now time.Time) (string, error) {
	key, err := ParseApplePrivateKey(pemKey)
	if err != nil {
		return "", err
	}
	claims := &jwt.RegisteredClaims{
		Issuer:    teamID,
		Subject:   clientID,
		Audience:  jwt.ClaimStrings{appleAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(appleClientSecretLifetime)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyID
	return token.SignedString(key)
}
