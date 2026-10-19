package jwthelper

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/alexhokl/helper/cryptohelper"
	"github.com/alexhokl/helper/httphelper"
	"github.com/alexhokl/helper/iohelper"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// IDTokenClaims describes the claims of an OpenID Connect ID token.
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce           string `json:"nonce,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"`
	Email           string `json:"email,omitempty"`
}

type EcKeyJWTGenerator struct {
	kid           string
	key           *ecdsa.PrivateKey
	signingMethod jwt.SigningMethod
}

func NewEcKeyJWTGenerator(kid string, key *ecdsa.PrivateKey, signingMethod jwt.SigningMethod) *EcKeyJWTGenerator {
	return &EcKeyJWTGenerator{
		kid:           kid,
		key:           key,
		signingMethod: signingMethod,
	}
}

func LoadEcdsaPrivateKey(pathToPrivateKeyFile string, pathToPrivateKeyPasswordFile string) (*ecdsa.PrivateKey, error) {
	privateKeyBytes, err := iohelper.ReadBytesFromFile(pathToPrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %w", err)
	}
	passwordBytes, err := iohelper.ReadFirstLineBytesFromFile(pathToPrivateKeyPasswordFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read password: %w", err)
	}

	key, err := cryptohelper.GetEcdsaKey(privateKeyBytes, passwordBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to get ECDSA key: %w", err)
	}

	return key, nil
}

func (g *EcKeyJWTGenerator) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {
	claims := &jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{data.Client.GetID()},
		Subject:   data.UserID,
		ExpiresAt: jwt.NewNumericDate(data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn())),
		IssuedAt:  jwt.NewNumericDate(data.TokenInfo.GetAccessCreateAt()),
		Issuer:    httphelper.GetBaseURL(data.Request),
	}

	access, err := g.sign(claims)
	if err != nil {
		return "", "", err
	}
	refresh := ""

	if isGenRefresh {
		t := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
		refresh = base64.URLEncoding.EncodeToString([]byte(t))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}

	return access, refresh, nil
}

// IDToken signs an OpenID Connect ID token with the same key as access tokens.
func (g *EcKeyJWTGenerator) IDToken(claims *IDTokenClaims) (string, error) {
	return g.sign(claims)
}

func (g *EcKeyJWTGenerator) sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(g.signingMethod, claims)
	if g.kid != "" {
		token.Header["kid"] = g.kid
	}
	return token.SignedString(g.key)
}
