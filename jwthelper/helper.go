package jwthelper

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/alexhokl/helper/cryptohelper"
	"github.com/alexhokl/helper/iohelper"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type EcKeyJWTGenerator struct {
	kid           string
	key           *ecdsa.PrivateKey
	signingMethod jwt.SigningMethod
}

func NewEcKeyJWTGenerator(keyID string, pathToPrivateKeyFile string, pathToPrivateKeyPasswordFile string, signingMethod jwt.SigningMethod) (*EcKeyJWTGenerator, error) {
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

	return &EcKeyJWTGenerator{
		kid:           keyID,
		key:           key,
		signingMethod: signingMethod,
	}, nil
}

func (g *EcKeyJWTGenerator) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {
	claims := &jwt.StandardClaims{
		Audience:  data.Client.GetID(),
		Subject:   data.UserID,
		ExpiresAt: data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
	}

	token := jwt.NewWithClaims(g.signingMethod, claims)
	if g.kid != "" {
		token.Header["kid"] = g.kid
	}

	access, err := token.SignedString(g.key)
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
