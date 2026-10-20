package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/auth-server/jwthelper"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

type OIDCProvider string

const (
	Google    OIDCProvider = "google"
	GitHub    OIDCProvider = "github"
	Apple     OIDCProvider = "apple"
	Okta      OIDCProvider = "okta"
	Microsoft OIDCProvider = "microsoft"
)

const googleIssuer = "https://accounts.google.com"

const appleIssuer = "https://appleid.apple.com"

var appleEndpoint = oauth2.Endpoint{
	AuthURL:   "https://appleid.apple.com/auth/authorize",
	TokenURL:  "https://appleid.apple.com/auth/token",
	AuthStyle: oauth2.AuthStyleInParams,
}

const githubEmailsURL = "https://api.github.com/user/emails"

const microsoftLoginURL = "https://login.microsoftonline.com"

// microsoftConsumersTenantID is the tenant of personal Microsoft accounts,
// whose email addresses are verified by Microsoft.
const microsoftConsumersTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"

var microsoftIssuerPattern = regexp.MustCompile(`^https://login\.microsoftonline\.com/([^/]+)/v2\.0$`)

var microsoftTenantPattern = regexp.MustCompile(`^(common|organizations|consumers|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

// externalProvider describes how to sign in through an external provider.
type externalProvider struct {
	scopes []string
	// authParams are extra parameters of the authorization request
	authParams map[string]string
	// usesNonce is true for an OpenID Connect provider, whose ID token
	// carries the nonce of the authorization request
	usesNonce bool
	usesPKCE  bool
	endpoint  func(ctx context.Context, client *db.OidcClient) (oauth2.Endpoint, error)
	// clientSecret returns the client secret of a token request; the stored
	// client secret is used if it is nil
	clientSecret func(client *db.OidcClient) (string, error)
	// email returns the verified email address of the user signed in
	email func(ctx context.Context, client *db.OidcClient, config *oauth2.Config, token *oauth2.Token, nonce string) (string, error)
	// validate checks the provider specific settings of a client
	validate func(client *db.OidcClient) error
}

var externalProviders = map[OIDCProvider]*externalProvider{
	Google: {
		scopes:     []string{"openid", "profile", "email"},
		authParams: map[string]string{"access_type": "online"},
		usesNonce:  true,
		usesPKCE:   true,
		endpoint:   staticEndpoint(google.Endpoint),
		email: func(ctx context.Context, client *db.OidcClient, _ *oauth2.Config, token *oauth2.Token, nonce string) (string, error) {
			return getEmailFromIDToken(ctx, googleIssuer, client, token, nonce)
		},
	},
	GitHub: {
		scopes:   []string{"read:user", "user:email"},
		usesPKCE: true,
		endpoint: staticEndpoint(github.Endpoint),
		email:    getGitHubEmail,
	},
	Apple: {
		scopes: []string{"name", "email"},
		// Apple requires a form post of the callback when scopes are
		// requested
		authParams: map[string]string{"response_mode": "form_post"},
		usesNonce:  true,
		// PKCE is not documented by Apple
		usesPKCE: false,
		endpoint: staticEndpoint(appleEndpoint),
		clientSecret: func(client *db.OidcClient) (string, error) {
			return jwthelper.AppleClientSecret(client.TeamID, client.KeyID, client.ClientID, []byte(client.ClientSecret), time.Now())
		},
		email: func(ctx context.Context, client *db.OidcClient, _ *oauth2.Config, token *oauth2.Token, nonce string) (string, error) {
			return getEmailFromIDToken(ctx, appleIssuer, client, token, nonce)
		},
		validate: validateAppleClient,
	},
	Okta: {
		scopes:    []string{"openid", "profile", "email"},
		usesNonce: true,
		usesPKCE:  true,
		endpoint: func(ctx context.Context, client *db.OidcClient) (oauth2.Endpoint, error) {
			provider, err := oidc.NewProvider(ctx, client.Issuer)
			if err != nil {
				return oauth2.Endpoint{}, fmt.Errorf("unable to discover Okta issuer [%s]: %w", client.Issuer, err)
			}
			return provider.Endpoint(), nil
		},
		email: func(ctx context.Context, client *db.OidcClient, _ *oauth2.Config, token *oauth2.Token, nonce string) (string, error) {
			return getEmailFromIDToken(ctx, client.Issuer, client, token, nonce)
		},
		validate: validateOktaClient,
	},
	Microsoft: {
		scopes:    []string{"openid", "profile", "email"},
		usesNonce: true,
		usesPKCE:  true,
		endpoint: func(_ context.Context, client *db.OidcClient) (oauth2.Endpoint, error) {
			tenant, err := getMicrosoftTenant(client.Issuer)
			if err != nil {
				return oauth2.Endpoint{}, err
			}
			return microsoft.AzureADEndpoint(tenant), nil
		},
		email:    getMicrosoftEmail,
		validate: validateMicrosoftClient,
	},
}

func getExternalProvider(name string) (*externalProvider, error) {
	provider, ok := externalProviders[OIDCProvider(name)]
	if !ok {
		return nil, fmt.Errorf("unsupported OIDC client: %s", name)
	}
	return provider, nil
}

func isSupportedExternalProvider(name string) bool {
	_, ok := externalProviders[OIDCProvider(name)]
	return ok
}

// validateOIDCClient checks the settings of a client against its provider.
func validateOIDCClient(client *db.OidcClient) error {
	provider, err := getExternalProvider(client.Name)
	if err != nil {
		return err
	}
	if provider.validate == nil {
		return nil
	}
	return provider.validate(client)
}

func getOAuthConfig(ctx context.Context, oidcClient *db.OidcClient) (*oauth2.Config, *externalProvider, error) {
	provider, err := getExternalProvider(oidcClient.Name)
	if err != nil {
		return nil, nil, err
	}
	endpoint, err := provider.endpoint(ctx, oidcClient)
	if err != nil {
		return nil, nil, err
	}
	return &oauth2.Config{
		ClientID:     oidcClient.ClientID,
		ClientSecret: oidcClient.ClientSecret,
		RedirectURL:  oidcClient.RedirectURI,
		Endpoint:     endpoint,
		Scopes:       provider.scopes,
	}, provider, nil
}

func staticEndpoint(endpoint oauth2.Endpoint) func(context.Context, *db.OidcClient) (oauth2.Endpoint, error) {
	return func(context.Context, *db.OidcClient) (oauth2.Endpoint, error) {
		return endpoint, nil
	}
}

// flexibleBool is a boolean claim which some providers (such as Apple) send
// as a string.
type flexibleBool bool

func (b *flexibleBool) UnmarshalJSON(data []byte) error {
	switch strings.Trim(string(data), `"`) {
	case "true":
		*b = true
	case "false", "null", "":
		*b = false
	default:
		return fmt.Errorf("invalid boolean value: %s", data)
	}
	return nil
}

type idTokenClaims struct {
	Email         string       `json:"email"`
	EmailVerified flexibleBool `json:"email_verified"`
	Issuer        string       `json:"iss"`
	TenantID      string       `json:"tid"`
	// EmailDomainOwnerVerified is the optional claim xms_edov of Microsoft
	EmailDomainOwnerVerified flexibleBool `json:"xms_edov"`
}

// verifyIDToken verifies the ID token of a token response against the given
// verifier and the nonce of the authorization request.
func verifyIDToken(ctx context.Context, verifier *oidc.IDTokenVerifier, token *oauth2.Token, nonce string) (*idTokenClaims, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("unable to get ID token")
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("unable to verify ID token: %w", err)
	}
	if nonce == "" || idToken.Nonce != nonce {
		return nil, fmt.Errorf("nonce of ID token does not match")
	}
	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("unable to get claims from ID token: %w", err)
	}
	return &claims, nil
}

// getEmailFromIDToken returns the email address of an ID token issued by the
// given issuer, provided that the issuer has verified it.
func getEmailFromIDToken(ctx context.Context, issuer string, client *db.OidcClient, token *oauth2.Token, nonce string) (string, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return "", fmt.Errorf("unable to get ID token provider: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: client.ClientID})
	claims, err := verifyIDToken(ctx, verifier, token, nonce)
	if err != nil {
		return "", err
	}
	if claims.Email == "" {
		return "", fmt.Errorf("no email in ID token")
	}
	if !claims.EmailVerified {
		return "", fmt.Errorf("email [%s] is not verified by the OIDC provider", claims.Email)
	}
	return claims.Email, nil
}

func getGitHubEmail(ctx context.Context, _ *db.OidcClient, config *oauth2.Config, token *oauth2.Token, _ string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubEmailsURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := config.Client(ctx, token).Do(req)
	if err != nil {
		return "", fmt.Errorf("unable to get emails from GitHub: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unable to get emails from GitHub: status %d", res.StatusCode)
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(res.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("unable to parse emails from GitHub: %w", err)
	}
	for _, e := range emails {
		if e.Primary && e.Verified && e.Email != "" {
			return e.Email, nil
		}
	}
	return "", fmt.Errorf("no verified primary email on GitHub")
}

// getMicrosoftEmail returns the email address of a Microsoft ID token. As the
// email claim of an organisational account can be set by a tenant
// administrator, it is trusted only for personal accounts or if Microsoft has
// verified the domain owner of the email (optional claim xms_edov).
func getMicrosoftEmail(ctx context.Context, client *db.OidcClient, _ *oauth2.Config, token *oauth2.Token, nonce string) (string, error) {
	tenant, err := getMicrosoftTenant(client.Issuer)
	if err != nil {
		return "", err
	}
	keySet := oidc.NewRemoteKeySet(ctx, fmt.Sprintf("%s/%s/discovery/v2.0/keys", microsoftLoginURL, tenant))
	// the issuer of a multi-tenant application depends on the tenant of the
	// user and it is checked below
	verifier := oidc.NewVerifier(client.Issuer, keySet, &oidc.Config{
		ClientID:        client.ClientID,
		SkipIssuerCheck: true,
	})
	claims, err := verifyIDToken(ctx, verifier, token, nonce)
	if err != nil {
		return "", err
	}
	if err := checkMicrosoftTenant(tenant, claims); err != nil {
		return "", err
	}
	if claims.Email == "" {
		return "", fmt.Errorf("no email in ID token")
	}
	if claims.TenantID != microsoftConsumersTenantID && !claims.EmailDomainOwnerVerified {
		return "", fmt.Errorf("email [%s] of tenant [%s] is not verified by Microsoft", claims.Email, claims.TenantID)
	}
	return claims.Email, nil
}

// checkMicrosoftTenant checks the issuer and the tenant of an ID token
// against the tenant configured.
func checkMicrosoftTenant(tenant string, claims *idTokenClaims) error {
	if claims.TenantID == "" {
		return fmt.Errorf("no tenant in ID token")
	}
	if expected := fmt.Sprintf("%s/%s/v2.0", microsoftLoginURL, claims.TenantID); claims.Issuer != expected {
		return fmt.Errorf("expected issuer [%s] but got [%s]", expected, claims.Issuer)
	}
	switch tenant {
	case "common":
		return nil
	case "organizations":
		if claims.TenantID == microsoftConsumersTenantID {
			return fmt.Errorf("personal accounts are not allowed")
		}
		return nil
	case "consumers":
		if claims.TenantID != microsoftConsumersTenantID {
			return fmt.Errorf("only personal accounts are allowed")
		}
		return nil
	default:
		if claims.TenantID != tenant {
			return fmt.Errorf("expected tenant [%s] but got [%s]", tenant, claims.TenantID)
		}
		return nil
	}
}

func getMicrosoftTenant(issuer string) (string, error) {
	matches := microsoftIssuerPattern.FindStringSubmatch(issuer)
	if matches == nil || !microsoftTenantPattern.MatchString(matches[1]) {
		return "", fmt.Errorf("issuer [%s] is not in the form of %s/{common|organizations|consumers|tenant ID}/v2.0", issuer, microsoftLoginURL)
	}
	return matches[1], nil
}

func validateMicrosoftClient(client *db.OidcClient) error {
	_, err := getMicrosoftTenant(client.Issuer)
	return err
}

func validateOktaClient(client *db.OidcClient) error {
	issuer, err := url.Parse(client.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" {
		return fmt.Errorf("issuer [%s] is not an https URL", client.Issuer)
	}
	return nil
}

func validateAppleClient(client *db.OidcClient) error {
	if client.TeamID == "" || client.KeyID == "" {
		return fmt.Errorf("team ID and key ID are required")
	}
	if _, err := jwthelper.ParseApplePrivateKey([]byte(client.ClientSecret)); err != nil {
		return fmt.Errorf("client secret is not a valid private key: %w", err)
	}
	return nil
}
