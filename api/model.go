package api

import (
	"github.com/alexhokl/auth-server/db"
)

type UserSignUpRequest struct {
	Email    string `form:"email" binding:"required,email" example:"alex@test.com"`
	Password string `form:"password" binding:"required" example:"P@ssw0rd"`
}

type UserSignInRequest struct {
	Email string `form:"email" binding:"required,email" example:"alex@test.com"`
}

type UserSignInWithPasswordRequest struct {
	Password string `form:"password" binding:"required" example:"P@ssw0rd"`
}

type PasswordChangeRequest struct {
	OldPassword string `form:"current_password" binding:"required" example:"P@ssw0rd"`
	NewPassword string `form:"new_password" binding:"required" example:"NewP@ssw0rd"`
}

type PasswordResetRequest struct {
	Email string `form:"email" binding:"required,email" example:"alex@test.com"`
}

type NewPasswordRequest struct {
	NewPassword string `form:"new_password" binding:"required" example:"P@ssw0rd"`
	OTP         string `form:"otp" binding:"required" example:"123456"`
}

type UserResponse struct {
	Email       string           `json:"email"`
	DisplayName string           `json:"display_name"`
	Roles       []string         `json:"roles"`
	Credentials []CredentialInfo `json:"credentials"`
	IsEnabled   bool             `json:"is_enabled"`
}

type UserUpdateRequest struct {
	DisplayName *string `json:"display_name,omitempty" example:"Alex"`
	IsEnabled   *bool   `json:"is_enabled,omitempty" example:"true"`
}

type UserRoleRequest struct {
	Name string `json:"name" binding:"required" example:"admin"`
}

type ClientCreateRequest struct {
	ClientID     string `json:"client_id" binding:"required" example:"cli"`
	ClientSecret string `json:"client_secret" binding:"required" example:"P@ssw0rd"`
	RedirectUri  string `json:"redirect_uri" binding:"required" example:"http://localhost:8080/callback"`
	UserEmail    string `json:"user_email" binding:"required" example:"alex@test.com"`
}

type ClientUpdateRequest struct {
	ClientSecret *string `json:"client_secret,omitempty" example:"P@ssw0rd"`
	RedirectUri  *string `json:"redirect_uri,omitempty" example:"http://localhost:8080/callback"`
	UserEmail    *string `json:"user_email,omitempty" example:"alex@test.com"`
}

type ClientResponse struct {
	ClientID    string `json:"client_id"`
	RedirectUri string `json:"redirect_uri"`
	UserEmail   string `json:"user_email"`
}

type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required" example:"authorization_code"`
	Code         string `form:"code" binding:"required" example:"code"`
	RedirectUri  string `form:"redirect_uri" binding:"required" example:"http://localhost:8088"`
	ClientID     string `form:"client_id" binding:"required" example:"cli"`
	ClientSecret string `form:"client_secret" binding:"required" example:"P@ssw0rd"`
}

type CredentialNameRequest struct {
	Name string `json:"name" binding:"required" example:"My FIDO key"`
}

type OIDCClientResponse struct {
	Name        string `json:"name"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	ButtonName  string `json:"button_name"`
	Issuer      string `json:"issuer,omitempty"`
	TeamID      string `json:"team_id,omitempty"`
	KeyID       string `json:"key_id,omitempty"`
}

type OIDCClientCreateRequest struct {
	Name         string `json:"name" binding:"required" example:"google" enums:"google,github,apple,okta,microsoft"`
	ClientID     string `json:"client_id" binding:"required" example:"cli"`
	ClientSecret string `json:"client_secret" binding:"required" example:"P@ssw0rd"`
	RedirectURI  string `json:"redirect_uri" binding:"required" example:"http://localhost:8080/callback"`
	ButtonName   string `json:"button_name" binding:"required" example:"Login with My OIDC client"`
	// Issuer is required for Okta and Microsoft
	Issuer string `json:"issuer" example:"https://login.microsoftonline.com/common/v2.0"`
	// TeamID and KeyID are required for Apple, whose client secret is the
	// PEM encoded private key (.p8 file)
	TeamID string `json:"team_id" example:"ABCDE12345"`
	KeyID  string `json:"key_id" example:"FGHIJ67890"`
}

type OIDCClientUpdateRequest struct {
	ClientID     string `json:"client_id" binding:"required" example:"cli"`
	ClientSecret string `json:"client_secret" binding:"required" example:"P@ssw0rd"`
	RedirectURI  string `json:"redirect_uri" binding:"required" example:"http://localhost:8080/callback"`
	ButtonName   string `json:"button_name" binding:"required" example:"Login with My OIDC client"`
	Issuer       string `json:"issuer" example:"https://login.microsoftonline.com/common/v2.0"`
	TeamID       string `json:"team_id" example:"ABCDE12345"`
	KeyID        string `json:"key_id" example:"FGHIJ67890"`
}

type OpenIDConfiguration struct {
	Issuer                                             string   `json:"issuer,omitempty"`
	AuthorizationEndpoint                              string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                                      string   `json:"token_endpoint,omitempty"`
	JwksUri                                            string   `json:"jwks_uri,omitempty"`
	UserinfoEndpoint                                   string   `json:"userinfo_endpoint,omitempty"`
	RegistrationEndpoint                               string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                                    []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                             []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported                             []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported                              []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported                   []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ClaimsSupported                                    []string `json:"claims_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                               string   `json:"service_documentation,omitempty"`
	UILocalesSupported                                 []string `json:"ui_locales_supported,omitempty"`
	OpPolicyUri                                        string   `json:"op_policy_uri,omitempty"`
	OpTosUri                                           string   `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                 string   `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported             []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                              string   `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported                      []string `json:"code_challenge_methods_supported,omitempty"`
}

// UserInfo describes the claims returned by the userinfo endpoint.
type UserInfo struct {
	Subject       string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
}

// IntrospectionResponse describes a token returned by the introspection
// endpoint (RFC 7662 section 2.2); an inactive token has only Active.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	Issuer    string `json:"iss,omitempty"`
}

type WebFingerLinks struct {
	Rel  string `json:"rel,omitempty"`
	Type string `json:"type,omitempty"`
	Href string `json:"href"`
}

type WebFingerConfiguration struct {
	Subject string           `json:"subject"`
	Links   []WebFingerLinks `json:"links"`
}

type JSONWebKey struct {
	Kty     string   `json:"kty"`
	Use     string   `json:"use,omitempty"`
	KeyOps  []string `json:"key_ops,omitempty"`
	Alg     string   `json:"alg,omitempty"`
	Kid     string   `json:"kid,omitempty"`
	X5u     string   `json:"x5u,omitempty"`
	X5c     []string `json:"x5c,omitempty"`
	X5t     string   `json:"x5t,omitempty"`
	X5tS256 string   `json:"x5t#S256,omitempty"`
	N       string   `json:"n,omitempty"`
	E       string   `json:"e,omitempty"`
	Crv     string   `json:"crv,omitempty"`
	X       string   `json:"x,omitempty"`
	Y       string   `json:"y,omitempty"`
}

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

type CredentialInfo struct {
	ID   []byte `json:"id"`
	Name string `json:"name"`
}

type ImportUser struct {
	Email       string   `json:"email"`
	Password    string   `json:"password"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
}

type ScopeCreationRequest struct {
	Name string `json:"name" binding:"required" example:"read"`
}

func (req *UserSignUpRequest) ToUser() (*db.User, error) {
	hash, err := hashPassword(req.Password)
	if err != nil {
		return nil, err
	}
	return &db.User{
		Email:        req.Email,
		PasswordHash: hash,
	}, nil
}

func ToClientResponse(c db.Client) *ClientResponse {
	return &ClientResponse{
		ClientID:    c.ClientID,
		RedirectUri: c.RedirectURI,
		UserEmail:   c.UserEmail,
	}
}

func ToUserResponse(u db.User) UserResponse {
	response := UserResponse{
		Email:       u.Email,
		DisplayName: u.DisplayName,
		Roles:       []string{},
		Credentials: []CredentialInfo{},
		IsEnabled:   u.IsEnabled,
	}
	for _, role := range u.Roles {
		response.Roles = append(response.Roles, role.Name)
	}
	for _, credential := range u.Credentials {
		response.Credentials = append(response.Credentials, CredentialInfo{
			ID:   credential.ID,
			Name: credential.FriendlyName,
		})
	}
	return response
}
