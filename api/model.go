package api

import "github.com/alexhokl/auth-server/db"

type UserSignUpRequest struct {
	Email    string `form:"email" binding:"required,email" example:"alex@test.com"`
	Password string `form:"password" binding:"required" example:"P@ssw0rd"`
}

type UserSignInRequest struct {
	Email    string `form:"email" binding:"required,email" example:"alex@test.com"`
	Password string `form:"password" binding:"required" example:"P@ssw0rd"`
}

type PasswordChangeRequest struct {
	OldPassword string `json:"old_password" binding:"required" example:"P@ssw0rd"`
	NewPassword string `json:"new_password" binding:"required" example:"NewP@ssw0rd"`
}

type ClientCreateRequest struct {
	ClientID     string `json:"client_id" binding:"required" example:"cli"`
	ClientSecret string `json:"client_secret" binding:"required" example:"P@ssw0rd"`
	RedirectUri  string `json:"redirect_uri" binding:"required" example:"http://localhost:8080/callback"`
	UserEmail    string `json:"user_email" binding:"required" example:"alex@test.com"`
}

type ClientResponse struct {
	ClientID    string `json:"client_id"`
	RedirectUri string `json:"redirect_uri"`
	UserEmail   string `json:"user_email"`
}

type OpenIDConfiguration struct {
	Issuer                                             string   `json:"issuer,omitempty"`
	AuthorizationEndpoint                              string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                                      string   `json:"token_endpoint,omitempty"`
	JwksUri                                            string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                               string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                                    []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                             []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported                             []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                []string `json:"grant_types_supported,omitempty"`
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

type WebFingerLinks struct {
	Rel  string `json:"rel,omitempty"`
	Type string `json:"type,omitempty"`
	Href string `json:"href"`
}

type WebFingerConfiguration struct {
	Subject string `json:"subject"`
	Links   []WebFingerLinks `json:"links"`
}

func (req *UserSignUpRequest) ToUser() *db.User {
	return &db.User{
		Email:        req.Email,
		PasswordHash: getPasswordHash(req.Password),
	}
}

func ToClientResponse(c db.Client) *ClientResponse {
	return &ClientResponse{
		ClientID:    c.ClientID,
		RedirectUri: c.RedirectURI,
		UserEmail:   c.UserEmail,
	}
}
