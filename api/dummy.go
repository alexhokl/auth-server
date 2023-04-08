package api

type DummyCredentialCreationData struct {
	DummyPublicKeyCredential
	Response DummyParsedAttestationResponse
	Raw      CredentialCreationResponse
}

type DummyCredentialAssertionData struct {
	DummyPublicKeyCredential
	Response ParsedAssertionResponse
	Raw      CredentialAssertionResponse
}

type DummyPublicKeyCredential struct {
	DummyCredential
	RawID                   []byte                                     `json:"rawId"`
	ClientExtensionResults  DummyAuthenticationExtensionsClientOutputs `json:"clientExtensionResults,omitempty"`
	AuthenticatorAttachment DummyAuthenticatorAttachment               `json:"authenticatorAttachment,omitempty"`
}

type DummyCredential struct {
	ID   string `cbor:"id"`
	Type string `cbor:"type"`
}

type DummyAuthenticationExtensionsClientOutputs map[string]interface{}

type DummyAuthenticatorAttachment string

type DummyParsedAttestationResponse struct {
	CollectedClientData CollectedClientData
	AttestationObject   AttestationObject
	Transports          []AuthenticatorTransport
}

type CollectedClientData struct {
	Type         CeremonyType  `json:"type"`
	Challenge    string        `json:"challenge"`
	Origin       string        `json:"origin"`
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
	Hint         string        `json:"new_keys_may_be_added_here,omitempty"`
}
type CeremonyType string
type TokenBinding struct {
	Status TokenBindingStatus `json:"status"`
	ID     string             `json:"id,omitempty"`
}
type TokenBindingStatus string
type AuthenticatorTransport string
type AttestationObject struct {
	AuthData     AuthenticatorData
	RawAuthData  []byte                 `json:"authData"`
	Format       string                 `json:"fmt"`
	AttStatement map[string]interface{} `json:"attStmt,omitempty"`
}
type AuthenticatorData struct {
	RPIDHash []byte                 `json:"rpid"`
	Flags    AuthenticatorFlags     `json:"flags"`
	Counter  uint32                 `json:"sign_count"`
	AttData  AttestedCredentialData `json:"att_data"`
	ExtData  []byte                 `json:"ext_data"`
}
type AuthenticatorFlags byte
type AttestedCredentialData struct {
	AAGUID              []byte `json:"aaguid"`
	CredentialID        []byte `json:"credential_id"`
	CredentialPublicKey []byte `json:"public_key"`
}
type CredentialCreationResponse struct {
	PublicKeyCredential
	AttestationResponse AuthenticatorAttestationResponse `json:"response"`
	Transports          []string                         `json:"transports,omitempty"`
}
type PublicKeyCredential struct {
	Credential
	RawID                   URLEncodedBase64                           `json:"rawId"`
	ClientExtensionResults  DummyAuthenticationExtensionsClientOutputs `json:"clientExtensionResults,omitempty"`
	AuthenticatorAttachment string                                     `json:"authenticatorAttachment,omitempty"`
}
type Credential struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}
type URLEncodedBase64 []byte
type AuthenticatorAttestationResponse struct {
	AuthenticatorResponse
	AttestationObject URLEncodedBase64 `json:"attestationObject"`
	Transports        []string         `json:"transports,omitempty"`
}
type AuthenticatorResponse struct {
	ClientDataJSON URLEncodedBase64 `json:"clientDataJSON"`
}
type ParsedAssertionResponse struct {
	CollectedClientData CollectedClientData
	AuthenticatorData   AuthenticatorData
	Signature           []byte
	UserHandle          []byte
}
type CredentialAssertionResponse struct {
	PublicKeyCredential
	AssertionResponse AuthenticatorAssertionResponse `json:"response"`
}
type AuthenticatorAssertionResponse struct {
	AuthenticatorResponse
	AuthenticatorData URLEncodedBase64 `json:"authenticatorData"`
	Signature         URLEncodedBase64 `json:"signature"`
	UserHandle        URLEncodedBase64 `json:"userHandle,omitempty"`
}

