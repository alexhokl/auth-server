package db

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

func (user *User) WebAuthnID() []byte {
	return []byte(user.WebAuthnUserID.String())
}

func (user *User) WebAuthnName() string {
	return user.Email
}

func (user *User) WebAuthnDisplayName() string {
	// TODO: return user.DisplayName when sign-up is properly implemented
	return user.Email
}

func (user *User) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, len(user.Credentials))
	for i, cred := range user.Credentials {
		creds[i] = webauthn.Credential{
			ID:              cred.ID,
			PublicKey:       cred.PublicKey,
			AttestationType: cred.AttestationType,
			Transport:       cred.Transport,
			Flags: webauthn.CredentialFlags{
				UserPresent:    cred.UserPresent,
				UserVerified:   cred.UserVerified,
				BackupEligible: cred.BackupEligible,
				BackupState:    cred.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:       cred.AAGUID,
				SignCount:    cred.SignCount,
				CloneWarning: cred.CloneWarning,
				Attachment:   cred.Attachment,
			},
		}
	}
	return creds
}

func (user *User) WebAuthnIcon() string {
	return ""
}

func NewUserCredential(email string, friendlyName string, cred *webauthn.Credential) *UserCredential {
	return &UserCredential{
		ID:              cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Transport:       cred.Transport,
		UserPresent:     cred.Flags.UserPresent,
		UserVerified:    cred.Flags.UserVerified,
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		CloneWarning:    cred.Authenticator.CloneWarning,
		Attachment:      cred.Authenticator.Attachment,
		UserEmail:       email,
		FriendlyName:    friendlyName,
	}
}
