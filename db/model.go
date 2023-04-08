package db

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
)

type User struct {
	Email          string    `gorm:"primary_key;unique;not null"`
	PasswordHash   []byte    `gorm:"not null"`
	DisplayName    string    `gorm:""`
	WebAuthnUserID uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	Credentials    []UserCredential
}

type Client struct {
	ClientID     string `gorm:"primary_key;unique;not null"`
	ClientSecret string `gorm:"not null"`
	RedirectURI  string
	IsPublic     bool
	UserEmail    string `gorm:"not null"`
	User         User   `gorm:"foreignKey:UserEmail"`
}

type UserCredential struct {
	ID              []byte                            `gorm:"primary_key;unique;not null"`
	PublicKey       []byte                            `gorm:"unique;not null"`
	AttestationType string                            `gorm:"not null"`
	Transport       []protocol.AuthenticatorTransport `gorm:"type:text[]"`
	UserPresent     bool                              `gorm:"not null"`
	UserVerified    bool                              `gorm:"not null"`
	BackupEligible  bool                              `gorm:"not null"`
	BackupState     bool                              `gorm:"not null"`
	AAGUID          []byte                            `gorm:"not null"`
	SignCount       uint32                            `gorm:"not null"`
	CloneWarning    bool                              `gorm:"not null"`
	Attachment      protocol.AuthenticatorAttachment  `gorm:"not null"`
	UserEmail       string                            `gorm:"uniqueIndex:idx_uniq_credential_name,priority:1;not null"`
	FriendlyName    string                            `gorm:"uniqueIndex:idx_uniq_credential_name,priority:2;not null"`
	User            User                              `gorm:"foreignKey:UserEmail"`
}
