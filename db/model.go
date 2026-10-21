package db

import (
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
)

type User struct {
	Email          string    `gorm:"primary_key;unique;not null"`
	PasswordHash   []byte    `gorm:"not null"`
	DisplayName    string    `gorm:""`
	WebAuthnUserID uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	Credentials    []UserCredential
	Roles          []Role `gorm:"many2many:user_roles;"`
	IsEnabled      bool   `gorm:"default:false;not null"`
	// CreatedAt is nil for users created before the column was added
	CreatedAt *time.Time `gorm:"autoCreateTime"`
	// RevokedAt is the time the user was last disabled; sessions and tokens
	// issued at or before it are invalid
	RevokedAt *time.Time
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

type Role struct {
	Name string `gorm:"primary_key;unique;not null"`
}

type UserRole struct {
	UserEmail string `gorm:"uniqueIndex:idx_uniq_user_role,priority:1;not null"`
	RoleName  string `gorm:"uniqueIndex:idx_uniq_user_role,priority:2;not null"`
	User      User   `gorm:"foreignKey:UserEmail"`
	Role      Role   `gorm:"foreignKey:RoleName"`
}

type UserConfirmation struct {
	UserEmail       string `gorm:"primary_key;unique;not null"`
	OneTimePassword string `gorm:"not null"`
	ExpiryTime      int64  `gorm:"not null"`
	ConfirmedTime   int64  `gorm:"not null"`
	Purpose         string `gorm:"not null;default:''"`
	User            User   `gorm:"foreignKey:UserEmail"`
}

const ConfirmationPurposeSignUp = "sign_up"
const ConfirmationPurposeResetPassword = "reset_password"

type Scope struct {
	Name string `gorm:"primary_key;unique;not null"`
}

type ClientScope struct {
	ClientID  string `gorm:"uniqueIndex:idx_uniq_client_scope,priority:1;not null"`
	ScopeName string `gorm:"uniqueIndex:idx_uniq_client_scope,priority:2;not null"`
	Client    Client `gorm:"foreignKey:ClientID"`
	Scope     Scope  `gorm:"foreignKey:ScopeName"`
}

type OidcClient struct {
	Name 		 string `gorm:"primary_key;unique;not null"`
	ClientID     string `gorm:"not null"`
	ClientSecret string `gorm:"not null"`
	RedirectURI  string `gorm:"not null"`
	ButtonName   string `gorm:"not null"`
	// Issuer is the issuer URL of an Okta or a Microsoft client
	Issuer string `gorm:"not null;default:''"`
	// TeamID and KeyID identify the private key of an Apple client, which is
	// stored as its client secret
	TeamID string `gorm:"not null;default:''"`
	KeyID  string `gorm:"not null;default:''"`
}
