package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func Migrate(db *gorm.DB) {
	db.AutoMigrate(&User{})
	db.AutoMigrate(&Client{})
	db.AutoMigrate(&UserCredential{})
	db.AutoMigrate(&UserRole{})
	db.AutoMigrate(&UserConfirmation{})
	db.AutoMigrate(&Role{})
	if err := db.AutoMigrate(&Scope{}); err == nil && db.Migrator().HasTable(&Scope{}) {
		if err := db.First(&Scope{}).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			db.Create(&Scope{Name: "openid"})
			db.Create(&Scope{Name: "profile"})
			db.Create(&Scope{Name: "email"})
		}
	}
	db.AutoMigrate(&ClientScope{})
	db.AutoMigrate(&OidcClient{})
}

func ListUsers(db *gorm.DB) ([]User, error) {
	var users []User
	dbResult := db.Preload("Roles").Preload("Credentials").Find(&users)
	if dbResult.Error != nil {
		if dbResult.Error == gorm.ErrRecordNotFound {
			return users, nil
		}
		return nil, dbResult.Error
	}
	return users, nil
}

func GetUser(db *gorm.DB, email string) (*User, error) {
	var user User
	dbResult := db.Preload(clause.Associations).First(&user, "email = ?", email)
	if dbResult.Error != nil {
		if dbResult.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, dbResult.Error
	}
	return &user, nil
}

func HasUsers(db *gorm.DB) (bool, error) {
	var count int64
	dbResult := db.Model(&User{}).Count(&count)
	if dbResult.Error != nil {
		return false, dbResult.Error
	}
	return count > 0, nil
}

func CreateUser(db *gorm.DB, user *User) error {
	if dbResult := db.Create(user); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func CreateCredential(db *gorm.DB, credential *UserCredential) error {
	if dbResult := db.Create(credential); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func GetCredentialDescriptors(db *gorm.DB, email string) ([]protocol.CredentialDescriptor, error) {
	var credentials []UserCredential
	dbResult := db.Where("user_email = ?", email).Find(&credentials)
	if dbResult.Error != nil {
		if dbResult.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, dbResult.Error
	}
	var credentialDescriptors []protocol.CredentialDescriptor
	for _, credential := range credentials {
		credentialDescriptors = append(credentialDescriptors, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: credential.ID,
			AttestationType: credential.AttestationType,
			Transport:   credential.Transport,
		})
	}
	return credentialDescriptors, nil
}

func GetCredentials(db *gorm.DB, email string) ([]UserCredential, error) {
	var credentials []UserCredential
	dbResult := db.Where("user_email = ?", email).Find(&credentials)
	if dbResult.Error != nil {
		if dbResult.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, dbResult.Error
	}

	return credentials, nil
}

func GetCredentialNames(db *gorm.DB, email string) ([]string, error) {
	var credentials []UserCredential
	dbResult := db.Where("user_email = ?", email).Find(&credentials)
	if dbResult.Error != nil {
		if dbResult.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, dbResult.Error
	}
	var names []string
	for _, credential := range credentials {
		names = append(names, credential.FriendlyName)
	}
	return names, nil
}

func DeleteCredential(db *gorm.DB, email string, id []byte) error {
	var credential UserCredential
	searchResult := db.Where("user_email = ? AND id = ?", email, id).First(&credential)
	if searchResult.Error != nil {
		if searchResult.Error == gorm.ErrRecordNotFound {
			return fmt.Errorf("credential not found")
		}
		return searchResult.Error
	}
	dbResult := db.Delete(credential)
	if dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func UpdateCredential(db *gorm.DB, email string, id []byte, friendlyName string) error {
	var credential UserCredential
	searchResult := db.Where("user_email = ? AND id = ?", email, id).First(&credential)
	if searchResult.Error != nil {
		if searchResult.Error == gorm.ErrRecordNotFound {
			return fmt.Errorf("credential not found")
		}
		return searchResult.Error
	}
	credential.FriendlyName = friendlyName
	dbResult := db.Save(credential)
	if dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func CreateRole(db *gorm.DB, role *Role) error {
	if dbResult := db.Create(role); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func HasRole(db *gorm.DB, email string, name string) bool {
	var count int64
	dbResult := db.Model(&UserRole{}).Where("user_email = ? AND role_name = ?", email, name).Count(&count)
	if dbResult.Error != nil {
		return false
	}
	return count > 0
}

func GetClients(db *gorm.DB) ([]Client, error) {
	var clients []Client
	dbResult := db.Find(&clients)
	if dbResult.Error != nil {
		if dbResult.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, dbResult.Error
	}
	return clients, nil
}

func GetClient(db *gorm.DB, clientID string) (*Client, error) {
	var client Client
	if err := db.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &client, nil
}

func CreateClient(db *gorm.DB, client *Client) error {
	if dbResult := db.Create(client); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func UpdateClient(db *gorm.DB, client *Client) error {
	if dbResult := db.Save(client); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func ExpireAllConfirmation(db *gorm.DB, email string) error {
	timeNow := time.Now().Unix()
	dbResult := db.Model(&UserConfirmation{}).Where("user_email = ? AND confirmed_time = ?", email, 0).Update("confirmed_time", timeNow)
	if dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func CreateConfirmation(db *gorm.DB, confirmation *UserConfirmation) error {
	if dbResult := db.Create(confirmation); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func GetConfirmation(db *gorm.DB, otp string) (*UserConfirmation, error) {
	var confirmation UserConfirmation
	if err := db.Where("one_time_password = ?", otp).First(&confirmation).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &confirmation, nil
}

func ConfirmUser(db *gorm.DB, confirmation *UserConfirmation) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&UserConfirmation{}).Where("one_time_password = ?", confirmation.OneTimePassword).Update("confirmed_time", time.Now().Unix()).Error; err != nil {
			return err
		}
		if err := tx.Model(&User{}).Where("email = ?", confirmation.UserEmail).Update("is_enabled", true).Error; err != nil {
			return err
		}
		return nil
	})
}

func ChangePassword(db *gorm.DB, email string, passwordHash []byte) error {
	if dbResult := db.Model(&User{}).Where("email = ?", email).Update("password_hash", passwordHash); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func CreateScope(db *gorm.DB, scope string) error {
	if dbResult := db.Create(&Scope{Name: scope}); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func ListScopes(db *gorm.DB) ([]string, error) {
	var scopes []Scope
	dbResult := db.Find(&scopes)
	if dbResult.Error != nil {
		if dbResult.Error == gorm.ErrRecordNotFound {
			return []string{}, nil
		}
		return nil, dbResult.Error
	}
	var scopeNames []string
	for _, scope := range scopes {
		scopeNames = append(scopeNames, scope.Name)
	}
	return scopeNames, nil
}

func DeleteScope(db *gorm.DB, scope string) error {
	if dbResult := db.Where("name = ?", scope).Delete(&Scope{}); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func IsScopeExist(db *gorm.DB, scope string) (bool, error) {
	var count int64
	dbResult := db.Model(&Scope{}).Where("name = ?", scope).Count(&count)
	if dbResult.Error != nil {
		return false, dbResult.Error
	}
	return count > 0, nil
}

func IsScopeInUse(db *gorm.DB, scope string) (bool, error) {
	var count int64
	dbResult := db.Model(&ClientScope{}).Where("scope_name = ?", scope).Count(&count)
	if dbResult.Error != nil {
		return false, dbResult.Error
	}
	return count > 0, nil
}

func CreateClientScope(db *gorm.DB, clientID string, scope string) error {
	if dbResult := db.Create(&ClientScope{ClientID: clientID, ScopeName: scope}); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func ListClientScopes(db *gorm.DB, clientID string) ([]string, error) {
	var clientScopes []ClientScope
	dbResult := db.Where("client_id = ?", clientID).Find(&clientScopes)
	if dbResult.Error != nil {
		if dbResult.Error == gorm.ErrRecordNotFound {
			return []string{}, nil
		}
		return nil, dbResult.Error
	}
	var scopeNames []string
	for _, clientScope := range clientScopes {
		scopeNames = append(scopeNames, clientScope.ScopeName)
	}
	return scopeNames, nil
}

func DeleteClientScope(db *gorm.DB, clientID string, scope string) error {
	if dbResult := db.Where("client_id = ? AND scope_name = ?", clientID, scope).Delete(&ClientScope{}); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func ListOIDCClients(db *gorm.DB) ([]OidcClient, error) {
	var clients []OidcClient
	dbResult := db.Find(&clients)
	if dbResult.Error != nil {
		if dbResult.Error == gorm.ErrRecordNotFound {
			return []OidcClient{}, nil
		}
		return nil, dbResult.Error
	}
	return clients, nil
}

func GetOIDCClient(db *gorm.DB, name string) (*OidcClient, error) {
	var client OidcClient
	if err := db.Where("name = ?", name).First(&client).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &client, nil
}

func CreateOIDCClient(db *gorm.DB, client *OidcClient) error {
	if dbResult := db.Create(client); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func UpdateOIDCClient(db *gorm.DB, client *OidcClient) error {
	if dbResult := db.Where("name = ?", client.Name).Updates(client); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}

func DeleteOIDCClient(db *gorm.DB, name string) error {
	if dbResult := db.Where("name = ?", name).Delete(&OidcClient{}); dbResult.Error != nil {
		return dbResult.Error
	}
	return nil
}
