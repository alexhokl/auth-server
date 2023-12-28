package db

import (
	"database/sql"
	"fmt"

	"github.com/alexhokl/helper/iohelper"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func GetDatabaseDailector() (gorm.Dialector, error) {
	path := viper.GetString("database_connection_string_file_path")
	if path == "" {
		return nil, fmt.Errorf("file path to database connection string is not set")
	}
	connectionString, err := iohelper.ReadFirstLineFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read password: %w", err)
	}
	if connectionString == "" {
		return nil, fmt.Errorf("database connection string is empty")
	}

	return postgres.Open(connectionString), nil
}

func GetDatabaseDialectorFromConnection(conn *sql.DB) gorm.Dialector {
	return postgres.New(postgres.Config{
		Conn: conn,
		DriverName: "postgres",
	})
}

func GetDatabaseConnection(dialector gorm.Dialector) (*gorm.DB, error) {
	conn, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func Migrate(db *gorm.DB) {
	db.AutoMigrate(&User{})
	db.AutoMigrate(&Client{})
	db.AutoMigrate(&UserCredential{})
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
