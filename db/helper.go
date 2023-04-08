package db

import (
	"fmt"

	"github.com/alexhokl/helper/iohelper"
	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func GetDatabaseConnection() (*gorm.DB, error) {
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

	conn, err := gorm.Open(postgres.Open(connectionString), &gorm.Config{})
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
