package db

import (
	"fmt"

	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func GetDatabaseConnection() (*gorm.DB, error) {
	connectionString := viper.GetString("database_connection_string")
	if connectionString == "" {
		return nil, fmt.Errorf("database connection string is not set")
	}
	conn, err := gorm.Open(postgres.Open(connectionString), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return conn, nil
}
