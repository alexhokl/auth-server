package db

import (
	"fmt"

	"github.com/alexhokl/helper/iohelper"
	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
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
