package db

type User struct {
	Email        string `gorm:"primary_key;unique;not null"`
	PasswordHash string `gorm:"not null"`
}

type Client struct {
	ClientID     string `gorm:"primary_key;unique;not null"`
	ClientSecret string `gorm:"not null"`
	RedirectURI  string
	IsPublic     bool
	UserEmail    string    `gorm:"not null"`
	User         User `gorm:"foreignKey:UserEmail"`
}
