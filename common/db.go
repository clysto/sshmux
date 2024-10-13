package common

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username       string `gorm:"unique"`
	Password       string
	IsAdmin        bool
	SSOCredentials []SSOCredential
	Pubkeys        []Pubkey
}

type SSOCredential struct {
	gorm.Model
	ProviderName string
	Subject      string
	UserID       uint
}

type Target struct {
	gorm.Model
	Name string `gorm:"unique"`
	Host string
	Port int32
	User string
}

type Pubkey struct {
	gorm.Model
	UserId uint
	Key    string
}
