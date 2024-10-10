package sshmux

import (
	"gorm.io/gorm"
)

type Target struct {
	gorm.Model
	Name string `gorm:"unique"`
	Host string
	Port int32
	User string
}

type Pubkey struct {
	gorm.Model
	User string
	Key  string
}
