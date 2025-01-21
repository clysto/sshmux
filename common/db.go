package common

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username       string `gorm:"unique"`
	Password       string
	IsAdmin        bool
	SSOCredentials []SSOCredential
	Pubkeys        []Pubkey
	LastLoginAt    time.Time
}

type SSOCredential struct {
	gorm.Model
	ProviderName string
	Subject      string
	UserID       uint
}

type Target struct {
	gorm.Model
	Name        string `gorm:"unique"`
	Description string
	Host        string
	Port        int32
	User        string
}

type Pubkey struct {
	gorm.Model
	UserID uint
	Key    string
	UsedAt time.Time
}

type Recording struct {
	gorm.Model
	UserID   uint
	TargetID uint
	RecordID string
	User     User   `gorm:"constraint:OnDelete:SET NULL;"`
	Target   Target `gorm:"constraint:OnDelete:SET NULL;"`
}
