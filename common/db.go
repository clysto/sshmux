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

type TargetGroup struct {
	gorm.Model
	Title        string
	Description  string
	DisplayOrder int
	Targets      []Target `gorm:"constraint:OnDelete:SET NULL;"`
}

type Target struct {
	gorm.Model
	Name          string `gorm:"unique"`
	Description   string
	Host          string
	Port          int32
	User          string
	DisplayOrder  int
	TargetGroup   TargetGroup
	TargetGroupID *uint
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
	IP       string
	Status   int
	User     User   `gorm:"constraint:OnDelete:SET NULL;"`
	Target   Target `gorm:"constraint:OnDelete:SET NULL;"`
}
