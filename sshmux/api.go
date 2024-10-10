package sshmux

import (
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type API struct {
	db *gorm.DB
}

func NewAPI(dbPath string) (*API, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&Target{}, &Pubkey{}); err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&Pubkey{}); err != nil {
		return nil, err
	}
	return &API{db: db}, nil
}

func (api *API) GetTargetByName(name string) *Target {
	var target Target
	if api.db.Where("name = ?", name).First(&target).Error != nil {
		return nil
	}
	return &target
}

func (api *API) GetTargetById(id int) *Target {
	var target Target
	if api.db.Where("id = ?", id).First(&target).Error != nil {
		return nil
	}
	return &target
}

func (api *API) ListTargets() []Target {
	var targets []Target
	api.db.Find(&targets)
	return targets
}

func (api *API) CreateTarget(target Target) error {
	return api.db.Create(&target).Error
}

func (api *API) DeleteTargetId(id int) error {
	return api.db.Where("id = ?", id).Delete(&Target{}).Error
}

func (api *API) UpdateTarget(target Target) error {
	return api.db.Save(&target).Error
}

func (api *API) GetPubkeysByUser(user string) []Pubkey {
	var pubkeys []Pubkey
	api.db.Where("user = ?", user).Find(&pubkeys)
	return pubkeys
}

func (api *API) CreatePubkey(pubkey Pubkey) error {
	return api.db.Create(&pubkey).Error
}

func (api *API) DeletePubkeyById(id int) error {
	return api.db.Unscoped().Where("id = ?", id).Delete(&Pubkey{}).Error
}

func (api *API) GetPubkeyById(id int) *Pubkey {
	var pubkey Pubkey
	if api.db.Where("id = ?", id).First(&pubkey).Error != nil {
		return nil
	}
	return &pubkey
}
