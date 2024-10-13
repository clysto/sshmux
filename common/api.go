package common

import (
	"errors"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
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
	if err := db.AutoMigrate(&Target{}, &Pubkey{}, &SSOCredential{}, &User{}); err != nil {
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

func (api *API) GetPubkeysByUserID(userID uint) []Pubkey {
	var pubkeys []Pubkey
	api.db.Where("user_id = ?", userID).Find(&pubkeys)
	return pubkeys
}

func (api *API) GetPubkeysByUsername(username string) []Pubkey {
	var pubkeys []Pubkey
	api.db.Joins("JOIN users ON users.id = pubkeys.user_id").Where("users.username = ?", username).Find(&pubkeys)
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

func (api *API) GetUserBySSO(providerName, subject string) *User {
	var user User

	err := api.db.Joins("JOIN sso_credentials ON sso_credentials.user_id = users.id").
		Where("sso_credentials.provider_name = ? AND sso_credentials.subject = ?", providerName, subject).
		First(&user).Error

	if err != nil {
		return nil
	}

	return &user
}

func (api *API) CreateUser(user User) error {
	return api.db.Create(&user).Error
}

func (api *API) Login(username, password string) (*User, error) {
	var user User

	if err := api.db.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("invalid password")
	}

	return &user, nil
}
