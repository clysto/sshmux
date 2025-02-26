package common

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type API struct {
	db *gorm.DB
}

type TargetHealth struct {
	TargetID uint
	Up       bool
	Time     time.Time
}

func NewAPI(dbPath string) (*API, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&Target{}, &Pubkey{}, &SSOCredential{}, &User{}, &Recording{}); err != nil {
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

func (api *API) SearchTargets(q string) []Target {
	var targets []Target
	api.db.Where("name LIKE ?", "%"+q+"%").Find(&targets)
	return targets
}

func (api *API) CreateTarget(target Target) error {
	r := regexp.MustCompile("^[a-zA-Z0-9_-]+$")
	if !r.MatchString(target.Name) {
		return errors.New("target name must only contain alphanumeric characters, dashes, and underscores")
	}
	return api.db.Create(&target).Error
}

func (api *API) DeleteTargetId(id int) error {
	return api.db.Unscoped().Where("id = ?", id).Delete(&Target{}).Error
}

func (api *API) UpdateTarget(target Target) error {
	r := regexp.MustCompile("^[a-zA-Z0-9_-]+$")
	if !r.MatchString(target.Name) {
		return errors.New("target name must only contain alphanumeric characters, dashes, and underscores")
	}
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

func (api *API) PubkeyUsedAt(pubkey Pubkey) {
	api.db.Save(&pubkey)
}

func (api *API) GetUserByName(username string) *User {
	var user User
	if api.db.Where("username = ?", username).First(&user).Error != nil {
		return nil
	}
	return &user
}

func (api *API) GetUserBySSO(providerName, subject string) *User {
	var user User

	err := api.db.Joins("JOIN sso_credentials ON sso_credentials.user_id = users.id").
		Where("sso_credentials.provider_name = ? AND sso_credentials.subject = ?", providerName, subject).
		First(&user).Error

	if err != nil {
		return nil
	}

	user.LastLoginAt = time.Now()

	if err := api.db.Save(&user).Error; err != nil {
		return &user
	}

	return &user
}

func (api *API) CreateUser(user User) error {
	return api.db.Create(&user).Error
}

func (api *API) UpdateUser(user User) error {
	return api.db.Save(&user).Error
}

func (api *API) UserExists(username string) bool {
	var user User
	return api.db.Where("username = ?", username).First(&user).Error == nil
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

	user.LastLoginAt = time.Now()

	if err := api.db.Save(&user).Error; err != nil {
		return &user, nil
	}

	return &user, nil
}

func TestSSHConnection(target Target) bool {
	timeout := 5 * time.Second
	address := net.JoinHostPort(target.Host, fmt.Sprint(target.Port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	serverResponse, err := reader.ReadString('\n')

	if err != nil {
		return false
	}
	if strings.HasPrefix(serverResponse, "SSH") {
		return true
	}

	return false
}

func (api *API) CreateRecording(recording Recording) error {
	return api.db.Create(&recording).Error
}

func (api *API) ListRecordings(pageSize int, pageNum int) ([]Recording, bool) {
	var recordings []Recording

	api.db.Preload("User").Preload("Target").
		Limit(pageSize).
		Offset(pageSize * (pageNum - 1)).
		Order("created_at desc").
		Find(&recordings)

	var totalRecordingsCount int64
	api.db.Model(&Recording{}).Count(&totalRecordingsCount)

	hasMore := (pageNum * pageSize) < int(totalRecordingsCount)

	return recordings, hasMore
}

func (api *API) SearchRecordings(pageSize int, pageNum int, user string, target string, after *time.Time, before *time.Time) ([]Recording, bool) {
	var recordings []Recording
	query := api.db.Model(&Recording{}).Joins("User").Joins("Target")

	if after != nil {
		query = query.Where("recordings.created_at >= ?", *after)
	}

	if before != nil {
		query = query.Where("recordings.created_at <= ?", *before)
	}

	if user != "" {
		query = query.Where("User.username LIKE ?", "%"+user+"%")
	}

	if target != "" {
		query = query.Where("Target.name LIKE ?", "%"+target+"%")
	}

	var totalRecordingsCount int64
	query.Count(&totalRecordingsCount)
	query.Limit(pageSize).Offset(pageSize * (pageNum - 1)).Order("recordings.created_at desc").Find(&recordings)

	hasMore := (pageNum * pageSize) < int(totalRecordingsCount)

	return recordings, hasMore
}

func (api *API) GetRecordingById(id string) *Recording {
	var recording Recording
	if api.db.Preload("User").Preload("Target").First(&recording, "id = ?", id).Error != nil {
		return nil
	}
	return &recording
}

func (api *API) DeleteOldRecordings(before time.Time, recorddir string) error {
	var recordings []Recording
	api.db.Where("created_at < ?", before).Find(&recordings)
	for _, recording := range recordings {
		f := path.Join(recorddir, recording.RecordID)
		_ = os.RemoveAll(f)
	}
	return api.db.Unscoped().Where("created_at < ?", before).Delete(&Recording{}).Error
}

func (api *API) ListUsers(pageSize int, pageNum int) ([]User, bool) {
	var users []User

	api.db.Limit(pageSize).
		Offset(pageSize * (pageNum - 1)).
		Order("created_at asc").
		Preload("SSOCredentials").
		Find(&users)

	var totalUsersCount int64
	api.db.Model(&User{}).Count(&totalUsersCount)

	hasMore := (pageNum * pageSize) < int(totalUsersCount)

	return users, hasMore
}

func (api *API) DeleteUserById(id int) error {
	return api.db.Unscoped().Select(clause.Associations).Delete(&User{
		Model: gorm.Model{ID: uint(id)},
	}).Error
}

func (api *API) GetUserById(id int) *User {
	var user User
	if api.db.Preload("SSOCredentials").First(&user, id).Error != nil {
		return nil
	}
	return &user
}

func (api *API) CheckTargetHealth(result *[]TargetHealth) {
	now := time.Now()
	targets := api.ListTargets()

	// Remove old statuses
	for index, status := range *result {
		if now.Sub(status.Time) <= 8*time.Hour {
			*result = (*result)[index:]
			break
		}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// Iterate over targets and check health concurrently
	for _, target := range targets {
		wg.Add(1)

		// Launch a goroutine for each target
		go func(t Target) {
			defer wg.Done()

			up := TestSSHConnection(t)

			// Lock before appending to the shared slice
			mu.Lock()
			*result = append(*result, TargetHealth{
				TargetID: t.ID,
				Up:       up,
				Time:     now,
			})
			mu.Unlock()
		}(target)
	}

	wg.Wait()
}
