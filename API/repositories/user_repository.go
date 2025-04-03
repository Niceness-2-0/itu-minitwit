package repositories

import (
	"api/models"
	"errors"

	"gorm.io/gorm"
)

type UserRepository struct {
	DB *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{DB: db}
}

// Check if a user exists by username
func (repo *UserRepository) UserExists(username string) (bool, error) {
	var count int64
	err := repo.DB.Model(&models.User{}).Where("username = ?", username).Count(&count).Error
	return count > 0, err
}

// Create a new user
func (repo *UserRepository) CreateUser(user *models.User) error {
	return repo.DB.Create(user).Error
}

// GetUserID fetches the user ID based on username
func (repo *UserRepository) GetUserID(username string) (uint, error) {
	var user models.User
	err := repo.DB.Table("user").Select("user_id").Where("username = ?", username).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, err // User not found
	}

	return user.User_Id, err
}

// Follow a user
func (repo *UserRepository) FollowUser(whoID, whomID uint) error {
	follow := models.Follow{WhoID: whoID, WhomID: whomID}
	return repo.DB.Create(&follow).Error
}

// Unfollow a user
func (repo *UserRepository) UnfollowUser(whoID, whomID uint) error {
	return repo.DB.Where("who_id = ? AND whom_id = ?", whoID, whomID).Delete(&models.Follow{}).Error
}

// Get followers of a user
func (repo *UserRepository) GetFollowers(userID uint, limit int) ([]string, error) {
	var followers []string
	err := repo.DB.Table("\"user\"").
		Select("\"user\".username").
		Joins("INNER JOIN follower ON follower.whom_id = \"user\".user_id").
		Where("follower.who_id = ?", userID).
		Limit(limit).
		Pluck("username", &followers).Error
	return followers, err
}
