package repositories

import (
	"api/models"

	"gorm.io/gorm"
)

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) FindByUsername(username string) (*models.User, error) {
	var user models.User
	err := r.db.Where("username = ?", username).First(&user).Error
	return &user, err
}

func (r *userRepository) Create(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *userRepository) Follow(followerID, followeeID uint) error {
	return r.db.Create(&models.Follower{
		WhoID:  followerID,
		WhomID: followeeID,
	}).Error
}

func (r *userRepository) Unfollow(followerID, followeeID uint) error {
	return r.db.Where("who_id = ? AND whom_id = ?", followerID, followeeID).
		Delete(&models.Follower{}).Error
}

func (r *userRepository) GetFollowers(userID uint) ([]models.User, error) {
	var followers []models.User
	err := r.db.Joins("JOIN followers ON users.user_id = followers.who_id").
		Where("followers.whom_id = ?", userID).
		Find(&followers).Error
	return followers, err
}

func (r *userRepository) Exists(username string) (bool, error) {
	var count int64
	err := r.db.Model(&models.User{}).
		Where("username = ?", username).
		Count(&count).Error
	return count > 0, err
}
