package repositories

import "api/models"

type UserRepository interface {
	FindByUsername(username string) (*models.User, error)
	Create(user *models.User) error
	Follow(followerID, followeeID uint) error
	Unfollow(followerID, followeeID uint) error
	GetFollowers(userID uint) ([]models.User, error)
	Exists(username string) (bool, error)
}

type MessageRepository interface {
	Create(message *models.Message) error
	GetLatest(limit int) ([]models.Message, error)
	GetByUserID(userID uint, limit int) ([]models.Message, error)
}
