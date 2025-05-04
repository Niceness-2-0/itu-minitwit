package repositories

import (
	"api/dto"
	"api/models"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type MessageRepository struct {
	DB *gorm.DB
}

func NewMessageRepository(db *gorm.DB) *MessageRepository {
	return &MessageRepository{DB: db}
}

// GetMessages fetches messages with the author's username
func (repo *MessageRepository) GetMessages(noMsgs int) ([]dto.MessageDTO, error) {
	var messages []dto.MessageDTO

	// Execute the query with joins and conditions
	err := repo.DB.Table("message").
		Select("message.text, message.pub_date, \"user\".username").Joins("JOIN \"user\" ON message.author_id = \"user\".user_id").
		Where("message.flagged = ?", 0).
		Order("message.pub_date DESC").
		Limit(noMsgs).
		Find(&messages).Error

	if err != nil {
		return nil, err
	}

	return messages, nil
}

func (repo *MessageRepository) GetMessagesPerUser(noMsgs int, id uint) ([]dto.MessageDTO, error) {
	var messages []dto.MessageDTO

	// Execute the query with joins and conditions
	err := repo.DB.Table("message").
		Select("message.text, message.pub_date, \"user\".username").Joins("JOIN \"user\" ON message.author_id = \"user\".user_id").
		Where("message.flagged = ?", 0).
		Where("\"user\".user_id = ?", id).
		Order("message.pub_date DESC").
		Limit(noMsgs).
		Find(&messages).Error

	if err != nil {
		return nil, err
	}

	return messages, nil
}

func (repo *MessageRepository) SaveMessage(message *models.Message) {
	err := repo.DB.Create(message).Error
	if err != nil {
		// Handle error
		logrus.WithFields(logrus.Fields{
			"message": message,
			"error":   err,
		}).Error("Failed to save message")
	}
}

// Get messages from users that the given user follows
func (repo *MessageRepository) GetFollowingMessages(userID uint, limit, offset int) ([]dto.MessageDTO, error) {
	var messages []dto.MessageDTO

	err := repo.DB.Table("message").
		Select("message.text, message.pub_date, \"user\".username").
		Joins("JOIN \"user\" ON message.author_id = \"user\".user_id").
		Where("message.flagged = ?", 0).
		Where("\"user\".user_id = ? OR \"user\".user_id IN (?)",
			userID,
			repo.DB.Table("follower").Select("whom_id").Where("who_id = ?", userID),
		).
		Order("message.pub_date DESC").
		Limit(limit).
		Offset(offset).
		Scan(&messages).Error

	return messages, err
}
