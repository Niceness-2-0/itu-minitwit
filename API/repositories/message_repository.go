package repositories

import (
	"api/models"

	"gorm.io/gorm"
)

type messageRepository struct {
	db *gorm.DB
}

func NewMessageRepository(db *gorm.DB) MessageRepository {
	return &messageRepository{db: db}
}

func (r *messageRepository) Create(message *models.Message) error {
	return r.db.Create(message).Error
}

func (r *messageRepository) GetLatest(limit int) ([]models.Message, error) {
	var messages []models.Message
	err := r.db.Preload("User").
		Where("flagged = ?", false).
		Order("pub_date DESC").
		Limit(limit).
		Find(&messages).Error
	return messages, err
}

func (r *messageRepository) GetByUserID(userID uint, limit int) ([]models.Message, error) {
	var messages []models.Message
	err := r.db.Where("author_id = ?", userID).
		Preload("User").
		Order("pub_date DESC").
		Limit(limit).
		Find(&messages).Error
	return messages, err
}
