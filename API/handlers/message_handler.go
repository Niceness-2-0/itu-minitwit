package handlers

import (
	"api/repositories"
)

// MessageHandler handles message-related endpoints
type MessageHandler struct {
	MessageRepo *repositories.MessageRepository
	UserRepo    *repositories.UserRepository
}

// NewMessageHandler initializes a new MessageHandler
func NewMessageHandler(msgRepo *repositories.MessageRepository, userRepo *repositories.UserRepository) *MessageHandler {
	return &MessageHandler{MessageRepo: msgRepo, UserRepo: userRepo}
}
