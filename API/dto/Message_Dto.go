// /internal/api/dto/message_dto.go

package dto

// MessageDTO is a Data Transfer Object for the message response
type MessageDTO struct {
	Text     string `json:"content"`
	PubDate  int64  `json:"pub_date"`
	Username string `json:"user"`
}
