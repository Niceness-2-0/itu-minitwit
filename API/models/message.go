package models

// Message represents a message in the system
type Message struct {
	ID       uint   `gorm:"primaryKey;column:message_id"`
	AuthorID uint   `gorm:"column:author_id"`
	Content  string `gorm:"column:text"`
	PubDate  int64  `gorm:"column:pub_date"`
	Flagged  int32  `gorm:"column:flagged"`
}

// TableName overrides the table name used by GORM
func (Message) TableName() string {
	return "message"
}
