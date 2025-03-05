package models

// password should be incripted, kinda see this working first tho
// `gorm:"column:pw_hash"`

type User struct {
	ID       uint   `gorm:"primaryKey;column:user_id"`
	Username string `gorm:"uniqueIndex;size:255"`
	Email    string
	Password string
}

type Message struct {
	ID      uint   `gorm:"primaryKey;column:message_id"`
	Content string `gorm:"type:text"`
	PubDate int64
	Flagged bool
	UserID  uint `gorm:"column:author_id"`
	User    User `gorm:"foreignKey:UserID"`
}

type Follower struct {
	WhoID  uint `gorm:"primaryKey;column:who_id"`
	WhomID uint `gorm:"primaryKey;column:whom_id"`
}
