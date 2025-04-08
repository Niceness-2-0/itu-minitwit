package models

import (
	"gorm.io/gorm"
)

// User represents a user in the database
type User struct {
	User_Id  uint   `gorm:"primaryKey"`
	Username string `gorm:"uniqueIndex"`
	Email    string
	PwHash   string `json:"pw_hash"`
}

// TableName overrides the table name used by User to `user`
func (User) TableName() string {
	// Specify the table name explicitly
	return "user"
}

// MigrateUser runs migrations for the User model
func MigrateUser(db *gorm.DB) error {
	return db.AutoMigrate(&User{})
}
