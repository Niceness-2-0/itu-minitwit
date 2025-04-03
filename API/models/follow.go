package models

type Follow struct {
	WhoID  uint `gorm:"column:who_id"`
	WhomID uint `gorm:"column:whom_id"`
}

// TableName overrides the table name used by GORM
func (Follow) TableName() string {
	return "follower"
}
