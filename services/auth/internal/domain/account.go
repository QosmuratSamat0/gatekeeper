package domain

import (
	"time"
)

// AccountStatus represents the administrative lifecycle status of an account.
type AccountStatus string

const (
	AccountStatusActive   AccountStatus = "active"
	AccountStatusDisabled AccountStatus = "disabled"
)

// Account represents the core registered identity entity.
// Notice: PasswordHash is explicitly omitted from JSON serialization to prevent accidental leakage.
type Account struct {
	ID            string        `json:"id"`
	Email         string        `json:"email"`
	PasswordHash  string        `json:"-"`
	Status        AccountStatus `json:"status"`
	EmailVerified bool          `json:"email_verified"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}
