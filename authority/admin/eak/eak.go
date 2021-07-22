package eak

import "time"

type ExternalAccountKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AccountID string    `json:"-"`
	KeyBytes  []byte    `json:"-"`
	CreatedAt time.Time `json:"createdAt"`
	BoundAt   time.Time `json:"boundAt,omitempty"`
}
