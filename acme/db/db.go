package acme

import "context"

// DB is the DB interface expected by the step-ca ACME API.
type DB interface {
	CreateAccount(ctx context.Context, acc *Account) (*Account, error)
	GetAccount(ctx context.Context, id string) (*Account, error)
	GetAccountByKeyID(ctx context.Context) (*Account, error)
	UpdateAccount(ctx context.Context, acc *Account) error

	CreateNonce(ctx context.Context) (Nonce, error)
	DeleteNonce(ctx context.Context, nonce Nonce) error

	CreateAuthorization(ctx context.Context, authz *Authorization) error
	GetAuthorization(ctx context.Context, id string) (*Authorization, error)
	UpdateAuthorization(ctx context.Context, authz *Authorization) error

	CreateCertificate(ctx context.Context, cert *Certificate) error
	GetCertificate(ctx context.Context, id string) (*Certificate, error)

	CreateChallenge(ctx context.Context, ch *Challenge) error
	GetChallenge(ctx context.Context, id string) (*Challenge, error)
	UpdateChallenge(ctx context.Context, ch *Challenge) error

	CreateOrder(ctx context.Context, o *Order) error
	DeleteOrder(ctx context.Context, id string) error
	GetOrder(ctx context.Context, id string) (*Order, error)
	GetOrdersByAccountID(ctx context.Context, accountID string) error
	UpdateOrder(ctx context.Context, o *Order) error
}
