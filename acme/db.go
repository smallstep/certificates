package acme

import "context"

// DB is the DB interface expected by the step-ca ACME API.
type DB interface {
	CreateAccount(ctx context.Context, acc *types.Account) (*types.Account, error)
	GetAccount(ctx context.Context, id string) (*types.Account, error)
	GetAccountByKeyID(ctx context.Context, kid string) (*types.Account, error)
	UpdateAccount(ctx context.Context, acc *types.Account) error

	CreateNonce(ctx context.Context) (types.Nonce, error)
	DeleteNonce(ctx context.Context, nonce types.Nonce) error

	CreateAuthorization(ctx context.Context, authz *types.Authorization) error
	GetAuthorization(ctx context.Context, id string) (*types.Authorization, error)
	UpdateAuthorization(ctx context.Context, authz *types.Authorization) error

	CreateCertificate(ctx context.Context, cert *types.Certificate) error
	GetCertificate(ctx context.Context, id string) (*types.Certificate, error)

	CreateChallenge(ctx context.Context, ch *types.Challenge) error
	GetChallenge(ctx context.Context, id, authzID string) (*types.Challenge, error)
	UpdateChallenge(ctx context.Context, ch *types.Challenge) error

	CreateOrder(ctx context.Context, o *types.Order) error
	DeleteOrder(ctx context.Context, id string) error
	GetOrder(ctx context.Context, id string) (*types.Order, error)
	GetOrdersByAccountID(ctx context.Context, accountID string) error
	UpdateOrder(ctx context.Context, o *types.Order) error
}
