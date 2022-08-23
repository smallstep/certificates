package provisioner

import (
	"context"
	"crypto/x509"

	"golang.org/x/crypto/ssh"
)

// noop provisioners is a provisioner that accepts anything.
type noop struct{}

func (p *noop) GetID() string {
	return "noop"
}

func (p *noop) GetIDForToken() string {
	return "noop"
}

func (p *noop) GetTokenID(token string) (string, error) {
	return "", nil
}

func (p *noop) GetName() string {
	return "noop"
}
func (p *noop) GetType() Type {
	return noopType
}

func (p *noop) GetEncryptedKey() (kid, key string, ok bool) {
	return "", "", false
}

func (p *noop) Init(config Config) error {
	return nil
}

func (p *noop) AuthorizeSign(ctx context.Context, token string) ([]SignOption, error) {
	return []SignOption{p}, nil
}

func (p *noop) AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error {
	return nil
}

func (p *noop) AuthorizeRevoke(ctx context.Context, token string) error {
	return nil
}

func (p *noop) AuthorizeSSHSign(ctx context.Context, token string) ([]SignOption, error) {
	return []SignOption{p}, nil
}

func (p *noop) AuthorizeSSHRenew(ctx context.Context, token string) (*ssh.Certificate, error) {
	//nolint:nilnil // fine for noop
	return nil, nil
}

func (p *noop) AuthorizeSSHRevoke(ctx context.Context, token string) error {
	return nil
}

func (p *noop) AuthorizeSSHRekey(ctx context.Context, token string) (*ssh.Certificate, []SignOption, error) {
	return nil, []SignOption{}, nil
}
