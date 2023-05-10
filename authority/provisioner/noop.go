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

func (p *noop) GetTokenID(string) (string, error) {
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

func (p *noop) Init(Config) error {
	return nil
}

func (p *noop) AuthorizeSign(context.Context, string) ([]SignOption, error) {
	return []SignOption{p}, nil
}

func (p *noop) AuthorizeRenew(context.Context, *x509.Certificate) error {
	return nil
}

func (p *noop) AuthorizeRevoke(context.Context, string) error {
	return nil
}

func (p *noop) AuthorizeSSHSign(context.Context, string) ([]SignOption, error) {
	return []SignOption{p}, nil
}

func (p *noop) AuthorizeSSHRenew(context.Context, string) (*ssh.Certificate, error) {
	//nolint:nilnil // fine for noop
	return nil, nil
}

func (p *noop) AuthorizeSSHRevoke(context.Context, string) error {
	return nil
}

func (p *noop) AuthorizeSSHRekey(context.Context, string) (*ssh.Certificate, []SignOption, error) {
	return nil, []SignOption{}, nil
}
