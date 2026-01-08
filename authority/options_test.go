package authority

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/stretchr/testify/assert"
)

func TestWithConfig(t *testing.T) {
	cfg := &config.Config{
		Root:             []string{"test-root"},
		IntermediateCert: "test-cert",
		IntermediateKey:  "test-key",
	}

	a := &Authority{}
	option := WithConfig(cfg)

	err := option(a)
	assert.NoError(t, err)
	assert.Equal(t, cfg, a.config)
}

func TestWithConfigFile(t *testing.T) {
	// Test with non-existent file
	a := &Authority{}
	option := WithConfigFile("non-existent-file.json")

	err := option(a)
	assert.Error(t, err)

	// Test with invalid path
	option = WithConfigFile("")
	err = option(a)
	assert.Error(t, err)
}

func TestWithPassword(t *testing.T) {
	password := []byte("test-password")
	a := &Authority{}
	option := WithPassword(password)

	err := option(a)
	assert.NoError(t, err)
	assert.Equal(t, password, a.password)
}

func TestWithDatabase(t *testing.T) {
	// Test with nil database
	a := &Authority{}
	option := WithDatabase(nil)

	err := option(a)
	assert.NoError(t, err)
	assert.Nil(t, a.db)
}

func TestWithGetIdentityFunc(t *testing.T) {
	mockFunc := func(ctx context.Context, p provisioner.Interface, email string) (*provisioner.Identity, error) {
		return nil, nil
	}

	a := &Authority{}
	option := WithGetIdentityFunc(mockFunc)

	err := option(a)
	assert.NoError(t, err)
	assert.NotNil(t, a.getIdentityFunc)
}

func TestWithAuthorizeRenewFunc(t *testing.T) {
	mockFunc := func(ctx context.Context, p *provisioner.Controller, cert *x509.Certificate) error {
		return nil
	}

	a := &Authority{}
	option := WithAuthorizeRenewFunc(mockFunc)

	err := option(a)
	assert.NoError(t, err)
	assert.NotNil(t, a.authorizeRenewFunc)
}

func TestWithX509Signer(t *testing.T) {
	a := &Authority{}

	// Test that WithX509Signer with nil values returns an error
	option := WithX509Signer(nil, nil)
	err := option(a)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signer")
}

func TestWithX509RootCerts(t *testing.T) {
	certs := []*x509.Certificate{}
	a := &Authority{}
	option := WithX509RootCerts(certs...)

	err := option(a)
	assert.NoError(t, err)
	assert.Equal(t, certs, a.rootX509Certs)
}

func TestWithX509FederatedCerts(t *testing.T) {
	certs := []*x509.Certificate{}
	a := &Authority{}
	option := WithX509FederatedCerts(certs...)

	err := option(a)
	assert.NoError(t, err)
	assert.Equal(t, certs, a.federatedX509Certs)
}
