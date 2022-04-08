package provisioner

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/smallstep/assert"
)

func Test_noop(t *testing.T) {
	p := noop{}
	assert.Equals(t, "noop", p.GetID())
	assert.Equals(t, "noop", p.GetName())
	assert.Equals(t, noopType, p.GetType())
	assert.Equals(t, nil, p.Init(Config{}))
	assert.Equals(t, nil, p.AuthorizeRenew(context.Background(), &x509.Certificate{}))
	assert.Equals(t, nil, p.AuthorizeRevoke(context.Background(), "foo"))

	kid, key, ok := p.GetEncryptedKey()
	assert.Equals(t, "", kid)
	assert.Equals(t, "", key)
	assert.Equals(t, false, ok)

	ctx := NewContextWithMethod(context.Background(), SignMethod)
	sigOptions, err := p.AuthorizeSign(ctx, "foo")
	assert.Equals(t, []SignOption{&p}, sigOptions)
	assert.Equals(t, nil, err)
}
