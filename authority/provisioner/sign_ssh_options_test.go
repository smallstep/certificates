package provisioner

import (
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/keys"
	"golang.org/x/crypto/ssh"
)

func Test_sshCertificateDefaultValidator_Valid(t *testing.T) {
	pub, _, err := keys.GenerateDefaultKeyPair()
	assert.FatalError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	assert.FatalError(t, err)
	v := sshCertificateDefaultValidator{}
	tests := []struct {
		name string
		cert *ssh.Certificate
		err  error
	}{
		{
			"fail/zero-nonce",
			&ssh.Certificate{},
			errors.New("ssh certificate nonce cannot be empty"),
		},
		{
			"fail/nil-key",
			&ssh.Certificate{Nonce: []byte("foo")},
			errors.New("ssh certificate key cannot be nil"),
		},
		{
			"fail/zero-serial",
			&ssh.Certificate{Nonce: []byte("foo"), Key: sshPub},
			errors.New("ssh certificate serial cannot be 0"),
		},
		{
			"fail/unexpected-cert-type",
			// UserCert = 1, HostCert = 2
			&ssh.Certificate{Nonce: []byte("foo"), Key: sshPub, CertType: 3, Serial: 1},
			errors.New("ssh certificate has an unknown type: 3"),
		},
		{
			"fail/empty-cert-key-id",
			&ssh.Certificate{Nonce: []byte("foo"), Key: sshPub, Serial: 1, CertType: 1},
			errors.New("ssh certificate key id cannot be empty"),
		},
		{
			"fail/empty-valid-principals",
			&ssh.Certificate{Nonce: []byte("foo"), Key: sshPub, Serial: 1, CertType: 1, KeyId: "foo"},
			errors.New("ssh certificate valid principals cannot be empty"),
		},
		{
			"fail/zero-validAfter",
			&ssh.Certificate{
				Nonce:           []byte("foo"),
				Key:             sshPub,
				Serial:          1,
				CertType:        1,
				KeyId:           "foo",
				ValidPrincipals: []string{"foo"},
				ValidAfter:      0,
			},
			errors.New("ssh certificate validAfter cannot be 0"),
		},
		{
			"fail/validBefore-past",
			&ssh.Certificate{
				Nonce:           []byte("foo"),
				Key:             sshPub,
				Serial:          1,
				CertType:        1,
				KeyId:           "foo",
				ValidPrincipals: []string{"foo"},
				ValidAfter:      uint64(time.Now().Add(-10 * time.Minute).Unix()),
				ValidBefore:     uint64(time.Now().Add(-5 * time.Minute).Unix()),
			},
			errors.New("ssh certificate validBefore cannot be in the past"),
		},
		{
			"fail/validAfter-after-validBefore",
			&ssh.Certificate{
				Nonce:           []byte("foo"),
				Key:             sshPub,
				Serial:          1,
				CertType:        1,
				KeyId:           "foo",
				ValidPrincipals: []string{"foo"},
				ValidAfter:      uint64(time.Now().Add(15 * time.Minute).Unix()),
				ValidBefore:     uint64(time.Now().Add(10 * time.Minute).Unix()),
			},
			errors.New("ssh certificate validBefore cannot be before validAfter"),
		},
		{
			"fail/empty-extensions",
			&ssh.Certificate{
				Nonce:           []byte("foo"),
				Key:             sshPub,
				Serial:          1,
				CertType:        1,
				KeyId:           "foo",
				ValidPrincipals: []string{"foo"},
				ValidAfter:      uint64(time.Now().Unix()),
				ValidBefore:     uint64(time.Now().Add(10 * time.Minute).Unix()),
			},
			errors.New("ssh certificate extensions cannot be empty"),
		},
		{
			"fail/nil-signature-key",
			&ssh.Certificate{
				Nonce:           []byte("foo"),
				Key:             sshPub,
				Serial:          1,
				CertType:        1,
				KeyId:           "foo",
				ValidPrincipals: []string{"foo"},
				ValidAfter:      uint64(time.Now().Unix()),
				ValidBefore:     uint64(time.Now().Add(10 * time.Minute).Unix()),
				Permissions: ssh.Permissions{
					Extensions: map[string]string{"foo": "bar"},
				},
			},
			errors.New("ssh certificate signature key cannot be nil"),
		},
		{
			"fail/nil-signature",
			&ssh.Certificate{
				Nonce:           []byte("foo"),
				Key:             sshPub,
				Serial:          1,
				CertType:        1,
				KeyId:           "foo",
				ValidPrincipals: []string{"foo"},
				ValidAfter:      uint64(time.Now().Unix()),
				ValidBefore:     uint64(time.Now().Add(10 * time.Minute).Unix()),
				Permissions: ssh.Permissions{
					Extensions: map[string]string{"foo": "bar"},
				},
				SignatureKey: sshPub,
			},
			errors.New("ssh certificate signature cannot be nil"),
		},
		{
			"ok/userCert",
			&ssh.Certificate{
				Nonce:           []byte("foo"),
				Key:             sshPub,
				Serial:          1,
				CertType:        1,
				KeyId:           "foo",
				ValidPrincipals: []string{"foo"},
				ValidAfter:      uint64(time.Now().Unix()),
				ValidBefore:     uint64(time.Now().Add(10 * time.Minute).Unix()),
				Permissions: ssh.Permissions{
					Extensions: map[string]string{"foo": "bar"},
				},
				SignatureKey: sshPub,
				Signature:    &ssh.Signature{},
			},
			nil,
		},
		{
			"ok/hostCert",
			&ssh.Certificate{
				Nonce:           []byte("foo"),
				Key:             sshPub,
				Serial:          1,
				CertType:        2,
				KeyId:           "foo",
				ValidPrincipals: []string{"foo"},
				ValidAfter:      uint64(time.Now().Unix()),
				ValidBefore:     uint64(time.Now().Add(10 * time.Minute).Unix()),
				SignatureKey:    sshPub,
				Signature:       &ssh.Signature{},
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := v.Valid(tt.cert); err != nil {
				if assert.NotNil(t, tt.err) {
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			} else {
				assert.Nil(t, tt.err)
			}
		})
	}
}
