package provisioner

import (
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"go.step.sm/crypto/keyutil"
	"golang.org/x/crypto/ssh"
)

func TestSSHOptions_Type(t *testing.T) {
	type fields struct {
		CertType string
	}
	tests := []struct {
		name   string
		fields fields
		want   uint32
	}{
		{"user", fields{"user"}, 1},
		{"host", fields{"host"}, 2},
		{"empty", fields{""}, 0},
		{"invalid", fields{"invalid"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := SignSSHOptions{
				CertType: tt.fields.CertType,
			}
			if got := o.Type(); got != tt.want {
				t.Errorf("SSHOptions.Type() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSHOptions_Modify(t *testing.T) {
	type test struct {
		so    SignSSHOptions
		cert  *ssh.Certificate
		valid func(*ssh.Certificate)
		err   error
	}
	tests := map[string]func() test{
		"fail/unexpected-cert-type": func() test {
			return test{
				so:   SignSSHOptions{CertType: "foo"},
				cert: new(ssh.Certificate),
				err:  errors.Errorf("ssh certificate has an unknown type 'foo'"),
			}
		},
		"fail/validAfter-greater-validBefore": func() test {
			return test{
				so:   SignSSHOptions{CertType: "user"},
				cert: &ssh.Certificate{ValidAfter: uint64(15), ValidBefore: uint64(10)},
				err:  errors.Errorf("ssh certificate validAfter cannot be greater than validBefore"),
			}
		},
		"ok/user-cert": func() test {
			return test{
				so:   SignSSHOptions{CertType: "user"},
				cert: new(ssh.Certificate),
				valid: func(cert *ssh.Certificate) {
					assert.Equals(t, cert.CertType, uint32(ssh.UserCert))
				},
			}
		},
		"ok/host-cert": func() test {
			return test{
				so:   SignSSHOptions{CertType: "host"},
				cert: new(ssh.Certificate),
				valid: func(cert *ssh.Certificate) {
					assert.Equals(t, cert.CertType, uint32(ssh.HostCert))
				},
			}
		},
		"ok": func() test {
			va := time.Now().Add(5 * time.Minute)
			vb := time.Now().Add(1 * time.Hour)
			so := SignSSHOptions{CertType: "host", KeyID: "foo", Principals: []string{"foo", "bar"},
				ValidAfter: NewTimeDuration(va), ValidBefore: NewTimeDuration(vb)}
			return test{
				so:   so,
				cert: new(ssh.Certificate),
				valid: func(cert *ssh.Certificate) {
					assert.Equals(t, cert.CertType, uint32(ssh.HostCert))
					assert.Equals(t, cert.KeyId, so.KeyID)
					assert.Equals(t, cert.ValidPrincipals, so.Principals)
					assert.Equals(t, cert.ValidAfter, uint64(so.ValidAfter.RelativeTime(time.Now()).Unix()))
					assert.Equals(t, cert.ValidBefore, uint64(so.ValidBefore.RelativeTime(time.Now()).Unix()))
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if err := tc.so.Modify(tc.cert, tc.so); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					tc.valid(tc.cert)
				}
			}
		})
	}
}

func TestSSHOptions_Match(t *testing.T) {
	type test struct {
		so  SignSSHOptions
		cmp SignSSHOptions
		err error
	}
	tests := map[string]func() test{
		"fail/cert-type": func() test {
			return test{
				so:  SignSSHOptions{CertType: "foo"},
				cmp: SignSSHOptions{CertType: "bar"},
				err: errors.Errorf("ssh certificate type does not match - got bar, want foo"),
			}
		},
		"fail/pricipals": func() test {
			return test{
				so:  SignSSHOptions{Principals: []string{"foo"}},
				cmp: SignSSHOptions{Principals: []string{"bar"}},
				err: errors.Errorf("ssh certificate principals does not match - got [bar], want [foo]"),
			}
		},
		"fail/validAfter": func() test {
			return test{
				so:  SignSSHOptions{ValidAfter: NewTimeDuration(time.Now().Add(1 * time.Minute))},
				cmp: SignSSHOptions{ValidAfter: NewTimeDuration(time.Now().Add(5 * time.Minute))},
				err: errors.Errorf("ssh certificate validAfter does not match"),
			}
		},
		"fail/validBefore": func() test {
			return test{
				so:  SignSSHOptions{ValidBefore: NewTimeDuration(time.Now().Add(1 * time.Minute))},
				cmp: SignSSHOptions{ValidBefore: NewTimeDuration(time.Now().Add(5 * time.Minute))},
				err: errors.Errorf("ssh certificate validBefore does not match"),
			}
		},
		"ok/original-empty": func() test {
			return test{
				so: SignSSHOptions{},
				cmp: SignSSHOptions{
					CertType:    "foo",
					Principals:  []string{"foo"},
					ValidAfter:  NewTimeDuration(time.Now().Add(1 * time.Minute)),
					ValidBefore: NewTimeDuration(time.Now().Add(5 * time.Minute)),
				},
			}
		},
		"ok/cmp-empty": func() test {
			return test{
				cmp: SignSSHOptions{},
				so: SignSSHOptions{
					CertType:    "foo",
					Principals:  []string{"foo"},
					ValidAfter:  NewTimeDuration(time.Now().Add(1 * time.Minute)),
					ValidBefore: NewTimeDuration(time.Now().Add(5 * time.Minute)),
				},
			}
		},
		"ok/equal": func() test {
			n := time.Now()
			va := NewTimeDuration(n.Add(1 * time.Minute))
			vb := NewTimeDuration(n.Add(5 * time.Minute))
			return test{
				cmp: SignSSHOptions{
					CertType:    "foo",
					Principals:  []string{"foo"},
					ValidAfter:  va,
					ValidBefore: vb,
				},
				so: SignSSHOptions{
					CertType:    "foo",
					Principals:  []string{"foo"},
					ValidAfter:  va,
					ValidBefore: vb,
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if err := tc.so.match(tc.cmp); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func Test_sshCertPrincipalsModifier_Modify(t *testing.T) {
	type test struct {
		modifier sshCertPrincipalsModifier
		cert     *ssh.Certificate
		expected []string
	}
	tests := map[string]func() test{
		"ok": func() test {
			a := []string{"foo", "bar"}
			return test{
				modifier: sshCertPrincipalsModifier(a),
				cert:     new(ssh.Certificate),
				expected: a,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if assert.Nil(t, tc.modifier.Modify(tc.cert, SignSSHOptions{})) {
				assert.Equals(t, tc.cert.ValidPrincipals, tc.expected)
			}
		})
	}
}

func Test_sshCertKeyIDModifier_Modify(t *testing.T) {
	type test struct {
		modifier sshCertKeyIDModifier
		cert     *ssh.Certificate
		expected string
	}
	tests := map[string]func() test{
		"ok": func() test {
			a := "foo"
			return test{
				modifier: sshCertKeyIDModifier(a),
				cert:     new(ssh.Certificate),
				expected: a,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if assert.Nil(t, tc.modifier.Modify(tc.cert, SignSSHOptions{})) {
				assert.Equals(t, tc.cert.KeyId, tc.expected)
			}
		})
	}
}

func Test_sshCertTypeModifier_Modify(t *testing.T) {
	type test struct {
		modifier sshCertTypeModifier
		cert     *ssh.Certificate
		expected uint32
	}
	tests := map[string]func() test{
		"ok/user": func() test {
			return test{
				modifier: sshCertTypeModifier("user"),
				cert:     new(ssh.Certificate),
				expected: ssh.UserCert,
			}
		},
		"ok/host": func() test {
			return test{
				modifier: sshCertTypeModifier("host"),
				cert:     new(ssh.Certificate),
				expected: ssh.HostCert,
			}
		},
		"ok/default": func() test {
			return test{
				modifier: sshCertTypeModifier("foo"),
				cert:     new(ssh.Certificate),
				expected: 0,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if assert.Nil(t, tc.modifier.Modify(tc.cert, SignSSHOptions{})) {
				assert.Equals(t, tc.cert.CertType, tc.expected)
			}
		})
	}
}

func Test_sshCertValidAfterModifier_Modify(t *testing.T) {
	type test struct {
		modifier sshCertValidAfterModifier
		cert     *ssh.Certificate
		expected uint64
	}
	tests := map[string]func() test{
		"ok": func() test {
			return test{
				modifier: sshCertValidAfterModifier(15),
				cert:     new(ssh.Certificate),
				expected: 15,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if assert.Nil(t, tc.modifier.Modify(tc.cert, SignSSHOptions{})) {
				assert.Equals(t, tc.cert.ValidAfter, tc.expected)
			}
		})
	}
}

func Test_sshCertDefaultsModifier_Modify(t *testing.T) {
	type test struct {
		modifier sshCertDefaultsModifier
		cert     *ssh.Certificate
		valid    func(*ssh.Certificate)
	}
	tests := map[string]func() test{
		"ok/changes": func() test {
			n := time.Now()
			va := NewTimeDuration(n.Add(1 * time.Minute))
			vb := NewTimeDuration(n.Add(5 * time.Minute))
			so := SignSSHOptions{
				Principals:  []string{"foo", "bar"},
				CertType:    "host",
				ValidAfter:  va,
				ValidBefore: vb,
			}
			return test{
				modifier: sshCertDefaultsModifier(so),
				cert:     new(ssh.Certificate),
				valid: func(cert *ssh.Certificate) {
					assert.Equals(t, cert.ValidPrincipals, so.Principals)
					assert.Equals(t, cert.CertType, uint32(ssh.HostCert))
					assert.Equals(t, cert.ValidAfter, uint64(so.ValidAfter.RelativeTime(time.Now()).Unix()))
					assert.Equals(t, cert.ValidBefore, uint64(so.ValidBefore.RelativeTime(time.Now()).Unix()))
				},
			}
		},
		"ok/no-changes": func() test {
			n := time.Now()
			so := SignSSHOptions{
				Principals:  []string{"foo", "bar"},
				CertType:    "host",
				ValidAfter:  NewTimeDuration(n.Add(15 * time.Minute)),
				ValidBefore: NewTimeDuration(n.Add(25 * time.Minute)),
			}
			return test{
				modifier: sshCertDefaultsModifier(so),
				cert: &ssh.Certificate{
					CertType:        uint32(ssh.UserCert),
					ValidPrincipals: []string{"zap", "zoop"},
					ValidAfter:      15,
					ValidBefore:     25,
				},
				valid: func(cert *ssh.Certificate) {
					assert.Equals(t, cert.ValidPrincipals, []string{"zap", "zoop"})
					assert.Equals(t, cert.CertType, uint32(ssh.UserCert))
					assert.Equals(t, cert.ValidAfter, uint64(15))
					assert.Equals(t, cert.ValidBefore, uint64(25))
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if assert.Nil(t, tc.modifier.Modify(tc.cert, SignSSHOptions{})) {
				tc.valid(tc.cert)
			}
		})
	}
}

func Test_sshDefaultExtensionModifier_Modify(t *testing.T) {
	type test struct {
		modifier sshDefaultExtensionModifier
		cert     *ssh.Certificate
		valid    func(*ssh.Certificate)
		err      error
	}
	tests := map[string]func() test{
		"fail/unexpected-cert-type": func() test {
			cert := &ssh.Certificate{CertType: 3}
			return test{
				modifier: sshDefaultExtensionModifier{},
				cert:     cert,
				err:      errors.New("ssh certificate has an unknown type '3'"),
			}
		},
		"ok/host": func() test {
			cert := &ssh.Certificate{CertType: ssh.HostCert}
			return test{
				modifier: sshDefaultExtensionModifier{},
				cert:     cert,
				valid: func(cert *ssh.Certificate) {
					assert.Len(t, 0, cert.Extensions)
				},
			}
		},
		"ok/user/extensions-exists": func() test {
			cert := &ssh.Certificate{CertType: ssh.UserCert, Permissions: ssh.Permissions{Extensions: map[string]string{
				"foo": "bar",
			}}}
			return test{
				modifier: sshDefaultExtensionModifier{},
				cert:     cert,
				valid: func(cert *ssh.Certificate) {
					val, ok := cert.Extensions["foo"]
					assert.True(t, ok)
					assert.Equals(t, val, "bar")

					val, ok = cert.Extensions["permit-X11-forwarding"]
					assert.True(t, ok)
					assert.Equals(t, val, "")

					val, ok = cert.Extensions["permit-agent-forwarding"]
					assert.True(t, ok)
					assert.Equals(t, val, "")

					val, ok = cert.Extensions["permit-port-forwarding"]
					assert.True(t, ok)
					assert.Equals(t, val, "")

					val, ok = cert.Extensions["permit-pty"]
					assert.True(t, ok)
					assert.Equals(t, val, "")

					val, ok = cert.Extensions["permit-user-rc"]
					assert.True(t, ok)
					assert.Equals(t, val, "")
				},
			}
		},
		"ok/user/no-extensions": func() test {
			return test{
				modifier: sshDefaultExtensionModifier{},
				cert:     &ssh.Certificate{CertType: ssh.UserCert},
				valid: func(cert *ssh.Certificate) {
					_, ok := cert.Extensions["foo"]
					assert.False(t, ok)

					val, ok := cert.Extensions["permit-X11-forwarding"]
					assert.True(t, ok)
					assert.Equals(t, val, "")

					val, ok = cert.Extensions["permit-agent-forwarding"]
					assert.True(t, ok)
					assert.Equals(t, val, "")

					val, ok = cert.Extensions["permit-port-forwarding"]
					assert.True(t, ok)
					assert.Equals(t, val, "")

					val, ok = cert.Extensions["permit-pty"]
					assert.True(t, ok)
					assert.Equals(t, val, "")

					val, ok = cert.Extensions["permit-user-rc"]
					assert.True(t, ok)
					assert.Equals(t, val, "")
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if err := tc.modifier.Modify(tc.cert, SignSSHOptions{}); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					tc.valid(tc.cert)
				}
			}
		})
	}
}

func Test_sshCertDefaultValidator_Valid(t *testing.T) {
	pub, _, err := keyutil.GenerateDefaultKeyPair()
	assert.FatalError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	assert.FatalError(t, err)
	v := sshCertDefaultValidator{}
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
			errors.New("ssh certificate has an unknown type '3'"),
		},
		{
			"fail/empty-cert-key-id",
			&ssh.Certificate{Nonce: []byte("foo"), Key: sshPub, Serial: 1, CertType: 1},
			errors.New("ssh certificate key id cannot be empty"),
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
		{
			"ok/emptyPrincipals",
			&ssh.Certificate{
				Nonce:           []byte("foo"),
				Key:             sshPub,
				Serial:          1,
				CertType:        1,
				KeyId:           "foo",
				ValidPrincipals: []string{},
				ValidAfter:      uint64(time.Now().Unix()),
				ValidBefore:     uint64(time.Now().Add(10 * time.Minute).Unix()),
				SignatureKey:    sshPub,
				Signature:       &ssh.Signature{},
			},
			nil,
		},
		{
			"ok/empty-extensions",
			&ssh.Certificate{
				Nonce:           []byte("foo"),
				Key:             sshPub,
				Serial:          1,
				CertType:        1,
				KeyId:           "foo",
				ValidPrincipals: []string{},
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
			if err := v.Valid(tt.cert, SignSSHOptions{}); err != nil {
				if assert.NotNil(t, tt.err) {
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			} else {
				assert.Nil(t, tt.err)
			}
		})
	}
}

func Test_sshCertValidityValidator(t *testing.T) {
	p, err := generateX5C(nil)
	assert.FatalError(t, err)
	v := sshCertValidityValidator{p.ctl.Claimer}
	n := now()
	tests := []struct {
		name string
		cert *ssh.Certificate
		opts SignSSHOptions
		err  error
	}{
		{
			"fail/validAfter-0",
			&ssh.Certificate{CertType: ssh.UserCert},
			SignSSHOptions{},
			errors.New("ssh certificate validAfter cannot be 0"),
		},
		{
			"fail/validBefore-in-past",
			&ssh.Certificate{CertType: ssh.UserCert, ValidAfter: uint64(now().Unix()), ValidBefore: uint64(now().Add(-time.Minute).Unix())},
			SignSSHOptions{},
			errors.New("ssh certificate validBefore cannot be in the past"),
		},
		{
			"fail/validBefore-before-validAfter",
			&ssh.Certificate{CertType: ssh.UserCert, ValidAfter: uint64(now().Add(5 * time.Minute).Unix()), ValidBefore: uint64(now().Add(3 * time.Minute).Unix())},
			SignSSHOptions{},
			errors.New("ssh certificate validBefore cannot be before validAfter"),
		},
		{
			"fail/cert-type-not-set",
			&ssh.Certificate{ValidAfter: uint64(now().Unix()), ValidBefore: uint64(now().Add(10 * time.Minute).Unix())},
			SignSSHOptions{},
			errors.New("ssh certificate type has not been set"),
		},
		{
			"fail/unexpected-cert-type",
			&ssh.Certificate{
				CertType:    3,
				ValidAfter:  uint64(now().Unix()),
				ValidBefore: uint64(now().Add(10 * time.Minute).Unix()),
			},
			SignSSHOptions{},
			errors.New("ssh certificate has an unknown type '3'"),
		},
		{
			"fail/duration<min",
			&ssh.Certificate{
				CertType:    1,
				ValidAfter:  uint64(n.Unix()),
				ValidBefore: uint64(n.Add(4 * time.Minute).Unix()),
			},
			SignSSHOptions{Backdate: time.Second},
			errors.New("requested duration of 4m0s is less than minimum accepted duration for selected provisioner of 5m0s"),
		},
		{
			"ok/duration-exactly-min",
			&ssh.Certificate{
				CertType:    1,
				ValidAfter:  uint64(n.Unix()),
				ValidBefore: uint64(n.Add(5 * time.Minute).Unix()),
			},
			SignSSHOptions{Backdate: time.Second},
			nil,
		},
		{
			"fail/duration>max",
			&ssh.Certificate{
				CertType:    1,
				ValidAfter:  uint64(n.Unix()),
				ValidBefore: uint64(n.Add(48 * time.Hour).Unix()),
			},
			SignSSHOptions{Backdate: time.Second},
			errors.New("requested duration of 48h0m0s is greater than maximum accepted duration for selected provisioner of 24h0m1s"),
		},
		{
			"ok/duration-exactly-max",
			&ssh.Certificate{
				CertType:    1,
				ValidAfter:  uint64(n.Unix()),
				ValidBefore: uint64(n.Add(24*time.Hour + time.Second).Unix()),
			},
			SignSSHOptions{Backdate: time.Second},
			nil,
		},
		{
			"ok",
			&ssh.Certificate{
				CertType:    1,
				ValidAfter:  uint64(now().Unix()),
				ValidBefore: uint64(now().Add(8 * time.Hour).Unix()),
			},
			SignSSHOptions{Backdate: time.Second},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := v.Valid(tt.cert, tt.opts); err != nil {
				if assert.NotNil(t, tt.err) {
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			} else {
				assert.Nil(t, tt.err)
			}
		})
	}
}

func Test_sshValidityModifier(t *testing.T) {
	n, fn := mockNow()
	defer fn()

	p, err := generateX5C(nil)
	assert.FatalError(t, err)
	type test struct {
		svm   *sshLimitDuration
		cert  *ssh.Certificate
		valid func(*ssh.Certificate)
		err   error
	}
	tests := map[string]func() test{
		"fail/type-not-set": func() test {
			return test{
				svm: &sshLimitDuration{Claimer: p.ctl.Claimer, NotAfter: n.Add(6 * time.Hour)},
				cert: &ssh.Certificate{
					ValidAfter:  uint64(n.Unix()),
					ValidBefore: uint64(n.Add(8 * time.Hour).Unix()),
				},
				err: errors.New("ssh certificate type has not been set"),
			}
		},
		"fail/type-not-recognized": func() test {
			return test{
				svm: &sshLimitDuration{Claimer: p.ctl.Claimer, NotAfter: n.Add(6 * time.Hour)},
				cert: &ssh.Certificate{
					CertType:    4,
					ValidAfter:  uint64(n.Unix()),
					ValidBefore: uint64(n.Add(8 * time.Hour).Unix()),
				},
				err: errors.New("ssh certificate has an unknown type: 4"),
			}
		},
		"fail/requested-validAfter-after-limit": func() test {
			return test{
				svm: &sshLimitDuration{Claimer: p.ctl.Claimer, NotAfter: n.Add(1 * time.Hour)},
				cert: &ssh.Certificate{
					CertType:    1,
					ValidAfter:  uint64(n.Add(2 * time.Hour).Unix()),
					ValidBefore: uint64(n.Add(8 * time.Hour).Unix()),
				},
				err: errors.Errorf("provisioning credential expiration ("),
			}
		},
		"fail/requested-validBefore-after-limit": func() test {
			return test{
				svm: &sshLimitDuration{Claimer: p.ctl.Claimer, NotAfter: n.Add(1 * time.Hour)},
				cert: &ssh.Certificate{
					CertType:    1,
					ValidAfter:  uint64(n.Unix()),
					ValidBefore: uint64(n.Add(2 * time.Hour).Unix()),
				},
				err: errors.New("provisioning credential expiration ("),
			}
		},
		"ok/no-limit": func() test {
			va, vb := uint64(n.Unix()), uint64(n.Add(16*time.Hour).Unix())
			return test{
				svm: &sshLimitDuration{Claimer: p.ctl.Claimer},
				cert: &ssh.Certificate{
					CertType: 1,
				},
				valid: func(cert *ssh.Certificate) {
					assert.Equals(t, cert.ValidAfter, va)
					assert.Equals(t, cert.ValidBefore, vb)
				},
			}
		},
		"ok/defaults": func() test {
			va, vb := uint64(n.Unix()), uint64(n.Add(16*time.Hour).Unix())
			return test{
				svm: &sshLimitDuration{Claimer: p.ctl.Claimer},
				cert: &ssh.Certificate{
					CertType: 1,
				},
				valid: func(cert *ssh.Certificate) {
					assert.Equals(t, cert.ValidAfter, va)
					assert.Equals(t, cert.ValidBefore, vb)
				},
			}
		},
		"ok/valid-requested-validBefore": func() test {
			va, vb := uint64(n.Unix()), uint64(n.Add(2*time.Hour).Unix())
			return test{
				svm: &sshLimitDuration{Claimer: p.ctl.Claimer, NotAfter: n.Add(3 * time.Hour)},
				cert: &ssh.Certificate{
					CertType:    1,
					ValidAfter:  va,
					ValidBefore: vb,
				},
				valid: func(cert *ssh.Certificate) {
					assert.Equals(t, cert.ValidAfter, va)
					assert.Equals(t, cert.ValidBefore, vb)
				},
			}
		},
		"ok/empty-requested-validBefore-limit-after-default": func() test {
			va := uint64(n.Unix())
			return test{
				svm: &sshLimitDuration{Claimer: p.ctl.Claimer, NotAfter: n.Add(24 * time.Hour)},
				cert: &ssh.Certificate{
					CertType:   1,
					ValidAfter: va,
				},
				valid: func(cert *ssh.Certificate) {
					assert.Equals(t, cert.ValidAfter, va)
					assert.Equals(t, cert.ValidBefore, uint64(n.Add(16*time.Hour).Unix()))
				},
			}
		},
		"ok/empty-requested-validBefore-limit-before-default": func() test {
			va := uint64(n.Unix())
			return test{
				svm: &sshLimitDuration{Claimer: p.ctl.Claimer, NotAfter: n.Add(3 * time.Hour)},
				cert: &ssh.Certificate{
					CertType:   1,
					ValidAfter: va,
				},
				valid: func(cert *ssh.Certificate) {
					assert.Equals(t, cert.ValidAfter, va)
					assert.Equals(t, cert.ValidBefore, uint64(n.Add(3*time.Hour).Unix()))
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tt := run()
			if err := tt.svm.Modify(tt.cert, SignSSHOptions{}); err != nil {
				if assert.NotNil(t, tt.err) {
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			} else {
				if assert.Nil(t, tt.err) {
					tt.valid(tt.cert)
				}
			}
		})
	}
}

func Test_sshDefaultDuration_Option(t *testing.T) {
	tm, fn := mockNow()
	defer fn()

	newClaimer := func(claims *Claims) *Claimer {
		c, err := NewClaimer(claims, globalProvisionerClaims)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	unix := func(d time.Duration) uint64 {
		return uint64(tm.Add(d).Unix())
	}

	type fields struct {
		Claimer *Claimer
	}
	type args struct {
		o    SignSSHOptions
		cert *ssh.Certificate
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *ssh.Certificate
		wantErr bool
	}{
		{"user", fields{newClaimer(nil)}, args{SignSSHOptions{}, &ssh.Certificate{CertType: ssh.UserCert}},
			&ssh.Certificate{CertType: ssh.UserCert, ValidAfter: unix(0), ValidBefore: unix(16 * time.Hour)}, false},
		{"host", fields{newClaimer(nil)}, args{SignSSHOptions{}, &ssh.Certificate{CertType: ssh.HostCert}},
			&ssh.Certificate{CertType: ssh.HostCert, ValidAfter: unix(0), ValidBefore: unix(30 * 24 * time.Hour)}, false},
		{"user claim", fields{newClaimer(&Claims{DefaultUserSSHDur: &Duration{1 * time.Hour}})}, args{SignSSHOptions{}, &ssh.Certificate{CertType: ssh.UserCert}},
			&ssh.Certificate{CertType: ssh.UserCert, ValidAfter: unix(0), ValidBefore: unix(1 * time.Hour)}, false},
		{"host claim", fields{newClaimer(&Claims{DefaultHostSSHDur: &Duration{1 * time.Hour}})}, args{SignSSHOptions{}, &ssh.Certificate{CertType: ssh.HostCert}},
			&ssh.Certificate{CertType: ssh.HostCert, ValidAfter: unix(0), ValidBefore: unix(1 * time.Hour)}, false},
		{"user backdate", fields{newClaimer(nil)}, args{SignSSHOptions{Backdate: 1 * time.Minute}, &ssh.Certificate{CertType: ssh.UserCert}},
			&ssh.Certificate{CertType: ssh.UserCert, ValidAfter: unix(-1 * time.Minute), ValidBefore: unix(16 * time.Hour)}, false},
		{"host backdate", fields{newClaimer(nil)}, args{SignSSHOptions{Backdate: 1 * time.Minute}, &ssh.Certificate{CertType: ssh.HostCert}},
			&ssh.Certificate{CertType: ssh.HostCert, ValidAfter: unix(-1 * time.Minute), ValidBefore: unix(30 * 24 * time.Hour)}, false},
		{"user validAfter", fields{newClaimer(nil)}, args{SignSSHOptions{Backdate: 1 * time.Minute}, &ssh.Certificate{CertType: ssh.UserCert, ValidAfter: unix(1 * time.Hour)}},
			&ssh.Certificate{CertType: ssh.UserCert, ValidAfter: unix(time.Hour), ValidBefore: unix(17 * time.Hour)}, false},
		{"user validBefore", fields{newClaimer(nil)}, args{SignSSHOptions{Backdate: 1 * time.Minute}, &ssh.Certificate{CertType: ssh.UserCert, ValidBefore: unix(1 * time.Hour)}},
			&ssh.Certificate{CertType: ssh.UserCert, ValidAfter: unix(-1 * time.Minute), ValidBefore: unix(time.Hour)}, false},
		{"host validAfter validBefore", fields{newClaimer(nil)}, args{SignSSHOptions{Backdate: 1 * time.Minute}, &ssh.Certificate{CertType: ssh.HostCert, ValidAfter: unix(1 * time.Minute), ValidBefore: unix(2 * time.Minute)}},
			&ssh.Certificate{CertType: ssh.HostCert, ValidAfter: unix(1 * time.Minute), ValidBefore: unix(2 * time.Minute)}, false},
		{"fail zero", fields{newClaimer(nil)}, args{SignSSHOptions{}, &ssh.Certificate{}}, &ssh.Certificate{}, true},
		{"fail type", fields{newClaimer(nil)}, args{SignSSHOptions{}, &ssh.Certificate{CertType: 3}}, &ssh.Certificate{CertType: 3}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &sshDefaultDuration{
				Claimer: tt.fields.Claimer,
			}
			if err := m.Modify(tt.args.cert, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("sshDefaultDuration.Option() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.cert, tt.want) {
				t.Errorf("sshDefaultDuration.Option() = %v, want %v", tt.args.cert, tt.want)
			}
		})
	}
}
