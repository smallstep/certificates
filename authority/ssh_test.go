package authority

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/sshutil"
	"golang.org/x/crypto/ssh"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/templates"
)

type sshTestModifier ssh.Certificate

func (m sshTestModifier) Modify(cert *ssh.Certificate, _ provisioner.SignSSHOptions) error {
	if m.CertType != 0 {
		cert.CertType = m.CertType
	}
	if m.KeyId != "" {
		cert.KeyId = m.KeyId
	}
	if m.ValidAfter != 0 {
		cert.ValidAfter = m.ValidAfter
	}
	if m.ValidBefore != 0 {
		cert.ValidBefore = m.ValidBefore
	}
	if len(m.ValidPrincipals) != 0 {
		cert.ValidPrincipals = m.ValidPrincipals
	}
	if m.Permissions.CriticalOptions != nil {
		cert.Permissions.CriticalOptions = m.Permissions.CriticalOptions
	}
	if m.Permissions.Extensions != nil {
		cert.Permissions.Extensions = m.Permissions.Extensions
	}
	return nil
}

type sshTestCertModifier string

func (m sshTestCertModifier) Modify(cert *ssh.Certificate, opts provisioner.SignSSHOptions) error {
	if m == "" {
		return nil
	}
	return errors.New(string(m))
}

type sshTestCertValidator string

func (v sshTestCertValidator) Valid(crt *ssh.Certificate, opts provisioner.SignSSHOptions) error {
	if v == "" {
		return nil
	}
	return errors.New(string(v))
}

type sshTestOptionsValidator string

func (v sshTestOptionsValidator) Valid(opts provisioner.SignSSHOptions) error {
	if v == "" {
		return nil
	}
	return errors.New(string(v))
}

type sshTestOptionsModifier string

func (m sshTestOptionsModifier) Modify(cert *ssh.Certificate, opts provisioner.SignSSHOptions) error {
	if m == "" {
		return nil
	}
	return errors.New(string(m))
}

func TestAuthority_initHostOnly(t *testing.T) {
	auth := testAuthority(t, func(a *Authority) error {
		a.config.SSH.UserKey = ""
		return nil
	})

	// Check keys
	keys, err := auth.GetSSHRoots(context.Background())
	assert.NoError(t, err)
	assert.Len(t, 1, keys.HostKeys)
	assert.Len(t, 0, keys.UserKeys)

	// Check templates, user templates should work fine.
	_, err = auth.GetSSHConfig(context.Background(), "user", nil)
	assert.NoError(t, err)

	_, err = auth.GetSSHConfig(context.Background(), "host", map[string]string{
		"Certificate": "ssh_host_ecdsa_key-cert.pub",
		"Key":         "ssh_host_ecdsa_key",
	})
	assert.Error(t, err)
}

func TestAuthority_initUserOnly(t *testing.T) {
	auth := testAuthority(t, func(a *Authority) error {
		a.config.SSH.HostKey = ""
		return nil
	})

	// Check keys
	keys, err := auth.GetSSHRoots(context.Background())
	assert.NoError(t, err)
	assert.Len(t, 0, keys.HostKeys)
	assert.Len(t, 1, keys.UserKeys)

	// Check templates, host templates should work fine.
	_, err = auth.GetSSHConfig(context.Background(), "host", map[string]string{
		"Certificate": "ssh_host_ecdsa_key-cert.pub",
		"Key":         "ssh_host_ecdsa_key",
	})
	assert.NoError(t, err)

	_, err = auth.GetSSHConfig(context.Background(), "user", nil)
	assert.Error(t, err)
}

func TestAuthority_SignSSH(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	pub, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)
	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	signer, err := ssh.NewSignerFromKey(signKey)
	assert.FatalError(t, err)

	userOptions := sshTestModifier{
		CertType: ssh.UserCert,
	}
	hostOptions := sshTestModifier{
		CertType: ssh.HostCert,
	}

	userTemplate, err := provisioner.TemplateSSHOptions(nil, sshutil.CreateTemplateData(sshutil.UserCert, "key-id", nil))
	assert.FatalError(t, err)
	hostTemplate, err := provisioner.TemplateSSHOptions(nil, sshutil.CreateTemplateData(sshutil.HostCert, "key-id", nil))
	assert.FatalError(t, err)
	userTemplateWithUser, err := provisioner.TemplateSSHOptions(nil, sshutil.CreateTemplateData(sshutil.UserCert, "key-id", []string{"user"}))
	assert.FatalError(t, err)
	hostTemplateWithHosts, err := provisioner.TemplateSSHOptions(nil, sshutil.CreateTemplateData(sshutil.HostCert, "key-id", []string{"foo.test.com", "bar.test.com"}))
	assert.FatalError(t, err)
	userTemplateWithRoot, err := provisioner.TemplateSSHOptions(nil, sshutil.CreateTemplateData(sshutil.UserCert, "key-id", []string{"root"}))
	assert.FatalError(t, err)
	hostTemplateWithExampleDotCom, err := provisioner.TemplateSSHOptions(nil, sshutil.CreateTemplateData(sshutil.HostCert, "key-id", []string{"example.com"}))
	assert.FatalError(t, err)
	badUserTemplate, err := provisioner.TemplateSSHOptions(nil, sshutil.CreateTemplateData(sshutil.UserCert, "key-id", []string{"127.0.0.1"}))
	assert.FatalError(t, err)
	badHostTemplate, err := provisioner.TemplateSSHOptions(nil, sshutil.CreateTemplateData(sshutil.HostCert, "key-id", []string{"host...local"}))
	assert.FatalError(t, err)
	userCustomTemplate, err := provisioner.TemplateSSHOptions(&provisioner.Options{
		SSH: &provisioner.SSHOptions{Template: `{
			"type": "{{ .Type }}",
			"keyId": "{{ .KeyID }}",
			"principals": {{ append .Principals "admin" | toJson }},
			"extensions": {{ set .Extensions "login@github.com" .Insecure.User.username | toJson }},
			"criticalOptions": {{ toJson .CriticalOptions }}
		}`},
	}, sshutil.CreateTemplateData(sshutil.UserCert, "key-id", []string{"user"}))
	assert.FatalError(t, err)
	enrichTemplateData := sshutil.CreateTemplateData(sshutil.UserCert, "key-id", []string{"user"})
	enrichTemplate, err := provisioner.TemplateSSHOptions(&provisioner.Options{
		SSH: &provisioner.SSHOptions{Template: `{
			"type": "{{ .Type }}",
			"keyId": "{{ .KeyID }}",
			"principals": {{ toJson .Webhooks.people.role }},
			"extensions": {{ set .Extensions "login@github.com" .Insecure.User.username | toJson }},
			"criticalOptions": {{ toJson .CriticalOptions }}
		}`},
	}, enrichTemplateData)
	assert.FatalError(t, err)
	userFailTemplate, err := provisioner.TemplateSSHOptions(&provisioner.Options{
		SSH: &provisioner.SSHOptions{Template: `{{ fail "an error"}}`},
	}, sshutil.CreateTemplateData(sshutil.UserCert, "key-id", []string{"user"}))
	assert.FatalError(t, err)
	userJSONSyntaxErrorTemplateFile, err := provisioner.TemplateSSHOptions(&provisioner.Options{
		SSH: &provisioner.SSHOptions{TemplateFile: "./testdata/templates/badjsonsyntax.tpl"},
	}, sshutil.CreateTemplateData(sshutil.UserCert, "key-id", []string{"user"}))
	assert.FatalError(t, err)
	userJSONValueErrorTemplateFile, err := provisioner.TemplateSSHOptions(&provisioner.Options{
		SSH: &provisioner.SSHOptions{TemplateFile: "./testdata/templates/badjsonvalue.tpl"},
	}, sshutil.CreateTemplateData(sshutil.UserCert, "key-id", []string{"user"}))
	assert.FatalError(t, err)

	userPolicyOptions := &policy.Options{
		SSH: &policy.SSHPolicyOptions{
			User: &policy.SSHUserCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					Principals: []string{"user"},
				},
			},
		},
	}
	userPolicy, err := policy.New(userPolicyOptions)
	assert.FatalError(t, err)

	hostPolicyOptions := &policy.Options{
		SSH: &policy.SSHPolicyOptions{
			Host: &policy.SSHHostCertificateOptions{
				AllowedNames: &policy.SSHNameOptions{
					DNSDomains: []string{"*.test.com"},
				},
			},
		},
	}
	hostPolicy, err := policy.New(hostPolicyOptions)
	assert.FatalError(t, err)

	now := time.Now()

	type fields struct {
		sshCAUserCertSignKey ssh.Signer
		sshCAHostCertSignKey ssh.Signer
		policyEngine         *policy.Engine
	}
	type args struct {
		key      ssh.PublicKey
		opts     provisioner.SignSSHOptions
		signOpts []provisioner.SignOption
	}
	type want struct {
		CertType    uint32
		Principals  []string
		ValidAfter  uint64
		ValidBefore uint64
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    want
		wantErr bool
	}{
		{"ok-user", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions}}, want{CertType: ssh.UserCert}, false},
		{"ok-host", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{hostTemplate, hostOptions}}, want{CertType: ssh.HostCert}, false},
		{"ok-user-only", fields{signer, nil, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions}}, want{CertType: ssh.UserCert}, false},
		{"ok-host-only", fields{nil, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{hostTemplate, hostOptions}}, want{CertType: ssh.HostCert}, false},
		{"ok-opts-type-user", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{CertType: "user"}, []provisioner.SignOption{userTemplate}}, want{CertType: ssh.UserCert}, false},
		{"ok-opts-type-host", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{CertType: "host"}, []provisioner.SignOption{hostTemplate}}, want{CertType: ssh.HostCert}, false},
		{"ok-opts-principals", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{CertType: "user", Principals: []string{"user"}}, []provisioner.SignOption{userTemplateWithUser}}, want{CertType: ssh.UserCert, Principals: []string{"user"}}, false},
		{"ok-opts-principals", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{CertType: "host", Principals: []string{"foo.test.com", "bar.test.com"}}, []provisioner.SignOption{hostTemplateWithHosts}}, want{CertType: ssh.HostCert, Principals: []string{"foo.test.com", "bar.test.com"}}, false},
		{"ok-opts-valid-after", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{CertType: "user", ValidAfter: provisioner.NewTimeDuration(now)}, []provisioner.SignOption{userTemplate}}, want{CertType: ssh.UserCert, ValidAfter: uint64(now.Unix())}, false},
		{"ok-opts-valid-before", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{CertType: "host", ValidBefore: provisioner.NewTimeDuration(now)}, []provisioner.SignOption{hostTemplate}}, want{CertType: ssh.HostCert, ValidBefore: uint64(now.Unix())}, false},
		{"ok-cert-validator", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions, sshTestCertValidator("")}}, want{CertType: ssh.UserCert}, false},
		{"ok-cert-modifier", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions, sshTestCertModifier("")}}, want{CertType: ssh.UserCert}, false},
		{"ok-opts-validator", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions, sshTestOptionsValidator("")}}, want{CertType: ssh.UserCert}, false},
		{"ok-opts-modifier", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions, sshTestOptionsModifier("")}}, want{CertType: ssh.UserCert}, false},
		{"ok-custom-template", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userCustomTemplate, userOptions}}, want{CertType: ssh.UserCert, Principals: []string{"user", "admin"}}, false},
		{"ok-enrich-template", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{enrichTemplate, userOptions, &mockWebhookController{templateData: enrichTemplateData, respData: map[string]any{"people": map[string]any{"role": []string{"user", "eng"}}}}}}, want{CertType: ssh.UserCert, Principals: []string{"user", "eng"}}, false},
		{"ok-user-policy", fields{signer, signer, userPolicy}, args{pub, provisioner.SignSSHOptions{CertType: "user", Principals: []string{"user"}}, []provisioner.SignOption{userTemplateWithUser}}, want{CertType: ssh.UserCert, Principals: []string{"user"}}, false},
		{"ok-host-policy", fields{signer, signer, hostPolicy}, args{pub, provisioner.SignSSHOptions{CertType: "host", Principals: []string{"foo.test.com", "bar.test.com"}}, []provisioner.SignOption{hostTemplateWithHosts}}, want{CertType: ssh.HostCert, Principals: []string{"foo.test.com", "bar.test.com"}}, false},
		{"fail-opts-type", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{CertType: "foo"}, []provisioner.SignOption{userTemplate}}, want{}, true},
		{"fail-cert-validator", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions, sshTestCertValidator("an error")}}, want{}, true},
		{"fail-cert-modifier", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions, sshTestCertModifier("an error")}}, want{}, true},
		{"fail-opts-validator", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions, sshTestOptionsValidator("an error")}}, want{}, true},
		{"fail-opts-modifier", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions, sshTestOptionsModifier("an error")}}, want{}, true},
		{"fail-bad-sign-options", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions, "wrong type"}}, want{}, true},
		{"fail-no-user-key", fields{nil, signer, nil}, args{pub, provisioner.SignSSHOptions{CertType: "user"}, []provisioner.SignOption{userTemplate}}, want{}, true},
		{"fail-no-host-key", fields{signer, nil, nil}, args{pub, provisioner.SignSSHOptions{CertType: "host"}, []provisioner.SignOption{hostTemplate}}, want{}, true},
		{"fail-bad-type", fields{signer, nil, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, sshTestModifier{CertType: 100}}}, want{}, true},
		{"fail-custom-template", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userFailTemplate, userOptions}}, want{}, true},
		{"fail-custom-template-syntax-error-file", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userJSONSyntaxErrorTemplateFile, userOptions}}, want{}, true},
		{"fail-custom-template-syntax-value-file", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userJSONValueErrorTemplateFile, userOptions}}, want{}, true},
		{"fail-user-policy", fields{signer, signer, userPolicy}, args{pub, provisioner.SignSSHOptions{CertType: "user", Principals: []string{"root"}}, []provisioner.SignOption{userTemplateWithRoot}}, want{}, true},
		{"fail-user-policy-with-host-cert", fields{signer, signer, userPolicy}, args{pub, provisioner.SignSSHOptions{CertType: "host", Principals: []string{"foo.test.com"}}, []provisioner.SignOption{hostTemplateWithExampleDotCom}}, want{}, true},
		{"fail-user-policy-with-bad-user", fields{signer, signer, userPolicy}, args{pub, provisioner.SignSSHOptions{CertType: "user", Principals: []string{"user"}}, []provisioner.SignOption{badUserTemplate}}, want{}, true},
		{"fail-host-policy", fields{signer, signer, hostPolicy}, args{pub, provisioner.SignSSHOptions{CertType: "host", Principals: []string{"example.com"}}, []provisioner.SignOption{hostTemplateWithExampleDotCom}}, want{}, true},
		{"fail-host-policy-with-user-cert", fields{signer, signer, hostPolicy}, args{pub, provisioner.SignSSHOptions{CertType: "user", Principals: []string{"user"}}, []provisioner.SignOption{userTemplateWithUser}}, want{}, true},
		{"fail-host-policy-with-bad-host", fields{signer, signer, hostPolicy}, args{pub, provisioner.SignSSHOptions{CertType: "host", Principals: []string{"example.com"}}, []provisioner.SignOption{badHostTemplate}}, want{}, true},
		{"fail-enriching-webhooks", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions, &mockWebhookController{enrichErr: provisioner.ErrWebhookDenied}}}, want{}, true},
		{"fail-authorizing-webhooks", fields{signer, signer, nil}, args{pub, provisioner.SignSSHOptions{}, []provisioner.SignOption{userTemplate, userOptions, &mockWebhookController{authorizeErr: provisioner.ErrWebhookDenied}}}, want{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuthority(t)
			a.sshCAUserCertSignKey = tt.fields.sshCAUserCertSignKey
			a.sshCAHostCertSignKey = tt.fields.sshCAHostCertSignKey
			a.policyEngine = tt.fields.policyEngine

			got, err := a.SignSSH(context.Background(), tt.args.key, tt.args.opts, tt.args.signOpts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.SignSSH() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && assert.NotNil(t, got) {
				assert.Equals(t, tt.want.CertType, got.CertType)
				assert.Equals(t, tt.want.Principals, got.ValidPrincipals)
				assert.Equals(t, tt.want.ValidAfter, got.ValidAfter)
				assert.Equals(t, tt.want.ValidBefore, got.ValidBefore)
				assert.NotNil(t, got.Key)
				assert.NotNil(t, got.Nonce)
				assert.NotEquals(t, 0, got.Serial)
				assert.NotNil(t, got.Signature)
				assert.NotNil(t, got.SignatureKey)
			}
		})
	}
}

func TestAuthority_SignSSHAddUser(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	pub, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)
	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	signer, err := ssh.NewSignerFromKey(signKey)
	assert.FatalError(t, err)

	type fields struct {
		sshCAUserCertSignKey ssh.Signer
		sshCAHostCertSignKey ssh.Signer
		addUserPrincipal     string
		addUserCommand       string
	}
	type args struct {
		key     ssh.PublicKey
		subject *ssh.Certificate
	}
	type want struct {
		CertType     uint32
		Principals   []string
		ValidAfter   uint64
		ValidBefore  uint64
		ForceCommand string
	}

	now := time.Now()
	validCert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"user"},
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(now.Add(time.Hour).Unix()),
	}
	validWant := want{
		CertType:     ssh.UserCert,
		Principals:   []string{"provisioner"},
		ValidAfter:   uint64(now.Unix()),
		ValidBefore:  uint64(now.Add(time.Hour).Unix()),
		ForceCommand: "sudo useradd -m user; nc -q0 localhost 22",
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    want
		wantErr bool
	}{
		{"ok", fields{signer, signer, "", ""}, args{pub, validCert}, validWant, false},
		{"ok-no-host-key", fields{signer, nil, "", ""}, args{pub, validCert}, validWant, false},
		{"ok-custom-principal", fields{signer, signer, "my-principal", ""}, args{pub, &ssh.Certificate{CertType: ssh.UserCert, ValidPrincipals: []string{"user"}}}, want{CertType: ssh.UserCert, Principals: []string{"my-principal"}, ForceCommand: "sudo useradd -m user; nc -q0 localhost 22"}, false},
		{"ok-custom-command", fields{signer, signer, "", "foo <principal> <principal>"}, args{pub, &ssh.Certificate{CertType: ssh.UserCert, ValidPrincipals: []string{"user"}}}, want{CertType: ssh.UserCert, Principals: []string{"provisioner"}, ForceCommand: "foo user user"}, false},
		{"ok-custom-principal-and-command", fields{signer, signer, "my-principal", "foo <principal> <principal>"}, args{pub, &ssh.Certificate{CertType: ssh.UserCert, ValidPrincipals: []string{"user"}}}, want{CertType: ssh.UserCert, Principals: []string{"my-principal"}, ForceCommand: "foo user user"}, false},
		{"fail-no-user-key", fields{nil, signer, "", ""}, args{pub, validCert}, want{}, true},
		{"fail-no-user-cert", fields{signer, signer, "", ""}, args{pub, &ssh.Certificate{CertType: ssh.HostCert, ValidPrincipals: []string{"foo"}}}, want{}, true},
		{"fail-no-principals", fields{signer, signer, "", ""}, args{pub, &ssh.Certificate{CertType: ssh.UserCert, ValidPrincipals: []string{}}}, want{}, true},
		{"fail-many-principals", fields{signer, signer, "", ""}, args{pub, &ssh.Certificate{CertType: ssh.UserCert, ValidPrincipals: []string{"foo", "bar"}}}, want{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuthority(t)
			a.sshCAUserCertSignKey = tt.fields.sshCAUserCertSignKey
			a.sshCAHostCertSignKey = tt.fields.sshCAHostCertSignKey
			a.config.SSH = &SSHConfig{
				AddUserPrincipal: tt.fields.addUserPrincipal,
				AddUserCommand:   tt.fields.addUserCommand,
			}
			got, err := a.SignSSHAddUser(context.Background(), tt.args.key, tt.args.subject)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.SignSSHAddUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && assert.NotNil(t, got) {
				assert.Equals(t, tt.want.CertType, got.CertType)
				assert.Equals(t, tt.want.Principals, got.ValidPrincipals)
				assert.Equals(t, tt.args.subject.ValidPrincipals[0]+"-"+tt.want.Principals[0], got.KeyId)
				assert.Equals(t, tt.want.ValidAfter, got.ValidAfter)
				assert.Equals(t, tt.want.ValidBefore, got.ValidBefore)
				assert.Equals(t, map[string]string{"force-command": tt.want.ForceCommand}, got.CriticalOptions)
				assert.Equals(t, nil, got.Extensions)
				assert.NotNil(t, got.Key)
				assert.NotNil(t, got.Nonce)
				assert.NotEquals(t, 0, got.Serial)
				assert.NotNil(t, got.Signature)
				assert.NotNil(t, got.SignatureKey)
			}
		})
	}
}

func TestAuthority_GetSSHRoots(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	user, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	host, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)

	type fields struct {
		sshCAUserCerts []ssh.PublicKey
		sshCAHostCerts []ssh.PublicKey
	}
	tests := []struct {
		name    string
		fields  fields
		want    *SSHKeys
		wantErr bool
	}{
		{"ok", fields{[]ssh.PublicKey{user}, []ssh.PublicKey{host}}, &SSHKeys{UserKeys: []ssh.PublicKey{user}, HostKeys: []ssh.PublicKey{host}}, false},
		{"nil", fields{}, &SSHKeys{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuthority(t)
			a.sshCAUserCerts = tt.fields.sshCAUserCerts
			a.sshCAHostCerts = tt.fields.sshCAHostCerts

			got, err := a.GetSSHRoots(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.GetSSHRoots() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.GetSSHRoots() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthority_GetSSHFederation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	user, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	host, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)

	type fields struct {
		sshCAUserFederatedCerts []ssh.PublicKey
		sshCAHostFederatedCerts []ssh.PublicKey
	}
	tests := []struct {
		name    string
		fields  fields
		want    *SSHKeys
		wantErr bool
	}{
		{"ok", fields{[]ssh.PublicKey{user}, []ssh.PublicKey{host}}, &SSHKeys{UserKeys: []ssh.PublicKey{user}, HostKeys: []ssh.PublicKey{host}}, false},
		{"nil", fields{}, &SSHKeys{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuthority(t)
			a.sshCAUserFederatedCerts = tt.fields.sshCAUserFederatedCerts
			a.sshCAHostFederatedCerts = tt.fields.sshCAHostFederatedCerts

			got, err := a.GetSSHFederation(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.GetSSHFederation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.GetSSHFederation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthority_GetSSHConfig(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	user, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)
	userSigner, err := ssh.NewSignerFromSigner(key)
	assert.FatalError(t, err)
	userB64 := base64.StdEncoding.EncodeToString(user.Marshal())

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	host, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)
	hostSigner, err := ssh.NewSignerFromSigner(key)
	assert.FatalError(t, err)
	hostB64 := base64.StdEncoding.EncodeToString(host.Marshal())

	tmplConfig := &templates.Templates{
		SSH: &templates.SSHTemplates{
			User: []templates.Template{
				{Name: "known_host.tpl", Type: templates.File, TemplatePath: "./testdata/templates/known_hosts.tpl", Path: "ssh/known_host", Comment: "#"},
			},
			Host: []templates.Template{
				{Name: "ca.tpl", Type: templates.File, TemplatePath: "./testdata/templates/ca.tpl", Path: "/etc/ssh/ca.pub", Comment: "#"},
			},
		},
		Data: map[string]interface{}{
			"Step": &templates.Step{
				SSH: templates.StepSSH{
					UserKey: user,
					HostKey: host,
				},
			},
		},
	}
	userOutput := []templates.Output{
		{Name: "known_host.tpl", Type: templates.File, Comment: "#", Path: "ssh/known_host", Content: []byte(fmt.Sprintf("@cert-authority * %s %s", host.Type(), hostB64))},
	}
	hostOutput := []templates.Output{
		{Name: "ca.tpl", Type: templates.File, Comment: "#", Path: "/etc/ssh/ca.pub", Content: []byte(user.Type() + " " + userB64)},
	}

	tmplConfigWithUserData := &templates.Templates{
		SSH: &templates.SSHTemplates{
			User: []templates.Template{
				{Name: "include.tpl", Type: templates.File, TemplatePath: "./testdata/templates/include.tpl", Path: "ssh/include", Comment: "#"},
				{Name: "config.tpl", Type: templates.File, TemplatePath: "./testdata/templates/config.tpl", Path: "ssh/config", Comment: "#"},
			},
			Host: []templates.Template{
				{
					Name:         "sshd_config.tpl",
					Type:         templates.File,
					TemplatePath: "./testdata/templates/sshd_config.tpl",
					Path:         "/etc/ssh/sshd_config",
					Comment:      "#",
					RequiredData: []string{"Certificate", "Key"},
				},
			},
		},
		Data: map[string]interface{}{
			"Step": &templates.Step{
				SSH: templates.StepSSH{
					UserKey: user,
					HostKey: host,
				},
			},
		},
	}
	userOutputWithUserData := []templates.Output{
		{Name: "include.tpl", Type: templates.File, Comment: "#", Path: "ssh/include", Content: []byte("Host *\n\tInclude /home/user/.step/ssh/config")},
		{Name: "config.tpl", Type: templates.File, Comment: "#", Path: "ssh/config", Content: []byte("Match exec \"step ssh check-host %h\"\n\tUserKnownHostsFile /home/user/.step/ssh/known_hosts\n\tProxyCommand step ssh proxycommand %r %h %p\n")},
	}
	hostOutputWithUserData := []templates.Output{
		{Name: "sshd_config.tpl", Type: templates.File, Comment: "#", Path: "/etc/ssh/sshd_config", Content: []byte("Match all\n\tTrustedUserCAKeys /etc/ssh/ca.pub\n\tHostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub\n\tHostKey /etc/ssh/ssh_host_ecdsa_key")},
	}

	tmplConfigUserIncludes := &templates.Templates{
		SSH: &templates.SSHTemplates{
			User: []templates.Template{
				{Name: "step_includes.tpl", Type: templates.PrependLine, TemplatePath: "./testdata/templates/step_includes.tpl", Path: "${STEPPATH}/ssh/includes", Comment: "#"},
			},
		},
		Data: map[string]interface{}{
			"Step": &templates.Step{
				SSH: templates.StepSSH{
					UserKey: user,
					HostKey: host,
				},
			},
		},
	}

	userOutputEmptyData := []templates.Output{
		{Name: "step_includes.tpl", Type: templates.File, Comment: "#", Path: "ssh/includes", Content: []byte("Include \"<no value>/ssh/config\"\n")},
	}
	userOutputWithoutTemplateVersion := []templates.Output{
		{Name: "step_includes.tpl", Type: templates.File, Comment: "#", Path: "ssh/includes", Content: []byte("Include \"/home/user/.step/ssh/config\"\n")},
	}
	userOutputWithTemplateVersion := []templates.Output{
		{Name: "step_includes.tpl", Type: templates.PrependLine, Comment: "#", Path: "${STEPPATH}/ssh/includes", Content: []byte("Include \"/home/user/.step/ssh/config\"\n")},
	}

	tmplConfigErr := &templates.Templates{
		SSH: &templates.SSHTemplates{
			User: []templates.Template{
				{Name: "error.tpl", Type: templates.File, TemplatePath: "./testdata/templates/error.tpl", Path: "ssh/error", Comment: "#"},
			},
			Host: []templates.Template{
				{Name: "error.tpl", Type: templates.File, TemplatePath: "./testdata/templates/error.tpl", Path: "ssh/error", Comment: "#"},
			},
		},
	}

	tmplConfigFail := &templates.Templates{
		SSH: &templates.SSHTemplates{
			User: []templates.Template{
				{Name: "fail.tpl", Type: templates.File, TemplatePath: "./testdata/templates/fail.tpl", Path: "ssh/fail", Comment: "#"},
			},
		},
	}

	type fields struct {
		templates  *templates.Templates
		userSigner ssh.Signer
		hostSigner ssh.Signer
	}
	type args struct {
		typ  string
		data map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []templates.Output
		wantErr bool
	}{
		{"user", fields{tmplConfig, userSigner, hostSigner}, args{"user", nil}, userOutput, false},
		{"user", fields{tmplConfig, userSigner, nil}, args{"user", nil}, userOutput, false},
		{"host", fields{tmplConfig, userSigner, hostSigner}, args{"host", nil}, hostOutput, false},
		{"host", fields{tmplConfig, nil, hostSigner}, args{"host", nil}, hostOutput, false},
		{"userWithData", fields{tmplConfigWithUserData, userSigner, hostSigner}, args{"user", map[string]string{"StepPath": "/home/user/.step"}}, userOutputWithUserData, false},
		{"hostWithData", fields{tmplConfigWithUserData, userSigner, hostSigner}, args{"host", map[string]string{"Certificate": "ssh_host_ecdsa_key-cert.pub", "Key": "ssh_host_ecdsa_key"}}, hostOutputWithUserData, false},
		{"userIncludesEmptyData", fields{tmplConfigUserIncludes, userSigner, hostSigner}, args{"user", nil}, userOutputEmptyData, false},
		{"userIncludesWithoutTemplateVersion", fields{tmplConfigUserIncludes, userSigner, hostSigner}, args{"user", map[string]string{"StepPath": "/home/user/.step"}}, userOutputWithoutTemplateVersion, false},
		{"userIncludesWithTemplateVersion", fields{tmplConfigUserIncludes, userSigner, hostSigner}, args{"user", map[string]string{"StepPath": "/home/user/.step", "StepSSHTemplateVersion": "v2"}}, userOutputWithTemplateVersion, false},
		{"disabled", fields{tmplConfig, nil, nil}, args{"host", nil}, nil, true},
		{"badType", fields{tmplConfig, userSigner, hostSigner}, args{"bad", nil}, nil, true},
		{"userError", fields{tmplConfigErr, userSigner, hostSigner}, args{"user", nil}, nil, true},
		{"hostError", fields{tmplConfigErr, userSigner, hostSigner}, args{"host", map[string]string{"Function": "foo"}}, nil, true},
		{"noTemplates", fields{nil, userSigner, hostSigner}, args{"user", nil}, nil, true},
		{"missingData", fields{tmplConfigWithUserData, userSigner, hostSigner}, args{"host", map[string]string{"Certificate": "ssh_host_ecdsa_key-cert.pub"}}, nil, true},
		{"failError", fields{tmplConfigFail, userSigner, hostSigner}, args{"user", nil}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuthority(t)
			a.templates = tt.fields.templates
			a.sshCAUserCertSignKey = tt.fields.userSigner
			a.sshCAHostCertSignKey = tt.fields.hostSigner

			got, err := a.GetSSHConfig(context.Background(), tt.args.typ, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.GetSSHConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.GetSSHConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthority_CheckSSHHost(t *testing.T) {
	type fields struct {
		exists bool
		err    error
	}
	type args struct {
		ctx       context.Context
		principal string
		token     string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{"true", fields{true, nil}, args{context.Background(), "foo.internal.com", ""}, true, false},
		{"false", fields{false, nil}, args{context.Background(), "foo.internal.com", ""}, false, false},
		{"notImplemented", fields{false, db.ErrNotImplemented}, args{context.Background(), "foo.internal.com", ""}, false, true},
		{"notImplemented", fields{true, db.ErrNotImplemented}, args{context.Background(), "foo.internal.com", ""}, false, true},
		{"internal", fields{false, fmt.Errorf("an error")}, args{context.Background(), "foo.internal.com", ""}, false, true},
		{"internal", fields{true, fmt.Errorf("an error")}, args{context.Background(), "foo.internal.com", ""}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuthority(t)
			a.db = &db.MockAuthDB{
				MIsSSHHost: func(_ string) (bool, error) {
					return tt.fields.exists, tt.fields.err
				},
			}
			got, err := a.CheckSSHHost(tt.args.ctx, tt.args.principal, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.CheckSSHHost() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Authority.CheckSSHHost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSHConfig_Validate(t *testing.T) {
	key, err := jose.GenerateJWK("EC", "P-256", "", "sig", "", 0)
	assert.FatalError(t, err)

	tests := []struct {
		name      string
		sshConfig *SSHConfig
		wantErr   bool
	}{
		{"nil", nil, false},
		{"ok", &SSHConfig{Keys: []*SSHPublicKey{{Type: "user", Key: key.Public()}}}, false},
		{"ok", &SSHConfig{Keys: []*SSHPublicKey{{Type: "host", Key: key.Public()}}}, false},
		{"badType", &SSHConfig{Keys: []*SSHPublicKey{{Type: "bad", Key: key.Public()}}}, true},
		{"badKey", &SSHConfig{Keys: []*SSHPublicKey{{Type: "user", Key: *key}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if err := tt.sshConfig.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("SSHConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthority_GetSSHBastion(t *testing.T) {
	bastion := &Bastion{
		Hostname: "bastion.local",
		Port:     "2222",
	}
	type fields struct {
		config         *Config
		sshBastionFunc func(ctx context.Context, user, hostname string) (*Bastion, error)
	}
	type args struct {
		user     string
		hostname string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Bastion
		wantErr bool
	}{
		{"config", fields{&Config{SSH: &SSHConfig{Bastion: bastion}}, nil}, args{"user", "host.local"}, bastion, false},
		{"bastion", fields{&Config{SSH: &SSHConfig{Bastion: bastion}}, nil}, args{"user", "bastion.local"}, nil, false},
		{"nil", fields{&Config{SSH: &SSHConfig{Bastion: nil}}, nil}, args{"user", "host.local"}, nil, false},
		{"empty", fields{&Config{SSH: &SSHConfig{Bastion: &Bastion{}}}, nil}, args{"user", "host.local"}, nil, false},
		{"func", fields{&Config{}, func(_ context.Context, _, _ string) (*Bastion, error) { return bastion, nil }}, args{"user", "host.local"}, bastion, false},
		{"func err", fields{&Config{}, func(_ context.Context, _, _ string) (*Bastion, error) { return nil, errors.New("foo") }}, args{"user", "host.local"}, nil, true},
		{"error", fields{&Config{SSH: nil}, nil}, args{"user", "host.local"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authority{
				config:         tt.fields.config,
				sshBastionFunc: tt.fields.sshBastionFunc,
			}
			got, err := a.GetSSHBastion(context.Background(), tt.args.user, tt.args.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authority.GetSSHBastion() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err != nil {
				var sc render.StatusCodedError
				assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authority.GetSSHBastion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthority_GetSSHHosts(t *testing.T) {
	a := testAuthority(t)

	type test struct {
		getHostsFunc func(context.Context, *x509.Certificate) ([]Host, error)
		auth         *Authority
		cert         *x509.Certificate
		cmp          func(got []Host)
		err          error
		code         int
	}
	tests := map[string]func(t *testing.T) *test{
		"fail/getHostsFunc-fail": func(t *testing.T) *test {
			return &test{
				getHostsFunc: func(ctx context.Context, cert *x509.Certificate) ([]Host, error) {
					return nil, errors.New("force")
				},
				cert: &x509.Certificate{},
				err:  errors.New("getSSHHosts: force"),
				code: http.StatusInternalServerError,
			}
		},
		"ok/getHostsFunc-defined": func(t *testing.T) *test {
			hosts := []Host{
				{HostID: "1", Hostname: "foo"},
				{HostID: "2", Hostname: "bar"},
			}

			return &test{
				getHostsFunc: func(ctx context.Context, cert *x509.Certificate) ([]Host, error) {
					return hosts, nil
				},
				cert: &x509.Certificate{},
				cmp: func(got []Host) {
					assert.Equals(t, got, hosts)
				},
			}
		},
		"fail/db-get-fail": func(t *testing.T) *test {
			return &test{
				auth: testAuthority(t, WithDatabase(&db.MockAuthDB{
					MGetSSHHostPrincipals: func() ([]string, error) {
						return nil, errors.New("force")
					},
				})),
				cert: &x509.Certificate{},
				err:  errors.New("getSSHHosts: force"),
				code: http.StatusInternalServerError,
			}
		},
		"ok": func(t *testing.T) *test {
			return &test{
				auth: testAuthority(t, WithDatabase(&db.MockAuthDB{
					MGetSSHHostPrincipals: func() ([]string, error) {
						return []string{"foo", "bar"}, nil
					},
				})),
				cert: &x509.Certificate{},
				cmp: func(got []Host) {
					assert.Equals(t, got, []Host{
						{Hostname: "foo"},
						{Hostname: "bar"},
					})
				},
			}
		},
	}
	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			auth := tc.auth
			if auth == nil {
				auth = a
			}
			auth.sshGetHostsFunc = tc.getHostsFunc

			hosts, err := auth.GetSSHHosts(context.Background(), tc.cert)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equals(t, sc.StatusCode(), tc.code)
					}
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					tc.cmp(hosts)
				}
			}
		})
	}
}

func TestAuthority_RekeySSH(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	pub, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)
	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	signer, err := ssh.NewSignerFromKey(signKey)
	assert.FatalError(t, err)

	userOptions := sshTestModifier{
		CertType: ssh.UserCert,
	}

	now := time.Now().UTC()

	a := testAuthority(t)
	a.db = &db.MockAuthDB{
		MIsSSHRevoked: func(sn string) (bool, error) {
			return false, nil
		},
	}

	type test struct {
		auth       *Authority
		userSigner ssh.Signer
		hostSigner ssh.Signer
		cert       *ssh.Certificate
		key        ssh.PublicKey
		signOpts   []provisioner.SignOption
		cmpResult  func(old, n *ssh.Certificate)
		err        error
		code       int
	}
	tests := map[string]func(t *testing.T) *test{
		"fail/is-revoked": func(t *testing.T) *test {
			auth := testAuthority(t)
			auth.db = &db.MockAuthDB{
				MIsSSHRevoked: func(sn string) (bool, error) {
					return true, nil
				},
			}
			return &test{
				auth:       auth,
				userSigner: signer,
				hostSigner: signer,
				cert: &ssh.Certificate{
					Serial:          1234567890,
					ValidAfter:      uint64(now.Unix()),
					ValidBefore:     uint64(now.Add(time.Hour).Unix()),
					CertType:        ssh.UserCert,
					ValidPrincipals: []string{"foo", "bar"},
					KeyId:           "foo",
				},
				key:      pub,
				signOpts: []provisioner.SignOption{},
				err:      errors.New("authority.authorizeSSHCertificate: certificate has been revoked"),
				code:     http.StatusUnauthorized,
			}
		},
		"fail/is-revoked-error": func(t *testing.T) *test {
			auth := testAuthority(t)
			auth.db = &db.MockAuthDB{
				MIsSSHRevoked: func(sn string) (bool, error) {
					return false, errors.New("an error")
				},
			}
			return &test{
				auth:       auth,
				userSigner: signer,
				hostSigner: signer,
				cert: &ssh.Certificate{
					Serial:          1234567890,
					ValidAfter:      uint64(now.Unix()),
					ValidBefore:     uint64(now.Add(time.Hour).Unix()),
					CertType:        ssh.UserCert,
					ValidPrincipals: []string{"foo", "bar"},
					KeyId:           "foo",
				},
				key:      pub,
				signOpts: []provisioner.SignOption{},
				err:      errors.New("authority.authorizeSSHCertificate: an error"),
				code:     http.StatusInternalServerError,
			}
		},
		"fail/opts-type": func(t *testing.T) *test {
			return &test{
				userSigner: signer,
				hostSigner: signer,
				key:        pub,
				signOpts:   []provisioner.SignOption{userOptions},
				err:        errors.New("rekeySSH; invalid extra option type"),
				code:       http.StatusInternalServerError,
			}
		},
		"fail/old-cert-validAfter": func(t *testing.T) *test {
			return &test{
				userSigner: signer,
				hostSigner: signer,
				cert:       &ssh.Certificate{},
				key:        pub,
				signOpts:   []provisioner.SignOption{},
				err:        errors.New("cannot rekey a certificate without validity period"),
				code:       http.StatusBadRequest,
			}
		},
		"fail/old-cert-validBefore": func(t *testing.T) *test {
			return &test{
				userSigner: signer,
				hostSigner: signer,
				cert:       &ssh.Certificate{ValidAfter: uint64(now.Unix())},
				key:        pub,
				signOpts:   []provisioner.SignOption{},
				err:        errors.New("cannot rekey a certificate without validity period"),
				code:       http.StatusBadRequest,
			}
		},
		"fail/old-cert-no-user-key": func(t *testing.T) *test {
			return &test{
				userSigner: nil,
				hostSigner: signer,
				cert:       &ssh.Certificate{ValidAfter: uint64(now.Unix()), ValidBefore: uint64(now.Add(10 * time.Minute).Unix()), CertType: ssh.UserCert},
				key:        pub,
				signOpts:   []provisioner.SignOption{},
				err:        errors.New("rekeySSH; user certificate signing is not enabled"),
				code:       http.StatusNotImplemented,
			}
		},
		"fail/old-cert-no-host-key": func(t *testing.T) *test {
			return &test{
				userSigner: signer,
				hostSigner: nil,
				cert:       &ssh.Certificate{ValidAfter: uint64(now.Unix()), ValidBefore: uint64(now.Add(10 * time.Minute).Unix()), CertType: ssh.HostCert},
				key:        pub,
				signOpts:   []provisioner.SignOption{},
				err:        errors.New("rekeySSH; host certificate signing is not enabled"),
				code:       http.StatusNotImplemented,
			}
		},
		"fail/unexpected-old-cert-type": func(t *testing.T) *test {
			return &test{
				userSigner: signer,
				hostSigner: signer,
				cert:       &ssh.Certificate{ValidAfter: uint64(now.Unix()), ValidBefore: uint64(now.Add(10 * time.Minute).Unix()), CertType: 0},
				key:        pub,
				signOpts:   []provisioner.SignOption{},
				err:        errors.New("unexpected certificate type '0'"),
				code:       http.StatusBadRequest,
			}
		},
		"fail/db-store": func(t *testing.T) *test {
			return &test{
				auth: testAuthority(t, WithDatabase(&db.MockAuthDB{
					MIsSSHRevoked: func(sn string) (bool, error) {
						return false, nil
					},
					MStoreSSHCertificate: func(cert *ssh.Certificate) error {
						return errors.New("force")
					},
				})),
				userSigner: signer,
				hostSigner: nil,
				cert:       &ssh.Certificate{ValidAfter: uint64(now.Unix()), ValidBefore: uint64(now.Add(10 * time.Minute).Unix()), CertType: ssh.UserCert},
				key:        pub,
				signOpts:   []provisioner.SignOption{},
				err:        errors.New("rekeySSH; error storing certificate in db: force"),
				code:       http.StatusInternalServerError,
			}
		},
		"ok": func(t *testing.T) *test {
			va1 := now.Add(-24 * time.Hour)
			vb1 := now.Add(-23 * time.Hour)
			return &test{
				userSigner: signer,
				hostSigner: nil,
				cert: &ssh.Certificate{
					ValidAfter:      uint64(va1.Unix()),
					ValidBefore:     uint64(vb1.Unix()),
					CertType:        ssh.UserCert,
					ValidPrincipals: []string{"foo", "bar"},
					KeyId:           "foo",
				},
				key:      pub,
				signOpts: []provisioner.SignOption{},
				cmpResult: func(old, n *ssh.Certificate) {
					assert.Equals(t, n.CertType, old.CertType)
					assert.Equals(t, n.ValidPrincipals, old.ValidPrincipals)
					assert.Equals(t, n.KeyId, old.KeyId)

					assert.True(t, n.ValidAfter > uint64(now.Add(-5*time.Minute).Unix()))
					assert.True(t, n.ValidAfter < uint64(now.Add(5*time.Minute).Unix()))

					l8r := now.Add(1 * time.Hour)
					assert.True(t, n.ValidBefore > uint64(l8r.Add(-5*time.Minute).Unix()))
					assert.True(t, n.ValidBefore < uint64(l8r.Add(5*time.Minute).Unix()))
				},
			}
		},
	}
	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			auth := tc.auth
			if auth == nil {
				auth = a
			}
			a.sshCAUserCertSignKey = tc.userSigner
			a.sshCAHostCertSignKey = tc.hostSigner

			cert, err := auth.RekeySSH(context.Background(), tc.cert, tc.key, tc.signOpts...)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					var sc render.StatusCodedError
					if assert.True(t, errors.As(err, &sc), "error does not implement StatusCodedError interface") {
						assert.Equals(t, sc.StatusCode(), tc.code)
					}
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					tc.cmpResult(tc.cert, cert)
				}
			}
		})
	}
}

func TestIsValidForAddUser(t *testing.T) {
	type args struct {
		cert *ssh.Certificate
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{&ssh.Certificate{CertType: ssh.UserCert, ValidPrincipals: []string{"john"}}}, false},
		{"ok oidc", args{&ssh.Certificate{CertType: ssh.UserCert, ValidPrincipals: []string{"jane", "jane@smallstep.com"}}}, false},
		{"fail at", args{&ssh.Certificate{CertType: ssh.UserCert, ValidPrincipals: []string{"jane", "@smallstep.com"}}}, true},
		{"fail host", args{&ssh.Certificate{CertType: ssh.HostCert, ValidPrincipals: []string{"john"}}}, true},
		{"fail principals", args{&ssh.Certificate{CertType: ssh.UserCert, ValidPrincipals: []string{"john", "jane"}}}, true},
		{"fail no principals", args{&ssh.Certificate{CertType: ssh.UserCert, ValidPrincipals: []string{}}}, true},
		{"fail extra principals", args{&ssh.Certificate{CertType: ssh.UserCert, ValidPrincipals: []string{"john", "jane", "doe"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := IsValidForAddUser(tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("IsValidForAddUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
