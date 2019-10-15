package authority

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/templates"
	"github.com/smallstep/cli/jose"
	"golang.org/x/crypto/ssh"
)

type sshTestModifier ssh.Certificate

func (m sshTestModifier) Modify(cert *ssh.Certificate) error {
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

func (m sshTestCertModifier) Modify(cert *ssh.Certificate) error {
	if m == "" {
		return nil
	}
	return fmt.Errorf(string(m))
}

type sshTestCertValidator string

func (v sshTestCertValidator) Valid(crt *ssh.Certificate) error {
	if v == "" {
		return nil
	}
	return fmt.Errorf(string(v))
}

type sshTestOptionsValidator string

func (v sshTestOptionsValidator) Valid(opts provisioner.SSHOptions) error {
	if v == "" {
		return nil
	}
	return fmt.Errorf(string(v))
}

type sshTestOptionsModifier string

func (m sshTestOptionsModifier) Option(opts provisioner.SSHOptions) provisioner.SSHCertificateModifier {
	return sshTestCertModifier(string(m))
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

	now := time.Now()

	type fields struct {
		sshCAUserCertSignKey ssh.Signer
		sshCAHostCertSignKey ssh.Signer
	}
	type args struct {
		key      ssh.PublicKey
		opts     provisioner.SSHOptions
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
		{"ok-user", fields{signer, signer}, args{pub, provisioner.SSHOptions{}, []provisioner.SignOption{userOptions}}, want{CertType: ssh.UserCert}, false},
		{"ok-host", fields{signer, signer}, args{pub, provisioner.SSHOptions{}, []provisioner.SignOption{hostOptions}}, want{CertType: ssh.HostCert}, false},
		{"ok-opts-type-user", fields{signer, signer}, args{pub, provisioner.SSHOptions{CertType: "user"}, []provisioner.SignOption{}}, want{CertType: ssh.UserCert}, false},
		{"ok-opts-type-host", fields{signer, signer}, args{pub, provisioner.SSHOptions{CertType: "host"}, []provisioner.SignOption{}}, want{CertType: ssh.HostCert}, false},
		{"ok-opts-principals", fields{signer, signer}, args{pub, provisioner.SSHOptions{CertType: "user", Principals: []string{"user"}}, []provisioner.SignOption{}}, want{CertType: ssh.UserCert, Principals: []string{"user"}}, false},
		{"ok-opts-principals", fields{signer, signer}, args{pub, provisioner.SSHOptions{CertType: "host", Principals: []string{"foo.test.com", "bar.test.com"}}, []provisioner.SignOption{}}, want{CertType: ssh.HostCert, Principals: []string{"foo.test.com", "bar.test.com"}}, false},
		{"ok-opts-valid-after", fields{signer, signer}, args{pub, provisioner.SSHOptions{CertType: "user", ValidAfter: provisioner.NewTimeDuration(now)}, []provisioner.SignOption{}}, want{CertType: ssh.UserCert, ValidAfter: uint64(now.Unix())}, false},
		{"ok-opts-valid-before", fields{signer, signer}, args{pub, provisioner.SSHOptions{CertType: "host", ValidBefore: provisioner.NewTimeDuration(now)}, []provisioner.SignOption{}}, want{CertType: ssh.HostCert, ValidBefore: uint64(now.Unix())}, false},
		{"ok-cert-validator", fields{signer, signer}, args{pub, provisioner.SSHOptions{}, []provisioner.SignOption{userOptions, sshTestCertValidator("")}}, want{CertType: ssh.UserCert}, false},
		{"ok-cert-modifier", fields{signer, signer}, args{pub, provisioner.SSHOptions{}, []provisioner.SignOption{userOptions, sshTestCertModifier("")}}, want{CertType: ssh.UserCert}, false},
		{"ok-opts-validator", fields{signer, signer}, args{pub, provisioner.SSHOptions{}, []provisioner.SignOption{userOptions, sshTestOptionsValidator("")}}, want{CertType: ssh.UserCert}, false},
		{"ok-opts-modifier", fields{signer, signer}, args{pub, provisioner.SSHOptions{}, []provisioner.SignOption{userOptions, sshTestOptionsModifier("")}}, want{CertType: ssh.UserCert}, false},
		{"fail-opts-type", fields{signer, signer}, args{pub, provisioner.SSHOptions{CertType: "foo"}, []provisioner.SignOption{}}, want{}, true},
		{"fail-cert-validator", fields{signer, signer}, args{pub, provisioner.SSHOptions{}, []provisioner.SignOption{userOptions, sshTestCertValidator("an error")}}, want{}, true},
		{"fail-cert-modifier", fields{signer, signer}, args{pub, provisioner.SSHOptions{}, []provisioner.SignOption{userOptions, sshTestCertModifier("an error")}}, want{}, true},
		{"fail-opts-validator", fields{signer, signer}, args{pub, provisioner.SSHOptions{}, []provisioner.SignOption{userOptions, sshTestOptionsValidator("an error")}}, want{}, true},
		{"fail-opts-modifier", fields{signer, signer}, args{pub, provisioner.SSHOptions{}, []provisioner.SignOption{userOptions, sshTestOptionsModifier("an error")}}, want{}, true},
		{"fail-bad-sign-options", fields{signer, signer}, args{pub, provisioner.SSHOptions{}, []provisioner.SignOption{userOptions, "wrong type"}}, want{}, true},
		{"fail-no-user-key", fields{nil, signer}, args{pub, provisioner.SSHOptions{CertType: "user"}, []provisioner.SignOption{}}, want{}, true},
		{"fail-no-host-key", fields{signer, nil}, args{pub, provisioner.SSHOptions{CertType: "host"}, []provisioner.SignOption{}}, want{}, true},
		{"fail-bad-type", fields{signer, nil}, args{pub, provisioner.SSHOptions{}, []provisioner.SignOption{sshTestModifier{CertType: 0}}}, want{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuthority(t)
			a.sshCAUserCertSignKey = tt.fields.sshCAUserCertSignKey
			a.sshCAHostCertSignKey = tt.fields.sshCAHostCertSignKey

			got, err := a.SignSSH(tt.args.key, tt.args.opts, tt.args.signOpts...)
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
			got, err := a.SignSSHAddUser(tt.args.key, tt.args.subject)
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

			got, err := a.GetSSHRoots()
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

			got, err := a.GetSSHFederation()
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
				{Name: "sshd_config.tpl", Type: templates.File, TemplatePath: "./testdata/templates/sshd_config.tpl", Path: "/etc/ssh/sshd_config", Comment: "#"},
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
		{Name: "config.tpl", Type: templates.File, Comment: "#", Path: "ssh/config", Content: []byte("Match exec \"step ssh check-host %h\"\n\tForwardAgent yes\n\tUserKnownHostsFile /home/user/.step/ssh/known_hosts")},
	}
	hostOutputWithUserData := []templates.Output{
		{Name: "sshd_config.tpl", Type: templates.File, Comment: "#", Path: "/etc/ssh/sshd_config", Content: []byte("TrustedUserCAKeys /etc/ssh/ca.pub\nHostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub\nHostKey /etc/ssh/ssh_host_ecdsa_key")},
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
		{"disabled", fields{tmplConfig, nil, nil}, args{"host", nil}, nil, true},
		{"badType", fields{tmplConfig, userSigner, hostSigner}, args{"bad", nil}, nil, true},
		{"userError", fields{tmplConfigErr, userSigner, hostSigner}, args{"user", nil}, nil, true},
		{"hostError", fields{tmplConfigErr, userSigner, hostSigner}, args{"host", map[string]string{"Function": "foo"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuthority(t)
			a.config.Templates = tt.fields.templates
			a.sshCAUserCertSignKey = tt.fields.userSigner
			a.sshCAHostCertSignKey = tt.fields.hostSigner

			got, err := a.GetSSHConfig(tt.args.typ, tt.args.data)
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
		principal string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{"true", fields{true, nil}, args{"foo.internal.com"}, true, false},
		{"false", fields{false, nil}, args{"foo.internal.com"}, false, false},
		{"notImplemented", fields{false, db.ErrNotImplemented}, args{"foo.internal.com"}, false, true},
		{"notImplemented", fields{true, db.ErrNotImplemented}, args{"foo.internal.com"}, false, true},
		{"internal", fields{false, fmt.Errorf("an error")}, args{"foo.internal.com"}, false, true},
		{"internal", fields{true, fmt.Errorf("an error")}, args{"foo.internal.com"}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := testAuthority(t)
			a.db = &MockAuthDB{
				isSSHHost: func(_ string) (bool, error) {
					return tt.fields.exists, tt.fields.err
				},
			}
			got, err := a.CheckSSHHost(tt.args.principal)
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

func TestSSHPublicKey_Validate(t *testing.T) {
	key, err := jose.GenerateJWK("EC", "P-256", "", "sig", "", 0)
	assert.FatalError(t, err)

	type fields struct {
		Type      string
		Federated bool
		Key       jose.JSONWebKey
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"user", fields{"user", true, key.Public()}, false},
		{"host", fields{"host", false, key.Public()}, false},
		{"empty", fields{"", true, key.Public()}, true},
		{"badType", fields{"bad", false, key.Public()}, true},
		{"badKey", fields{"user", false, *key}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &SSHPublicKey{
				Type:      tt.fields.Type,
				Federated: tt.fields.Federated,
				Key:       tt.fields.Key,
			}
			if err := k.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("SSHPublicKey.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSSHPublicKey_PublicKey(t *testing.T) {
	key, err := jose.GenerateJWK("EC", "P-256", "", "sig", "", 0)
	assert.FatalError(t, err)
	pub, err := ssh.NewPublicKey(key.Public().Key)
	assert.FatalError(t, err)

	type fields struct {
		publicKey ssh.PublicKey
	}
	tests := []struct {
		name   string
		fields fields
		want   ssh.PublicKey
	}{
		{"ok", fields{pub}, pub},
		{"nil", fields{nil}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &SSHPublicKey{
				publicKey: tt.fields.publicKey,
			}
			if got := k.PublicKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SSHPublicKey.PublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
