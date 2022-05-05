package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/certificates/templates"
)

var (
	sshSignerKey = mustKey()
	sshUserKey   = mustKey()
	sshHostKey   = mustKey()
)

func mustKey() *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv
}

func signSSHCertificate(cert *ssh.Certificate) error {
	signerKey, err := ssh.NewPublicKey(sshSignerKey.Public())
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromSigner(sshSignerKey)
	if err != nil {
		return err
	}
	cert.SignatureKey = signerKey
	data := cert.Marshal()
	data = data[:len(data)-4]
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return err
	}
	cert.Signature = sig
	return nil
}

func getSignedUserCertificate() (*ssh.Certificate, error) {
	key, err := ssh.NewPublicKey(sshUserKey.Public())
	if err != nil {
		return nil, err
	}
	t := time.Now()
	cert := &ssh.Certificate{
		Nonce:           []byte("1234567890"),
		Key:             key,
		Serial:          1234567890,
		CertType:        ssh.UserCert,
		KeyId:           "user@localhost",
		ValidPrincipals: []string{"user"},
		ValidAfter:      uint64(t.Unix()),
		ValidBefore:     uint64(t.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
		Reserved: []byte{},
	}
	if err := signSSHCertificate(cert); err != nil {
		return nil, err
	}
	return cert, nil
}

func getSignedHostCertificate() (*ssh.Certificate, error) {
	key, err := ssh.NewPublicKey(sshHostKey.Public())
	if err != nil {
		return nil, err
	}
	t := time.Now()
	cert := &ssh.Certificate{
		Nonce:           []byte("1234567890"),
		Key:             key,
		Serial:          1234567890,
		CertType:        ssh.UserCert,
		KeyId:           "internal.smallstep.com",
		ValidPrincipals: []string{"internal.smallstep.com"},
		ValidAfter:      uint64(t.Unix()),
		ValidBefore:     uint64(t.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{},
		},
		Reserved: []byte{},
	}
	if err := signSSHCertificate(cert); err != nil {
		return nil, err
	}
	return cert, nil
}

func TestSSHCertificate_MarshalJSON(t *testing.T) {
	user, err := getSignedUserCertificate()
	assert.FatalError(t, err)
	host, err := getSignedHostCertificate()
	assert.FatalError(t, err)
	userB64 := base64.StdEncoding.EncodeToString(user.Marshal())
	hostB64 := base64.StdEncoding.EncodeToString(host.Marshal())

	type fields struct {
		Certificate *ssh.Certificate
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{"nil", fields{Certificate: nil}, []byte("null"), false},
		{"user", fields{Certificate: user}, []byte(`"` + userB64 + `"`), false},
		{"user", fields{Certificate: host}, []byte(`"` + hostB64 + `"`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := SSHCertificate{
				Certificate: tt.fields.Certificate,
			}
			got, err := c.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("SSHCertificate.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SSHCertificate.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSHCertificate_UnmarshalJSON(t *testing.T) {
	user, err := getSignedUserCertificate()
	assert.FatalError(t, err)
	host, err := getSignedHostCertificate()
	assert.FatalError(t, err)
	userB64 := base64.StdEncoding.EncodeToString(user.Marshal())
	hostB64 := base64.StdEncoding.EncodeToString(host.Marshal())
	keyB64 := base64.StdEncoding.EncodeToString(user.Key.Marshal())

	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *ssh.Certificate
		wantErr bool
	}{
		{"null", args{[]byte(`null`)}, nil, false},
		{"empty", args{[]byte(`""`)}, nil, false},
		{"user", args{[]byte(`"` + userB64 + `"`)}, user, false},
		{"host", args{[]byte(`"` + hostB64 + `"`)}, host, false},
		{"bad-string", args{[]byte(userB64)}, nil, true},
		{"bad-base64", args{[]byte(`"this-is-not-base64"`)}, nil, true},
		{"bad-key", args{[]byte(`"bm90LWEta2V5"`)}, nil, true},
		{"bat-cert", args{[]byte(`"` + keyB64 + `"`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &SSHCertificate{}
			if err := c.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("SSHCertificate.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.want, c.Certificate) {
				t.Errorf("SSHCertificate.UnmarshalJSON() got = %v, want %v\n", c.Certificate, tt.want)
			}
		})
	}
}

func TestSignSSHRequest_Validate(t *testing.T) {
	csr := parseCertificateRequest(csrPEM)
	badCSR := parseCertificateRequest(csrPEM)
	badCSR.SignatureAlgorithm = x509.SHA1WithRSA

	type fields struct {
		PublicKey        []byte
		OTT              string
		CertType         string
		Principals       []string
		ValidAfter       TimeDuration
		ValidBefore      TimeDuration
		AddUserPublicKey []byte
		KeyID            string
		IdentityCSR      CertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok-empty", fields{[]byte("Zm9v"), "ott", "", []string{"user"}, TimeDuration{}, TimeDuration{}, nil, "", CertificateRequest{}}, false},
		{"ok-user", fields{[]byte("Zm9v"), "ott", "user", []string{"user"}, TimeDuration{}, TimeDuration{}, nil, "", CertificateRequest{}}, false},
		{"ok-host", fields{[]byte("Zm9v"), "ott", "host", []string{"user"}, TimeDuration{}, TimeDuration{}, nil, "", CertificateRequest{}}, false},
		{"ok-keyID", fields{[]byte("Zm9v"), "ott", "user", []string{"user"}, TimeDuration{}, TimeDuration{}, nil, "key-id", CertificateRequest{}}, false},
		{"ok-identityCSR", fields{[]byte("Zm9v"), "ott", "user", []string{"user"}, TimeDuration{}, TimeDuration{}, nil, "key-id", CertificateRequest{CertificateRequest: csr}}, false},
		{"key", fields{nil, "ott", "user", []string{"user"}, TimeDuration{}, TimeDuration{}, nil, "", CertificateRequest{}}, true},
		{"key", fields{[]byte(""), "ott", "user", []string{"user"}, TimeDuration{}, TimeDuration{}, nil, "", CertificateRequest{}}, true},
		{"type", fields{[]byte("Zm9v"), "ott", "foo", []string{"user"}, TimeDuration{}, TimeDuration{}, nil, "", CertificateRequest{}}, true},
		{"ott", fields{[]byte("Zm9v"), "", "user", []string{"user"}, TimeDuration{}, TimeDuration{}, nil, "", CertificateRequest{}}, true},
		{"identityCSR", fields{[]byte("Zm9v"), "ott", "user", []string{"user"}, TimeDuration{}, TimeDuration{}, nil, "key-id", CertificateRequest{CertificateRequest: badCSR}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SSHSignRequest{
				PublicKey:        tt.fields.PublicKey,
				OTT:              tt.fields.OTT,
				CertType:         tt.fields.CertType,
				Principals:       tt.fields.Principals,
				ValidAfter:       tt.fields.ValidAfter,
				ValidBefore:      tt.fields.ValidBefore,
				AddUserPublicKey: tt.fields.AddUserPublicKey,
				KeyID:            tt.fields.KeyID,
				IdentityCSR:      tt.fields.IdentityCSR,
			}
			if err := s.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("SignSSHRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_SSHSign(t *testing.T) {
	user, err := getSignedUserCertificate()
	assert.FatalError(t, err)
	host, err := getSignedHostCertificate()
	assert.FatalError(t, err)

	userB64 := base64.StdEncoding.EncodeToString(user.Marshal())
	hostB64 := base64.StdEncoding.EncodeToString(host.Marshal())

	userReq, err := json.Marshal(SSHSignRequest{
		PublicKey: user.Key.Marshal(),
		OTT:       "ott",
	})
	assert.FatalError(t, err)
	hostReq, err := json.Marshal(SSHSignRequest{
		PublicKey: host.Key.Marshal(),
		OTT:       "ott",
	})
	assert.FatalError(t, err)
	userAddReq, err := json.Marshal(SSHSignRequest{
		PublicKey:        user.Key.Marshal(),
		OTT:              "ott",
		AddUserPublicKey: user.Key.Marshal(),
	})
	assert.FatalError(t, err)
	userIdentityReq, err := json.Marshal(SSHSignRequest{
		PublicKey:   user.Key.Marshal(),
		OTT:         "ott",
		IdentityCSR: CertificateRequest{parseCertificateRequest(csrPEM)},
	})
	assert.FatalError(t, err)
	identityCerts := []*x509.Certificate{
		parseCertificate(certPEM),
	}
	identityCertsPEM := []byte(`"` + strings.ReplaceAll(certPEM, "\n", `\n`) + `\n"`)

	tests := []struct {
		name         string
		req          []byte
		authErr      error
		signCert     *ssh.Certificate
		signErr      error
		addUserCert  *ssh.Certificate
		addUserErr   error
		tlsSignCerts []*x509.Certificate
		tlsSignErr   error
		body         []byte
		statusCode   int
	}{
		{"ok-user", userReq, nil, user, nil, nil, nil, nil, nil, []byte(fmt.Sprintf(`{"crt":%q}`, userB64)), http.StatusCreated},
		{"ok-host", hostReq, nil, host, nil, nil, nil, nil, nil, []byte(fmt.Sprintf(`{"crt":%q}`, hostB64)), http.StatusCreated},
		{"ok-user-add", userAddReq, nil, user, nil, user, nil, nil, nil, []byte(fmt.Sprintf(`{"crt":%q,"addUserCrt":%q}`, userB64, userB64)), http.StatusCreated},
		{"ok-user-identity", userIdentityReq, nil, user, nil, user, nil, identityCerts, nil, []byte(fmt.Sprintf(`{"crt":%q,"identityCrt":[%s]}`, userB64, identityCertsPEM)), http.StatusCreated},
		{"fail-body", []byte("bad-json"), nil, nil, nil, nil, nil, nil, nil, nil, http.StatusBadRequest},
		{"fail-validate", []byte("{}"), nil, nil, nil, nil, nil, nil, nil, nil, http.StatusBadRequest},
		{"fail-publicKey", []byte(`{"publicKey":"Zm9v","ott":"ott"}`), nil, nil, nil, nil, nil, nil, nil, nil, http.StatusBadRequest},
		{"fail-publicKey", []byte(fmt.Sprintf(`{"publicKey":%q,"ott":"ott","addUserPublicKey":"Zm9v"}`, base64.StdEncoding.EncodeToString(user.Key.Marshal()))), nil, nil, nil, nil, nil, nil, nil, nil, http.StatusBadRequest},
		{"fail-authorize", userReq, fmt.Errorf("an-error"), nil, nil, nil, nil, nil, nil, nil, http.StatusUnauthorized},
		{"fail-signSSH", userReq, nil, nil, fmt.Errorf("an-error"), nil, nil, nil, nil, nil, http.StatusForbidden},
		{"fail-SignSSHAddUser", userAddReq, nil, user, nil, nil, fmt.Errorf("an-error"), nil, nil, nil, http.StatusForbidden},
		{"fail-user-identity", userIdentityReq, nil, user, nil, user, nil, nil, fmt.Errorf("an-error"), nil, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{
				authorize: func(ctx context.Context, ott string) ([]provisioner.SignOption, error) {
					return []provisioner.SignOption{}, tt.authErr
				},
				signSSH: func(ctx context.Context, key ssh.PublicKey, opts provisioner.SignSSHOptions, signOpts ...provisioner.SignOption) (*ssh.Certificate, error) {
					return tt.signCert, tt.signErr
				},
				signSSHAddUser: func(ctx context.Context, key ssh.PublicKey, cert *ssh.Certificate) (*ssh.Certificate, error) {
					return tt.addUserCert, tt.addUserErr
				},
				sign: func(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
					return tt.tlsSignCerts, tt.tlsSignErr
				},
			})

			req := httptest.NewRequest("POST", "http://example.com/ssh/sign", bytes.NewReader(tt.req))
			w := httptest.NewRecorder()
			SSHSign(logging.NewResponseLogger(w), req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.SignSSH StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.SignSSH unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), tt.body) {
					t.Errorf("caHandler.SignSSH Body = %s, wants %s", body, tt.body)
				}
			}
		})
	}
}

func Test_SSHRoots(t *testing.T) {
	user, err := ssh.NewPublicKey(sshUserKey.Public())
	assert.FatalError(t, err)
	userB64 := base64.StdEncoding.EncodeToString(user.Marshal())

	host, err := ssh.NewPublicKey(sshHostKey.Public())
	assert.FatalError(t, err)
	hostB64 := base64.StdEncoding.EncodeToString(host.Marshal())

	tests := []struct {
		name       string
		keys       *authority.SSHKeys
		keysErr    error
		body       []byte
		statusCode int
	}{
		{"ok", &authority.SSHKeys{HostKeys: []ssh.PublicKey{host}, UserKeys: []ssh.PublicKey{user}}, nil, []byte(fmt.Sprintf(`{"userKey":[%q],"hostKey":[%q]}`, userB64, hostB64)), http.StatusOK},
		{"many", &authority.SSHKeys{HostKeys: []ssh.PublicKey{host, host}, UserKeys: []ssh.PublicKey{user, user}}, nil, []byte(fmt.Sprintf(`{"userKey":[%q,%q],"hostKey":[%q,%q]}`, userB64, userB64, hostB64, hostB64)), http.StatusOK},
		{"user", &authority.SSHKeys{UserKeys: []ssh.PublicKey{user}}, nil, []byte(fmt.Sprintf(`{"userKey":[%q]}`, userB64)), http.StatusOK},
		{"host", &authority.SSHKeys{HostKeys: []ssh.PublicKey{host}}, nil, []byte(fmt.Sprintf(`{"hostKey":[%q]}`, hostB64)), http.StatusOK},
		{"empty", &authority.SSHKeys{}, nil, nil, http.StatusNotFound},
		{"error", nil, fmt.Errorf("an error"), nil, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{
				getSSHRoots: func(ctx context.Context) (*authority.SSHKeys, error) {
					return tt.keys, tt.keysErr
				},
			})

			req := httptest.NewRequest("GET", "http://example.com/ssh/roots", http.NoBody)
			w := httptest.NewRecorder()
			SSHRoots(logging.NewResponseLogger(w), req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.SSHRoots StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.SSHRoots unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), tt.body) {
					t.Errorf("caHandler.SSHRoots Body = %s, wants %s", body, tt.body)
				}
			}
		})
	}
}

func Test_SSHFederation(t *testing.T) {
	user, err := ssh.NewPublicKey(sshUserKey.Public())
	assert.FatalError(t, err)
	userB64 := base64.StdEncoding.EncodeToString(user.Marshal())

	host, err := ssh.NewPublicKey(sshHostKey.Public())
	assert.FatalError(t, err)
	hostB64 := base64.StdEncoding.EncodeToString(host.Marshal())

	tests := []struct {
		name       string
		keys       *authority.SSHKeys
		keysErr    error
		body       []byte
		statusCode int
	}{
		{"ok", &authority.SSHKeys{HostKeys: []ssh.PublicKey{host}, UserKeys: []ssh.PublicKey{user}}, nil, []byte(fmt.Sprintf(`{"userKey":[%q],"hostKey":[%q]}`, userB64, hostB64)), http.StatusOK},
		{"many", &authority.SSHKeys{HostKeys: []ssh.PublicKey{host, host}, UserKeys: []ssh.PublicKey{user, user}}, nil, []byte(fmt.Sprintf(`{"userKey":[%q,%q],"hostKey":[%q,%q]}`, userB64, userB64, hostB64, hostB64)), http.StatusOK},
		{"user", &authority.SSHKeys{UserKeys: []ssh.PublicKey{user}}, nil, []byte(fmt.Sprintf(`{"userKey":[%q]}`, userB64)), http.StatusOK},
		{"host", &authority.SSHKeys{HostKeys: []ssh.PublicKey{host}}, nil, []byte(fmt.Sprintf(`{"hostKey":[%q]}`, hostB64)), http.StatusOK},
		{"empty", &authority.SSHKeys{}, nil, nil, http.StatusNotFound},
		{"error", nil, fmt.Errorf("an error"), nil, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{
				getSSHFederation: func(ctx context.Context) (*authority.SSHKeys, error) {
					return tt.keys, tt.keysErr
				},
			})

			req := httptest.NewRequest("GET", "http://example.com/ssh/federation", http.NoBody)
			w := httptest.NewRecorder()
			SSHFederation(logging.NewResponseLogger(w), req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.SSHFederation StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.SSHFederation unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), tt.body) {
					t.Errorf("caHandler.SSHFederation Body = %s, wants %s", body, tt.body)
				}
			}
		})
	}
}

func Test_SSHConfig(t *testing.T) {
	userOutput := []templates.Output{
		{Name: "config.tpl", Type: templates.File, Comment: "#", Path: "ssh/config", Content: []byte("UserKnownHostsFile /home/user/.step/ssh/known_hosts")},
		{Name: "known_host.tpl", Type: templates.File, Comment: "#", Path: "ssh/known_host", Content: []byte("@cert-authority * ecdsa-sha2-nistp256 AAAA...=")},
	}
	hostOutput := []templates.Output{
		{Name: "sshd_config.tpl", Type: templates.Snippet, Comment: "#", Path: "/etc/ssh/sshd_config", Content: []byte("TrustedUserCAKeys /etc/ssh/ca.pub")},
		{Name: "ca.tpl", Type: templates.File, Comment: "#", Path: "/etc/ssh/ca.pub", Content: []byte("ecdsa-sha2-nistp256 AAAA...=")},
	}
	userJSON, err := json.Marshal(userOutput)
	assert.FatalError(t, err)
	hostJSON, err := json.Marshal(hostOutput)
	assert.FatalError(t, err)

	tests := []struct {
		name       string
		req        string
		output     []templates.Output
		err        error
		body       []byte
		statusCode int
	}{
		{"user", `{"type":"user"}`, userOutput, nil, []byte(fmt.Sprintf(`{"userTemplates":%s}`, userJSON)), http.StatusOK},
		{"host", `{"type":"host"}`, hostOutput, nil, []byte(fmt.Sprintf(`{"hostTemplates":%s}`, hostJSON)), http.StatusOK},
		{"noType", `{}`, userOutput, nil, []byte(fmt.Sprintf(`{"userTemplates":%s}`, userJSON)), http.StatusOK},
		{"badType", `{"type":"bad"}`, userOutput, nil, nil, http.StatusBadRequest},
		{"badData", `{"type":"user","data":{"bad"}}`, userOutput, nil, nil, http.StatusBadRequest},
		{"error", `{"type": "user"}`, nil, fmt.Errorf("an error"), nil, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{
				getSSHConfig: func(ctx context.Context, typ string, data map[string]string) ([]templates.Output, error) {
					return tt.output, tt.err
				},
			})

			req := httptest.NewRequest("GET", "http://example.com/ssh/config", strings.NewReader(tt.req))
			w := httptest.NewRecorder()
			SSHConfig(logging.NewResponseLogger(w), req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.SSHConfig StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.SSHConfig unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), tt.body) {
					t.Errorf("caHandler.SSHConfig Body = %s, wants %s", body, tt.body)
				}
			}
		})
	}
}

func Test_SSHCheckHost(t *testing.T) {
	tests := []struct {
		name       string
		req        string
		exists     bool
		err        error
		body       []byte
		statusCode int
	}{
		{"true", `{"type":"host","principal":"foo.example.com"}`, true, nil, []byte(`{"exists":true}`), http.StatusOK},
		{"false", `{"type":"host","principal":"bar.example.com"}`, false, nil, []byte(`{"exists":false}`), http.StatusOK},
		{"badType", `{"type":"user","principal":"bar.example.com"}`, false, nil, nil, http.StatusBadRequest},
		{"badPrincipal", `{"type":"host","principal":""}`, false, nil, nil, http.StatusBadRequest},
		{"badRequest", `{"foo"}`, false, nil, nil, http.StatusBadRequest},
		{"error", `{"type":"host","principal":"foo.example.com"}`, false, fmt.Errorf("an error"), nil, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{
				checkSSHHost: func(ctx context.Context, principal, token string) (bool, error) {
					return tt.exists, tt.err
				},
			})

			req := httptest.NewRequest("GET", "http://example.com/ssh/check-host", strings.NewReader(tt.req))
			w := httptest.NewRecorder()
			SSHCheckHost(logging.NewResponseLogger(w), req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.SSHCheckHost StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.SSHCheckHost unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), tt.body) {
					t.Errorf("caHandler.SSHCheckHost Body = %s, wants %s", body, tt.body)
				}
			}
		})
	}
}

func Test_SSHGetHosts(t *testing.T) {
	hosts := []authority.Host{
		{HostID: "1", HostTags: []authority.HostTag{{ID: "1", Name: "group", Value: "1"}}, Hostname: "host1"},
		{HostID: "2", HostTags: []authority.HostTag{{ID: "1", Name: "group", Value: "1"}, {ID: "2", Name: "group", Value: "2"}}, Hostname: "host2"},
	}
	hostsJSON, err := json.Marshal(hosts)
	assert.FatalError(t, err)

	tests := []struct {
		name       string
		hosts      []authority.Host
		err        error
		body       []byte
		statusCode int
	}{
		{"ok", hosts, nil, []byte(fmt.Sprintf(`{"hosts":%s}`, hostsJSON)), http.StatusOK},
		{"empty (array)", []authority.Host{}, nil, []byte(`{"hosts":[]}`), http.StatusOK},
		{"empty (nil)", nil, nil, []byte(`{"hosts":null}`), http.StatusOK},
		{"error", nil, fmt.Errorf("an error"), nil, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{
				getSSHHosts: func(context.Context, *x509.Certificate) ([]authority.Host, error) {
					return tt.hosts, tt.err
				},
			})

			req := httptest.NewRequest("GET", "http://example.com/ssh/host", http.NoBody)
			w := httptest.NewRecorder()
			SSHGetHosts(logging.NewResponseLogger(w), req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.SSHGetHosts StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.SSHGetHosts unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), tt.body) {
					t.Errorf("caHandler.SSHGetHosts Body = %s, wants %s", body, tt.body)
				}
			}
		})
	}
}

func Test_SSHBastion(t *testing.T) {
	bastion := &authority.Bastion{
		Hostname: "bastion.local",
	}
	bastionPort := &authority.Bastion{
		Hostname: "bastion.local",
		Port:     "2222",
	}

	tests := []struct {
		name       string
		bastion    *authority.Bastion
		bastionErr error
		req        []byte
		body       []byte
		statusCode int
	}{
		{"ok", bastion, nil, []byte(`{"hostname":"host.local"}`), []byte(`{"hostname":"host.local","bastion":{"hostname":"bastion.local"}}`), http.StatusOK},
		{"ok", bastionPort, nil, []byte(`{"hostname":"host.local","user":"user"}`), []byte(`{"hostname":"host.local","bastion":{"hostname":"bastion.local","port":"2222"}}`), http.StatusOK},
		{"empty", nil, nil, []byte(`{"hostname":"host.local"}`), []byte(`{"hostname":"host.local"}`), http.StatusOK},
		{"bad json", bastion, nil, []byte(`bad json`), nil, http.StatusBadRequest},
		{"bad request", bastion, nil, []byte(`{"hostname": ""}`), nil, http.StatusBadRequest},
		{"error", nil, fmt.Errorf("an error"), []byte(`{"hostname":"host.local"}`), nil, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{
				getSSHBastion: func(ctx context.Context, user, hostname string) (*authority.Bastion, error) {
					return tt.bastion, tt.bastionErr
				},
			})

			req := httptest.NewRequest("POST", "http://example.com/ssh/bastion", bytes.NewReader(tt.req))
			w := httptest.NewRecorder()
			SSHBastion(logging.NewResponseLogger(w), req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.SSHBastion StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.SSHBastion unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), tt.body) {
					t.Errorf("caHandler.SSHBastion Body = %s, wants %s", body, tt.body)
				}
			}
		})
	}
}

func TestSSHPublicKey_MarshalJSON(t *testing.T) {
	key, err := ssh.NewPublicKey(sshUserKey.Public())
	assert.FatalError(t, err)
	keyB64 := base64.StdEncoding.EncodeToString(key.Marshal())

	tests := []struct {
		name      string
		publicKey *SSHPublicKey
		want      []byte
		wantErr   bool
	}{
		{"ok", &SSHPublicKey{PublicKey: key}, []byte(`"` + keyB64 + `"`), false},
		{"null", nil, []byte("null"), false},
		{"null", &SSHPublicKey{PublicKey: nil}, []byte("null"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.publicKey.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("SSHPublicKey.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SSHPublicKey.MarshalJSON() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSSHPublicKey_UnmarshalJSON(t *testing.T) {
	key, err := ssh.NewPublicKey(sshUserKey.Public())
	assert.FatalError(t, err)
	keyB64 := base64.StdEncoding.EncodeToString(key.Marshal())

	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *SSHPublicKey
		wantErr bool
	}{
		{"ok", args{[]byte(`"` + keyB64 + `"`)}, &SSHPublicKey{PublicKey: key}, false},
		{"empty", args{[]byte(`""`)}, &SSHPublicKey{}, false},
		{"null", args{[]byte(`null`)}, &SSHPublicKey{}, false},
		{"noString", args{[]byte("123")}, &SSHPublicKey{}, true},
		{"badB64", args{[]byte(`"bad"`)}, &SSHPublicKey{}, true},
		{"badKey", args{[]byte(`"Zm9vYmFyCg=="`)}, &SSHPublicKey{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &SSHPublicKey{}
			if err := p.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("SSHPublicKey.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(p, tt.want) {
				t.Errorf("SSHPublicKey.UnmarshalJSON() = %v, want %v", p, tt.want)
			}
		})
	}
}
