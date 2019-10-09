package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/logging"
	"golang.org/x/crypto/ssh"
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
	type fields struct {
		PublicKey        []byte
		OTT              string
		CertType         string
		Principals       []string
		ValidAfter       TimeDuration
		ValidBefore      TimeDuration
		AddUserPublicKey []byte
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok-empty", fields{[]byte("Zm9v"), "ott", "", []string{"user"}, TimeDuration{}, TimeDuration{}, nil}, false},
		{"ok-user", fields{[]byte("Zm9v"), "ott", "user", []string{"user"}, TimeDuration{}, TimeDuration{}, nil}, false},
		{"ok-host", fields{[]byte("Zm9v"), "ott", "host", []string{"user"}, TimeDuration{}, TimeDuration{}, nil}, false},
		{"key", fields{nil, "ott", "user", []string{"user"}, TimeDuration{}, TimeDuration{}, nil}, true},
		{"key", fields{[]byte(""), "ott", "user", []string{"user"}, TimeDuration{}, TimeDuration{}, nil}, true},
		{"type", fields{[]byte("Zm9v"), "ott", "foo", []string{"user"}, TimeDuration{}, TimeDuration{}, nil}, true},
		{"ott", fields{[]byte("Zm9v"), "", "user", []string{"user"}, TimeDuration{}, TimeDuration{}, nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SignSSHRequest{
				PublicKey:        tt.fields.PublicKey,
				OTT:              tt.fields.OTT,
				CertType:         tt.fields.CertType,
				Principals:       tt.fields.Principals,
				ValidAfter:       tt.fields.ValidAfter,
				ValidBefore:      tt.fields.ValidBefore,
				AddUserPublicKey: tt.fields.AddUserPublicKey,
			}
			if err := s.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("SignSSHRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_caHandler_SignSSH(t *testing.T) {
	user, err := getSignedUserCertificate()
	assert.FatalError(t, err)
	host, err := getSignedHostCertificate()
	assert.FatalError(t, err)

	userB64 := base64.StdEncoding.EncodeToString(user.Marshal())
	hostB64 := base64.StdEncoding.EncodeToString(host.Marshal())

	userReq, err := json.Marshal(SignSSHRequest{
		PublicKey: user.Key.Marshal(),
		OTT:       "ott",
	})
	assert.FatalError(t, err)
	hostReq, err := json.Marshal(SignSSHRequest{
		PublicKey: host.Key.Marshal(),
		OTT:       "ott",
	})
	assert.FatalError(t, err)
	userAddReq, err := json.Marshal(SignSSHRequest{
		PublicKey:        user.Key.Marshal(),
		OTT:              "ott",
		AddUserPublicKey: user.Key.Marshal(),
	})
	assert.FatalError(t, err)

	tests := []struct {
		name        string
		req         []byte
		authErr     error
		signCert    *ssh.Certificate
		signErr     error
		addUserCert *ssh.Certificate
		addUserErr  error
		body        []byte
		statusCode  int
	}{
		{"ok-user", userReq, nil, user, nil, nil, nil, []byte(fmt.Sprintf(`{"crt":"%s"}`, userB64)), http.StatusCreated},
		{"ok-host", hostReq, nil, host, nil, nil, nil, []byte(fmt.Sprintf(`{"crt":"%s"}`, hostB64)), http.StatusCreated},
		{"ok-user-add", userAddReq, nil, user, nil, user, nil, []byte(fmt.Sprintf(`{"crt":"%s","addUserCrt":"%s"}`, userB64, userB64)), http.StatusCreated},
		{"fail-body", []byte("bad-json"), nil, nil, nil, nil, nil, nil, http.StatusBadRequest},
		{"fail-validate", []byte("{}"), nil, nil, nil, nil, nil, nil, http.StatusBadRequest},
		{"fail-publicKey", []byte(`{"publicKey":"Zm9v","ott":"ott"}`), nil, nil, nil, nil, nil, nil, http.StatusBadRequest},
		{"fail-publicKey", []byte(fmt.Sprintf(`{"publicKey":"%s","ott":"ott","addUserPublicKey":"Zm9v"}`, base64.StdEncoding.EncodeToString(user.Key.Marshal()))), nil, nil, nil, nil, nil, nil, http.StatusBadRequest},
		{"fail-authorize", userReq, fmt.Errorf("an-error"), nil, nil, nil, nil, nil, http.StatusUnauthorized},
		{"fail-signSSH", userReq, nil, nil, fmt.Errorf("an-error"), nil, nil, nil, http.StatusForbidden},
		{"fail-SignSSHAddUser", userAddReq, nil, user, nil, nil, fmt.Errorf("an-error"), nil, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := New(&mockAuthority{
				authorizeSign: func(ott string) ([]provisioner.SignOption, error) {
					return []provisioner.SignOption{}, tt.authErr
				},
				signSSH: func(key ssh.PublicKey, opts provisioner.SSHOptions, signOpts ...provisioner.SignOption) (*ssh.Certificate, error) {
					return tt.signCert, tt.signErr
				},
				signSSHAddUser: func(key ssh.PublicKey, cert *ssh.Certificate) (*ssh.Certificate, error) {
					return tt.addUserCert, tt.addUserErr
				},
			}).(*caHandler)

			req := httptest.NewRequest("POST", "http://example.com/sign-ssh", bytes.NewReader(tt.req))
			w := httptest.NewRecorder()
			h.SignSSH(logging.NewResponseLogger(w), req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.Root StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.Root unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), tt.body) {
					t.Errorf("caHandler.Root Body = %s, wants %s", body, tt.body)
				}
			}
		})
	}
}
