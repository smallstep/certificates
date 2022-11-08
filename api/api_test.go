package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/dsa" //nolint
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/certificates/templates"
)

const (
	rootPEM = `-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----`

	certPEM = `-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgIIE31FZVaPXTUwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMTI5MTMyNzQzWhcNMTQwNTI5MDAwMDAw
WjBpMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEYMBYGA1UEAwwPbWFp
bC5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfRrObuSW5T7q
5CnSEqefEmtH4CCv6+5EckuriNr1CjfVvqzwfAhopXkLrq45EQm8vkmf7W96XJhC
7ZM0dYi1/qOCAU8wggFLMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAa
BgNVHREEEzARgg9tYWlsLmdvb2dsZS5jb20wCwYDVR0PBAQDAgeAMGgGCCsGAQUF
BwEBBFwwWjArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nbGUuY29tL0dJQUcy
LmNydDArBggrBgEFBQcwAYYfaHR0cDovL2NsaWVudHMxLmdvb2dsZS5jb20vb2Nz
cDAdBgNVHQ4EFgQUiJxtimAuTfwb+aUtBn5UYKreKvMwDAYDVR0TAQH/BAIwADAf
BgNVHSMEGDAWgBRK3QYWG7z2aLV29YG2u2IaulqBLzAXBgNVHSAEEDAOMAwGCisG
AQQB1nkCBQEwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29nbGUuY29t
L0dJQUcyLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAH6RYHxHdcGpMpFE3oxDoFnP+
gtuBCHan2yE2GRbJ2Cw8Lw0MmuKqHlf9RSeYfd3BXeKkj1qO6TVKwCh+0HdZk283
TZZyzmEOyclm3UGFYe82P/iDFt+CeQ3NpmBg+GoaVCuWAARJN/KfglbLyyYygcQq
0SgeDh8dRKUiaW3HQSoYvTvdTuqzwK4CXsr3b5/dAOY8uMuG/IAR3FgwTbZ1dtoW
RvOTa8hYiU6A475WuZKyEHcwnGYe57u2I2KbMgcKjPniocj4QzgYsVAVKW3IwaOh
yE+vPxsiUkvQHdO2fojCkY8jg70jxM+gu59tPDNbw3Uh/2Ij310FgTHsnGQMyA==
-----END CERTIFICATE-----`

	csrPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIIEYjCCAkoCAQAwHTEbMBkGA1UEAxMSdGVzdC5zbWFsbHN0ZXAuY29tMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuCpifZfoZhYNywfpnPa21NezXgtn
wrWBFE6xhVzE7YDSIqtIsj8aR7R8zwEymxfv5j5298LUy/XSmItVH31CsKyfcGqN
QM0PZr9XY3z5V6qchGMqjzt/jqlYMBHujcxIFBfz4HATxSgKyvHqvw14ESsS2huu
7jowx+XTKbFYgKcXrjBkvOej5FXD3ehkg0jDA2UAJNdfKmrc1BBEaaqOtfh7eyU2
HU7+5gxH8C27IiCAmNj719E0B99Nu2MUw6aLFIM4xAcRga33Avevx6UuXZZIEepe
V1sihrkcnDK9Vsxkme5erXzvAoOiRusiC2iIomJHJrdRM5ReEU+N+Tl1Kxq+rk7H
/qAq78wVm07M1/GGi9SUMObZS4WuJpM6whlikIAEbv9iV+CK0sv/Jr/AADdGMmQU
lwk+Q0ZNE8p4ZuWILv/dtLDtDVBpnrrJ9e8duBtB0lGcG8MdaUCQ346EI4T0Sgx0
hJ+wMq8zYYFfPIZEHC8o9p1ywWN9ySpJ8Zj/5ubmx9v2bY67GbuVFEa8iAp+S00x
/Z8nD6/JsoKtexuHyGr3ixWFzlBqXDuugukIDFUOVDCbuGw4Io4/hEMu4Zz0TIFk
Uu/wf2z75Tt8EkosKLu2wieKcY7n7Vhog/0tqexqWlWtJH0tvq4djsGoSvA62WPs
0iXXj+aZIARPNhECAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4ICAQA0vyHIndAkIs/I
Nnz5yZWCokRjokoKv3Aj4VilyjncL+W0UIPULLU/47ZyoHVSUj2t8gknr9xu/Kd+
g/2z0RiF3CIp8IUH49w/HYWaR95glzVNAAzr8qD9UbUqloLVQW3lObSRGtezhdZO
sspw5dC+inhAb1LZhx8PVxB3SAeJ8h11IEBr0s2Hxt9viKKd7YPtIFZkZdOkVx4R
if1DMawj1P6fEomf8z7m+dmbUYTqqosbCbRL01mzEga/kF6JyH/OzpNlcsAiyM8e
BxPWH6TtPqwmyy4y7j1outmM0RnyUw5A0HmIbWh+rHpXiHVsnNqse0XfzmaxM8+z
dxYeDax8aMWZKfvY1Zew+xIxl7DtEy1BpxrZcawumJYt5+LL+bwF/OtL0inQLnw8
zyqydsXNdrpIQJnfmWPld7ThWbQw2FBE70+nFSxHeG2ULnpF3M9xf6ZNAF4gqaNE
Q7vMNPBWrJWu+A++vHY61WGET+h4lY3GFr2I8OE4IiHPQi1D7Y0+fwOmStwuRPM4
2rARcJChNdiYBkkuvs4kixKTTjdXhB8RQtuBSrJ0M1tzq2qMbm7F8G01rOg4KlXU
58jHzJwr1K7cx0lpWfGTtc5bseCGtTKmDBXTziw04yl8eE1+ZFOganixGwCtl4Tt
DCbKzWTW8lqVdp9Kyf7XEhhc2R8C5w==
-----END CERTIFICATE REQUEST-----`

	stepCertPEM = `-----BEGIN CERTIFICATE-----
MIIChTCCAiugAwIBAgIRAJ3O5T28Rdj2lr/UPjf+GAUwCgYIKoZIzj0EAwIwJDEi
MCAGA1UEAxMZU21hbGxzdGVwIEludGVybWVkaWF0ZSBDQTAeFw0xOTAyMjAyMDE1
NDNaFw0xOTAyMjEyMDE1NDNaMHExCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEW
MBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEcMBoGA1UEChMTU21hbGxzdGVwIExhYnMg
SW5jLjEfMB0GA1UEAxMWaW50ZXJuYWwuc21hbGxzdGVwLmNvbTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABC0aKrTNl+gXFuNkXisqX4/foLO3VMt+Kphngziim+fz
aJhiS9JU+oFYLTNW6HWGUD8CNzfwrmWlVsAmiJwHKlKjgfAwge0wDgYDVR0PAQH/
BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQU
JheKvlZqNv1IcgaC8WOS1Zg0i1QwHwYDVR0jBBgwFoAUu97PaFQPfuyKOeew7Hg4
5WFIAVMwIQYDVR0RBBowGIIWaW50ZXJuYWwuc21hbGxzdGVwLmNvbTBZBgwrBgEE
AYKkZMYoQAEESTBHAgEBBBVtYXJpYW5vQHNtYWxsc3RlcC5jb20EK2pPMzdkdERi
a3UtUW5hYnM1VlIwWXc2WUZGdjl3ZUExOGRwM2h0dmRFanMwCgYIKoZIzj0EAwID
SAAwRQIhAIrn17fP5CBrGtKuhyPiq6eSwryBCf8ki+k17u5a+E/LAiB24Y2E0Put
nIHOI54lAqDeF7A0y73fPRVCiJEWmuxz0g==
-----END CERTIFICATE-----`

	pubKey = `{
	"use": "sig",
	"kty": "EC",
	"kid": "oV1p0MJeGQ7qBlK6B-oyfVdBRjh_e7VSK_YSEEqgW00",
	"crv": "P-256",
	"alg": "ES256",
	"x": "p9QX4tzjxUrB0fgqRWLKUuPolDtBW681f2Qyh-uVNhk",
	"y": "CNSEloc4oLDFTX0Vywj0WiqOlh516sFQwCj6WtM8LT8"
}`

	privKey = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjEwMDAwMCwicDJzIjoiNEhBYjE0WDQ5OFM4LWxSb29JTnpqZyJ9.RbkJXGzI3kOsaP20KmZs0ELFLgpRddAE49AJHlEblw-uH_gg6SV3QA.M3MArEpHgI171lhm.gBlFySpzK9F7riBJbtLSNkb4nAw_gWokqs1jS-ZK1qxuqTK-9mtX5yILjRnftx9P9uFp5xt7rvv4Mgom1Ed4V9WtIyfNP_Cz3Pme1Eanp5nY68WCe_yG6iSB1RJdMDBUb2qBDZiBdhJim1DRXsOfgedOrNi7GGbppMlD77DEpId118owR5izA-c6Q_hg08hIE3tnMAnebDNQoF9jfEY99_AReVRH8G4hgwZEPCfXMTb3J-lowKGG4vXIbK5knFLh47SgOqG4M2M51SMS-XJ7oBz1Vjoamc90QIqKV51rvZ5m0N_sPFtxzcfV4E9yYH3XVd4O-CG4ydVKfKVyMtQ.mcKFZqBHp_n7Ytj2jz9rvw"
)

func parseCertificate(data string) *x509.Certificate {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	return cert
}

func parseCertificateRequest(data string) *x509.CertificateRequest {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to parse certificate request PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		panic("failed to parse certificate request: " + err.Error())
	}
	return csr
}

func mockMustAuthority(t *testing.T, a Authority) {
	t.Helper()
	fn := mustAuthority
	t.Cleanup(func() {
		mustAuthority = fn
	})
	mustAuthority = func(ctx context.Context) Authority {
		return a
	}
}

type mockAuthority struct {
	ret1, ret2                   interface{}
	err                          error
	authorize                    func(ctx context.Context, ott string) ([]provisioner.SignOption, error)
	authorizeRenewToken          func(ctx context.Context, ott string) (*x509.Certificate, error)
	getTLSOptions                func() *authority.TLSOptions
	root                         func(shasum string) (*x509.Certificate, error)
	sign                         func(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	renew                        func(cert *x509.Certificate) ([]*x509.Certificate, error)
	rekey                        func(oldCert *x509.Certificate, pk crypto.PublicKey) ([]*x509.Certificate, error)
	renewContext                 func(ctx context.Context, oldCert *x509.Certificate, pk crypto.PublicKey) ([]*x509.Certificate, error)
	loadProvisionerByCertificate func(cert *x509.Certificate) (provisioner.Interface, error)
	loadProvisionerByName        func(name string) (provisioner.Interface, error)
	getProvisioners              func(nextCursor string, limit int) (provisioner.List, string, error)
	revoke                       func(context.Context, *authority.RevokeOptions) error
	getEncryptedKey              func(kid string) (string, error)
	getRoots                     func() ([]*x509.Certificate, error)
	getFederation                func() ([]*x509.Certificate, error)
	getCRL                       func() ([]byte, error)
	signSSH                      func(ctx context.Context, key ssh.PublicKey, opts provisioner.SignSSHOptions, signOpts ...provisioner.SignOption) (*ssh.Certificate, error)
	signSSHAddUser               func(ctx context.Context, key ssh.PublicKey, cert *ssh.Certificate) (*ssh.Certificate, error)
	renewSSH                     func(ctx context.Context, cert *ssh.Certificate) (*ssh.Certificate, error)
	rekeySSH                     func(ctx context.Context, cert *ssh.Certificate, key ssh.PublicKey, signOpts ...provisioner.SignOption) (*ssh.Certificate, error)
	getSSHHosts                  func(ctx context.Context, cert *x509.Certificate) ([]authority.Host, error)
	getSSHRoots                  func(ctx context.Context) (*authority.SSHKeys, error)
	getSSHFederation             func(ctx context.Context) (*authority.SSHKeys, error)
	getSSHConfig                 func(ctx context.Context, typ string, data map[string]string) ([]templates.Output, error)
	checkSSHHost                 func(ctx context.Context, principal, token string) (bool, error)
	getSSHBastion                func(ctx context.Context, user string, hostname string) (*authority.Bastion, error)
	version                      func() authority.Version
}

func (m *mockAuthority) GetCertificateRevocationList() ([]byte, error) {
	if m.getCRL != nil {
		return m.getCRL()
	}

	return m.ret1.([]byte), m.err
}

// TODO: remove once Authorize is deprecated.
func (m *mockAuthority) Authorize(ctx context.Context, ott string) ([]provisioner.SignOption, error) {
	if m.authorize != nil {
		return m.authorize(ctx, ott)
	}
	return m.ret1.([]provisioner.SignOption), m.err
}

func (m *mockAuthority) AuthorizeRenewToken(ctx context.Context, ott string) (*x509.Certificate, error) {
	if m.authorizeRenewToken != nil {
		return m.authorizeRenewToken(ctx, ott)
	}
	return m.ret1.(*x509.Certificate), m.err
}

func (m *mockAuthority) GetTLSOptions() *authority.TLSOptions {
	if m.getTLSOptions != nil {
		return m.getTLSOptions()
	}
	return m.ret1.(*authority.TLSOptions)
}

func (m *mockAuthority) Root(shasum string) (*x509.Certificate, error) {
	if m.root != nil {
		return m.root(shasum)
	}
	return m.ret1.(*x509.Certificate), m.err
}

func (m *mockAuthority) Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
	if m.sign != nil {
		return m.sign(cr, opts, signOpts...)
	}
	return []*x509.Certificate{m.ret1.(*x509.Certificate), m.ret2.(*x509.Certificate)}, m.err
}

func (m *mockAuthority) Renew(cert *x509.Certificate) ([]*x509.Certificate, error) {
	if m.renew != nil {
		return m.renew(cert)
	}
	return []*x509.Certificate{m.ret1.(*x509.Certificate), m.ret2.(*x509.Certificate)}, m.err
}

func (m *mockAuthority) RenewContext(ctx context.Context, oldcert *x509.Certificate, pk crypto.PublicKey) ([]*x509.Certificate, error) {
	if m.renewContext != nil {
		return m.renewContext(ctx, oldcert, pk)
	}
	return []*x509.Certificate{m.ret1.(*x509.Certificate), m.ret2.(*x509.Certificate)}, m.err
}

func (m *mockAuthority) Rekey(oldcert *x509.Certificate, pk crypto.PublicKey) ([]*x509.Certificate, error) {
	if m.rekey != nil {
		return m.rekey(oldcert, pk)
	}
	return []*x509.Certificate{m.ret1.(*x509.Certificate), m.ret2.(*x509.Certificate)}, m.err
}

func (m *mockAuthority) GetProvisioners(nextCursor string, limit int) (provisioner.List, string, error) {
	if m.getProvisioners != nil {
		return m.getProvisioners(nextCursor, limit)
	}
	return m.ret1.(provisioner.List), m.ret2.(string), m.err
}

func (m *mockAuthority) LoadProvisionerByCertificate(cert *x509.Certificate) (provisioner.Interface, error) {
	if m.loadProvisionerByCertificate != nil {
		return m.loadProvisionerByCertificate(cert)
	}
	return m.ret1.(provisioner.Interface), m.err
}

func (m *mockAuthority) LoadProvisionerByName(name string) (provisioner.Interface, error) {
	if m.loadProvisionerByName != nil {
		return m.loadProvisionerByName(name)
	}
	return m.ret1.(provisioner.Interface), m.err
}

func (m *mockAuthority) Revoke(ctx context.Context, opts *authority.RevokeOptions) error {
	if m.revoke != nil {
		return m.revoke(ctx, opts)
	}
	return m.err
}

func (m *mockAuthority) GetEncryptedKey(kid string) (string, error) {
	if m.getEncryptedKey != nil {
		return m.getEncryptedKey(kid)
	}
	return m.ret1.(string), m.err
}

func (m *mockAuthority) GetRoots() ([]*x509.Certificate, error) {
	if m.getRoots != nil {
		return m.getRoots()
	}
	return m.ret1.([]*x509.Certificate), m.err
}

func (m *mockAuthority) GetFederation() ([]*x509.Certificate, error) {
	if m.getFederation != nil {
		return m.getFederation()
	}
	return m.ret1.([]*x509.Certificate), m.err
}

func (m *mockAuthority) SignSSH(ctx context.Context, key ssh.PublicKey, opts provisioner.SignSSHOptions, signOpts ...provisioner.SignOption) (*ssh.Certificate, error) {
	if m.signSSH != nil {
		return m.signSSH(ctx, key, opts, signOpts...)
	}
	return m.ret1.(*ssh.Certificate), m.err
}

func (m *mockAuthority) SignSSHAddUser(ctx context.Context, key ssh.PublicKey, cert *ssh.Certificate) (*ssh.Certificate, error) {
	if m.signSSHAddUser != nil {
		return m.signSSHAddUser(ctx, key, cert)
	}
	return m.ret1.(*ssh.Certificate), m.err
}

func (m *mockAuthority) RenewSSH(ctx context.Context, cert *ssh.Certificate) (*ssh.Certificate, error) {
	if m.renewSSH != nil {
		return m.renewSSH(ctx, cert)
	}
	return m.ret1.(*ssh.Certificate), m.err
}

func (m *mockAuthority) RekeySSH(ctx context.Context, cert *ssh.Certificate, key ssh.PublicKey, signOpts ...provisioner.SignOption) (*ssh.Certificate, error) {
	if m.rekeySSH != nil {
		return m.rekeySSH(ctx, cert, key, signOpts...)
	}
	return m.ret1.(*ssh.Certificate), m.err
}

func (m *mockAuthority) GetSSHHosts(ctx context.Context, cert *x509.Certificate) ([]authority.Host, error) {
	if m.getSSHHosts != nil {
		return m.getSSHHosts(ctx, cert)
	}
	return m.ret1.([]authority.Host), m.err
}

func (m *mockAuthority) GetSSHRoots(ctx context.Context) (*authority.SSHKeys, error) {
	if m.getSSHRoots != nil {
		return m.getSSHRoots(ctx)
	}
	return m.ret1.(*authority.SSHKeys), m.err
}

func (m *mockAuthority) GetSSHFederation(ctx context.Context) (*authority.SSHKeys, error) {
	if m.getSSHFederation != nil {
		return m.getSSHFederation(ctx)
	}
	return m.ret1.(*authority.SSHKeys), m.err
}

func (m *mockAuthority) GetSSHConfig(ctx context.Context, typ string, data map[string]string) ([]templates.Output, error) {
	if m.getSSHConfig != nil {
		return m.getSSHConfig(ctx, typ, data)
	}
	return m.ret1.([]templates.Output), m.err
}

func (m *mockAuthority) CheckSSHHost(ctx context.Context, principal, token string) (bool, error) {
	if m.checkSSHHost != nil {
		return m.checkSSHHost(ctx, principal, token)
	}
	return m.ret1.(bool), m.err
}

func (m *mockAuthority) GetSSHBastion(ctx context.Context, user, hostname string) (*authority.Bastion, error) {
	if m.getSSHBastion != nil {
		return m.getSSHBastion(ctx, user, hostname)
	}
	return m.ret1.(*authority.Bastion), m.err
}

func (m *mockAuthority) Version() authority.Version {
	if m.version != nil {
		return m.version()
	}
	return m.ret1.(authority.Version)
}

func TestNewCertificate(t *testing.T) {
	cert := parseCertificate(rootPEM)
	if !reflect.DeepEqual(Certificate{Certificate: cert}, NewCertificate(cert)) {
		t.Errorf("NewCertificate failed, got %v, wants %v", NewCertificate(cert), Certificate{Certificate: cert})
	}
}

func TestCertificate_MarshalJSON(t *testing.T) {
	type fields struct {
		Certificate *x509.Certificate
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{"nil", fields{Certificate: nil}, []byte("null"), false},
		{"empty", fields{Certificate: &x509.Certificate{Raw: nil}}, []byte(`"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"`), false},
		{"root", fields{Certificate: parseCertificate(rootPEM)}, []byte(`"` + strings.ReplaceAll(rootPEM, "\n", `\n`) + `\n"`), false},
		{"cert", fields{Certificate: parseCertificate(certPEM)}, []byte(`"` + strings.ReplaceAll(certPEM, "\n", `\n`) + `\n"`), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Certificate{
				Certificate: tt.fields.Certificate,
			}
			got, err := c.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("Certificate.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Certificate.MarshalJSON() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCertificate_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantCert bool
		wantErr  bool
	}{
		{"no data", nil, false, true},
		{"incomplete string 1", []byte(`"foobar`), false, true}, {"incomplete string 2", []byte(`foobar"`), false, true},
		{"invalid string", []byte(`"foobar"`), false, true},
		{"invalid bytes 0", []byte{}, false, true}, {"invalid bytes 1", []byte{1}, false, true},
		{"empty csr", []byte(`"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE----\n"`), false, true},
		{"invalid type", []byte(`"` + strings.ReplaceAll(csrPEM, "\n", `\n`) + `"`), false, true},
		{"empty string", []byte(`""`), false, false},
		{"json null", []byte(`null`), false, false},
		{"valid root", []byte(`"` + strings.ReplaceAll(rootPEM, "\n", `\n`) + `"`), true, false},
		{"valid cert", []byte(`"` + strings.ReplaceAll(certPEM, "\n", `\n`) + `"`), true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c Certificate
			if err := c.UnmarshalJSON(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("Certificate.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantCert && c.Certificate == nil {
				t.Error("Certificate.UnmarshalJSON() failed, Certificate is nil")
			}
		})
	}
}

func TestCertificate_UnmarshalJSON_json(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		wantCert bool
		wantErr  bool
	}{
		{"invalid type (bool)", `{"crt":true}`, false, true},
		{"invalid type (number)", `{"crt":123}`, false, true},
		{"invalid type (object)", `{"crt":{}}`, false, true},
		{"empty crt (null)", `{"crt":null}`, false, false},
		{"empty crt (string)", `{"crt":""}`, false, false},
		{"empty crt", `{"crt":"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE----\n"}`, false, true},
		{"valid crt", `{"crt":"` + strings.ReplaceAll(certPEM, "\n", `\n`) + `"}`, true, false},
	}

	type request struct {
		Cert Certificate `json:"crt"`
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body request
			if err := json.Unmarshal([]byte(tt.data), &body); (err != nil) != tt.wantErr {
				t.Errorf("json.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}

			switch tt.wantCert {
			case true:
				if body.Cert.Certificate == nil {
					t.Error("json.Unmarshal() failed, Certificate is nil")
				}
			case false:
				if body.Cert.Certificate != nil {
					t.Error("json.Unmarshal() failed, Certificate is not nil")
				}
			}
		})
	}
}
func TestNewCertificateRequest(t *testing.T) {
	csr := parseCertificateRequest(csrPEM)
	if !reflect.DeepEqual(CertificateRequest{CertificateRequest: csr}, NewCertificateRequest(csr)) {
		t.Errorf("NewCertificateRequest failed, got %v, wants %v", NewCertificateRequest(csr), CertificateRequest{CertificateRequest: csr})
	}
}

func TestCertificateRequest_MarshalJSON(t *testing.T) {
	type fields struct {
		CertificateRequest *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{"nil", fields{CertificateRequest: nil}, []byte("null"), false},
		{"empty", fields{CertificateRequest: &x509.CertificateRequest{}}, []byte(`"-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n"`), false},
		{"csr", fields{CertificateRequest: parseCertificateRequest(csrPEM)}, []byte(`"` + strings.ReplaceAll(csrPEM, "\n", `\n`) + `\n"`), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CertificateRequest{
				CertificateRequest: tt.fields.CertificateRequest,
			}
			got, err := c.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("CertificateRequest.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CertificateRequest.MarshalJSON() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCertificateRequest_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantCert bool
		wantErr  bool
	}{
		{"no data", nil, false, true},
		{"incomplete string 1", []byte(`"foobar`), false, true}, {"incomplete string 2", []byte(`foobar"`), false, true},
		{"invalid string", []byte(`"foobar"`), false, true},
		{"invalid bytes 0", []byte{}, false, true}, {"invalid bytes 1", []byte{1}, false, true},
		{"empty csr", []byte(`"-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST----\n"`), false, true},
		{"invalid type", []byte(`"` + strings.ReplaceAll(rootPEM, "\n", `\n`) + `"`), false, true},
		{"empty string", []byte(`""`), false, false},
		{"json null", []byte(`null`), false, false},
		{"valid csr", []byte(`"` + strings.ReplaceAll(csrPEM, "\n", `\n`) + `"`), true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c CertificateRequest
			if err := c.UnmarshalJSON(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("CertificateRequest.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantCert && c.CertificateRequest == nil {
				t.Error("CertificateRequest.UnmarshalJSON() failed, CertificateRequet is nil")
			}
		})
	}
}

func TestCertificateRequest_UnmarshalJSON_json(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		wantCert bool
		wantErr  bool
	}{
		{"invalid type (bool)", `{"csr":true}`, false, true},
		{"invalid type (number)", `{"csr":123}`, false, true},
		{"invalid type (object)", `{"csr":{}}`, false, true},
		{"empty csr (null)", `{"csr":null}`, false, false},
		{"empty csr (string)", `{"csr":""}`, false, false},
		{"empty csr", `{"csr":"-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST----\n"}`, false, true},
		{"valid csr", `{"csr":"` + strings.ReplaceAll(csrPEM, "\n", `\n`) + `"}`, true, false},
	}

	type request struct {
		CSR CertificateRequest `json:"csr"`
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body request
			if err := json.Unmarshal([]byte(tt.data), &body); (err != nil) != tt.wantErr {
				t.Errorf("json.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}

			switch tt.wantCert {
			case true:
				if body.CSR.CertificateRequest == nil {
					t.Error("json.Unmarshal() failed, CertificateRequest is nil")
				}
			case false:
				if body.CSR.CertificateRequest != nil {
					t.Error("json.Unmarshal() failed, CertificateRequest is not nil")
				}
			}
		})
	}
}

func TestSignRequest_Validate(t *testing.T) {
	csr := parseCertificateRequest(csrPEM)
	bad := parseCertificateRequest(csrPEM)
	bad.Signature[0]++
	type fields struct {
		CsrPEM    CertificateRequest
		OTT       string
		NotBefore time.Time
		NotAfter  time.Time
	}
	tests := []struct {
		name   string
		fields fields
		err    error
	}{
		{"missing csr", fields{CertificateRequest{}, "foobarzar", time.Time{}, time.Time{}}, errors.New("missing csr")},
		{"invalid csr", fields{CertificateRequest{bad}, "foobarzar", time.Time{}, time.Time{}}, errors.New("invalid csr")},
		{"missing ott", fields{CertificateRequest{csr}, "", time.Time{}, time.Time{}}, errors.New("missing ott")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SignRequest{
				CsrPEM:    tt.fields.CsrPEM,
				OTT:       tt.fields.OTT,
				NotAfter:  NewTimeDuration(tt.fields.NotAfter),
				NotBefore: NewTimeDuration(tt.fields.NotBefore),
			}
			if err := s.Validate(); err != nil {
				if assert.NotNil(t, tt.err) {
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			} else {
				assert.Nil(t, tt.err)
			}
		})
	}
}

type mockProvisioner struct {
	ret1, ret2, ret3   interface{}
	err                error
	getID              func() string
	getIDForToken      func() string
	getTokenID         func(string) (string, error)
	getName            func() string
	getType            func() provisioner.Type
	getEncryptedKey    func() (string, string, bool)
	init               func(provisioner.Config) error
	authorizeRenew     func(ctx context.Context, cert *x509.Certificate) error
	authorizeRevoke    func(ctx context.Context, token string) error
	authorizeSign      func(ctx context.Context, ott string) ([]provisioner.SignOption, error)
	authorizeRenewal   func(*x509.Certificate) error
	authorizeSSHSign   func(ctx context.Context, token string) ([]provisioner.SignOption, error)
	authorizeSSHRevoke func(ctx context.Context, token string) error
	authorizeSSHRenew  func(ctx context.Context, token string) (*ssh.Certificate, error)
	authorizeSSHRekey  func(ctx context.Context, token string) (*ssh.Certificate, []provisioner.SignOption, error)
}

func (m *mockProvisioner) GetID() string {
	if m.getID != nil {
		return m.getID()
	}
	return m.ret1.(string)
}

func (m *mockProvisioner) GetIDForToken() string {
	if m.getIDForToken != nil {
		return m.getIDForToken()
	}
	return m.ret1.(string)
}

func (m *mockProvisioner) GetTokenID(token string) (string, error) {
	if m.getTokenID != nil {
		return m.getTokenID(token)
	}
	if m.ret1 == nil {
		return "", m.err
	}
	return m.ret1.(string), m.err
}

func (m *mockProvisioner) GetName() string {
	if m.getName != nil {
		return m.getName()
	}
	return m.ret1.(string)
}

func (m *mockProvisioner) GetType() provisioner.Type {
	if m.getType != nil {
		return m.getType()
	}
	return m.ret1.(provisioner.Type)
}

func (m *mockProvisioner) GetEncryptedKey() (string, string, bool) {
	if m.getEncryptedKey != nil {
		return m.getEncryptedKey()
	}
	return m.ret1.(string), m.ret2.(string), m.ret3.(bool)
}

func (m *mockProvisioner) Init(c provisioner.Config) error {
	if m.init != nil {
		return m.init(c)
	}
	return m.err
}

func (m *mockProvisioner) AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error {
	if m.authorizeRenew != nil {
		return m.authorizeRenew(ctx, cert)
	}
	return m.err
}

func (m *mockProvisioner) AuthorizeRevoke(ctx context.Context, token string) error {
	if m.authorizeRevoke != nil {
		return m.authorizeRevoke(ctx, token)
	}
	return m.err
}

func (m *mockProvisioner) AuthorizeSign(ctx context.Context, ott string) ([]provisioner.SignOption, error) {
	if m.authorizeSign != nil {
		return m.authorizeSign(ctx, ott)
	}
	return m.ret1.([]provisioner.SignOption), m.err
}

func (m *mockProvisioner) AuthorizeRenewal(c *x509.Certificate) error {
	if m.authorizeRenewal != nil {
		return m.authorizeRenewal(c)
	}
	return m.err
}

func (m *mockProvisioner) AuthorizeSSHSign(ctx context.Context, token string) ([]provisioner.SignOption, error) {
	if m.authorizeSSHSign != nil {
		return m.authorizeSSHSign(ctx, token)
	}
	return m.ret1.([]provisioner.SignOption), m.err
}
func (m *mockProvisioner) AuthorizeSSHRevoke(ctx context.Context, token string) error {
	if m.authorizeSSHRevoke != nil {
		return m.authorizeSSHRevoke(ctx, token)
	}
	return m.err
}
func (m *mockProvisioner) AuthorizeSSHRenew(ctx context.Context, token string) (*ssh.Certificate, error) {
	if m.authorizeSSHRenew != nil {
		return m.authorizeSSHRenew(ctx, token)
	}
	return m.ret1.(*ssh.Certificate), m.err
}
func (m *mockProvisioner) AuthorizeSSHRekey(ctx context.Context, token string) (*ssh.Certificate, []provisioner.SignOption, error) {
	if m.authorizeSSHRekey != nil {
		return m.authorizeSSHRekey(ctx, token)
	}
	return m.ret1.(*ssh.Certificate), m.ret2.([]provisioner.SignOption), m.err
}

func Test_CRLGeneration(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		statusCode int
		expected   []byte
	}{
		{"empty", nil, http.StatusOK, nil},
	}

	chiCtx := chi.NewRouteContext()
	req := httptest.NewRequest("GET", "http://example.com/crl", nil)
	req = req.WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{ret1: tt.expected, err: tt.err})
			w := httptest.NewRecorder()
			CRL(w, req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.CRL StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.Root unexpected error = %v", err)
			}
			if tt.statusCode == 200 {
				if !bytes.Equal(bytes.TrimSpace(body), tt.expected) {
					t.Errorf("caHandler.Root CRL = %s, wants %s", body, tt.expected)
				}
			}
		})
	}
}

func Test_caHandler_Route(t *testing.T) {
	type fields struct {
		Authority Authority
	}
	type args struct {
		r Router
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{"ok", fields{&mockAuthority{}}, args{chi.NewRouter()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &caHandler{
				Authority: tt.fields.Authority,
			}
			h.Route(tt.args.r)
		})
	}
}

func Test_Health(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/health", nil)
	w := httptest.NewRecorder()
	Health(w, req)

	res := w.Result()
	if res.StatusCode != 200 {
		t.Errorf("caHandler.Health StatusCode = %d, wants 200", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Errorf("caHandler.Health unexpected error = %v", err)
	}
	expected := []byte("{\"status\":\"ok\"}\n")
	if !bytes.Equal(body, expected) {
		t.Errorf("caHandler.Health Body = %s, wants %s", body, expected)
	}
}

func Test_Root(t *testing.T) {
	tests := []struct {
		name       string
		root       *x509.Certificate
		err        error
		statusCode int
	}{
		{"ok", parseCertificate(rootPEM), nil, 200},
		{"fail", nil, fmt.Errorf("not found"), 404},
	}

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("sha", "efc7d6b475a56fe587650bcdb999a4a308f815ba44db4bf0371ea68a786ccd36")
	req := httptest.NewRequest("GET", "http://example.com/root/efc7d6b475a56fe587650bcdb999a4a308f815ba44db4bf0371ea68a786ccd36", nil)
	req = req.WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx))

	expected := []byte(`{"ca":"` + strings.ReplaceAll(rootPEM, "\n", `\n`) + `\n"}`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{ret1: tt.root, err: tt.err})
			w := httptest.NewRecorder()
			Root(w, req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.Root StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.Root unexpected error = %v", err)
			}
			if tt.statusCode == 200 {
				if !bytes.Equal(bytes.TrimSpace(body), expected) {
					t.Errorf("caHandler.Root Body = %s, wants %s", body, expected)
				}
			}
		})
	}
}

func Test_Sign(t *testing.T) {
	csr := parseCertificateRequest(csrPEM)
	valid, err := json.Marshal(SignRequest{
		CsrPEM: CertificateRequest{csr},
		OTT:    "foobarzar",
	})
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := json.Marshal(SignRequest{
		CsrPEM: CertificateRequest{csr},
		OTT:    "",
	})
	if err != nil {
		t.Fatal(err)
	}

	expected1 := []byte(`{"crt":"` + strings.ReplaceAll(certPEM, "\n", `\n`) + `\n","ca":"` + strings.ReplaceAll(rootPEM, "\n", `\n`) + `\n","certChain":["` + strings.ReplaceAll(certPEM, "\n", `\n`) + `\n","` + strings.ReplaceAll(rootPEM, "\n", `\n`) + `\n"]}`)
	expected2 := []byte(`{"crt":"` + strings.ReplaceAll(stepCertPEM, "\n", `\n`) + `\n","ca":"` + strings.ReplaceAll(rootPEM, "\n", `\n`) + `\n","certChain":["` + strings.ReplaceAll(stepCertPEM, "\n", `\n`) + `\n","` + strings.ReplaceAll(rootPEM, "\n", `\n`) + `\n"]}`)

	tests := []struct {
		name         string
		input        string
		certAttrOpts []provisioner.SignOption
		autherr      error
		cert         *x509.Certificate
		root         *x509.Certificate
		signErr      error
		statusCode   int
		expected     []byte
	}{
		{"ok", string(valid), nil, nil, parseCertificate(certPEM), parseCertificate(rootPEM), nil, http.StatusCreated, expected1},
		{"ok with Provisioner", string(valid), nil, nil, parseCertificate(stepCertPEM), parseCertificate(rootPEM), nil, http.StatusCreated, expected2},
		{"json read error", "{", nil, nil, nil, nil, nil, http.StatusBadRequest, nil},
		{"validate error", string(invalid), nil, nil, nil, nil, nil, http.StatusBadRequest, nil},
		{"authorize error", string(valid), nil, fmt.Errorf("an error"), nil, nil, nil, http.StatusUnauthorized, nil},
		{"sign error", string(valid), nil, nil, nil, nil, fmt.Errorf("an error"), http.StatusForbidden, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{
				ret1: tt.cert, ret2: tt.root, err: tt.signErr,
				authorize: func(ctx context.Context, ott string) ([]provisioner.SignOption, error) {
					return tt.certAttrOpts, tt.autherr
				},
				getTLSOptions: func() *authority.TLSOptions {
					return nil
				},
			})
			req := httptest.NewRequest("POST", "http://example.com/sign", strings.NewReader(tt.input))
			w := httptest.NewRecorder()
			Sign(logging.NewResponseLogger(w), req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.Root StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.Root unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), tt.expected) {
					t.Errorf("caHandler.Root Body = %s, wants %s", body, tt.expected)
				}
			}
		})
	}
}

func Test_Renew(t *testing.T) {
	cs := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{parseCertificate(certPEM)},
	}

	// Prepare root and leaf for renew after expiry test.
	now := time.Now()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPub, leafPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		PublicKey:             rootPub,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             now.Add(-2 * time.Hour),
		NotAfter:              now.Add(time.Hour),
	}
	root, err = x509util.CreateCertificate(root, root, rootPub, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	expiredLeaf := &x509.Certificate{
		Subject:        pkix.Name{CommonName: "Leaf certificate"},
		PublicKey:      leafPub,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		NotBefore:      now.Add(-time.Hour),
		NotAfter:       now.Add(-time.Minute),
		EmailAddresses: []string{"test@example.org"},
	}
	expiredLeaf, err = x509util.CreateCertificate(expiredLeaf, root, leafPub, rootPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Generate renew after expiry token
	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader("x5cInsecure", []string{base64.StdEncoding.EncodeToString(expiredLeaf.Raw)})
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: leafPriv}, so)
	if err != nil {
		t.Fatal(err)
	}
	generateX5cToken := func(claims jose.Claims) string {
		s, err := jose.Signed(sig).Claims(claims).CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	tests := []struct {
		name       string
		tls        *tls.ConnectionState
		header     http.Header
		cert       *x509.Certificate
		root       *x509.Certificate
		err        error
		statusCode int
	}{
		{"ok", cs, nil, parseCertificate(certPEM), parseCertificate(rootPEM), nil, http.StatusCreated},
		{"ok renew after expiry", &tls.ConnectionState{}, http.Header{
			"Authorization": []string{"Bearer " + generateX5cToken(jose.Claims{
				NotBefore: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(5 * time.Minute)),
			})},
		}, expiredLeaf, root, nil, http.StatusCreated},
		{"no tls", nil, nil, nil, nil, nil, http.StatusBadRequest},
		{"no peer certificates", &tls.ConnectionState{}, nil, nil, nil, nil, http.StatusBadRequest},
		{"renew error", cs, nil, nil, nil, errs.Forbidden("an error"), http.StatusForbidden},
		{"fail expired token", &tls.ConnectionState{}, http.Header{
			"Authorization": []string{"Bearer " + generateX5cToken(jose.Claims{
				NotBefore: jose.NewNumericDate(now.Add(-time.Hour)), Expiry: jose.NewNumericDate(now.Add(-time.Minute)),
			})},
		}, expiredLeaf, root, errs.Forbidden("an error"), http.StatusUnauthorized},
		{"fail invalid root", &tls.ConnectionState{}, http.Header{
			"Authorization": []string{"Bearer " + generateX5cToken(jose.Claims{
				NotBefore: jose.NewNumericDate(now.Add(-time.Hour)), Expiry: jose.NewNumericDate(now.Add(-time.Minute)),
			})},
		}, expiredLeaf, parseCertificate(rootPEM), errs.Forbidden("an error"), http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{
				ret1: tt.cert, ret2: tt.root, err: tt.err,
				authorizeRenewToken: func(ctx context.Context, ott string) (*x509.Certificate, error) {
					jwt, chain, err := jose.ParseX5cInsecure(ott, []*x509.Certificate{tt.root})
					if err != nil {
						return nil, errs.Unauthorized(err.Error())
					}
					var claims jose.Claims
					if err := jwt.Claims(chain[0][0].PublicKey, &claims); err != nil {
						return nil, errs.Unauthorized(err.Error())
					}
					if err := claims.ValidateWithLeeway(jose.Expected{
						Time: now,
					}, time.Minute); err != nil {
						return nil, errs.Unauthorized(err.Error())
					}
					return chain[0][0], nil
				},
				getTLSOptions: func() *authority.TLSOptions {
					return nil
				},
			})
			req := httptest.NewRequest("POST", "http://example.com/renew", nil)
			req.TLS = tt.tls
			req.Header = tt.header
			w := httptest.NewRecorder()
			Renew(logging.NewResponseLogger(w), req)

			res := w.Result()
			defer res.Body.Close()

			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Errorf("caHandler.Renew unexpected error = %v", err)
			}
			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.Renew StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
				t.Errorf("%s", body)
			}

			if tt.statusCode < http.StatusBadRequest {
				expected := []byte(`{"crt":"` + strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tt.cert.Raw})), "\n", `\n`) + `",` +
					`"ca":"` + strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tt.root.Raw})), "\n", `\n`) + `",` +
					`"certChain":["` +
					strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tt.cert.Raw})), "\n", `\n`) + `","` +
					strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tt.root.Raw})), "\n", `\n`) + `"]}`)

				if !bytes.Equal(bytes.TrimSpace(body), expected) {
					t.Errorf("caHandler.Root Body = \n%s, wants \n%s", body, expected)
				}
			}
		})
	}
}

func Test_Rekey(t *testing.T) {
	cs := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{parseCertificate(certPEM)},
	}
	csr := parseCertificateRequest(csrPEM)
	valid, err := json.Marshal(RekeyRequest{
		CsrPEM: CertificateRequest{csr},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		input      string
		tls        *tls.ConnectionState
		cert       *x509.Certificate
		root       *x509.Certificate
		err        error
		statusCode int
	}{
		{"ok", string(valid), cs, parseCertificate(certPEM), parseCertificate(rootPEM), nil, http.StatusCreated},
		{"no tls", string(valid), nil, nil, nil, nil, http.StatusBadRequest},
		{"no peer certificates", string(valid), &tls.ConnectionState{}, nil, nil, nil, http.StatusBadRequest},
		{"rekey error", string(valid), cs, nil, nil, errs.Forbidden("an error"), http.StatusForbidden},
		{"json read error", "{", cs, nil, nil, nil, http.StatusBadRequest},
	}

	expected := []byte(`{"crt":"` + strings.ReplaceAll(certPEM, "\n", `\n`) + `\n","ca":"` + strings.ReplaceAll(rootPEM, "\n", `\n`) + `\n","certChain":["` + strings.ReplaceAll(certPEM, "\n", `\n`) + `\n","` + strings.ReplaceAll(rootPEM, "\n", `\n`) + `\n"]}`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{
				ret1: tt.cert, ret2: tt.root, err: tt.err,
				getTLSOptions: func() *authority.TLSOptions {
					return nil
				},
			})
			req := httptest.NewRequest("POST", "http://example.com/rekey", strings.NewReader(tt.input))
			req.TLS = tt.tls
			w := httptest.NewRecorder()
			Rekey(logging.NewResponseLogger(w), req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.Rekey StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.Rekey unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), expected) {
					t.Errorf("caHandler.Rekey Body = %s, wants %s", body, expected)
				}
			}
		})
	}
}

func Test_Provisioners(t *testing.T) {
	type fields struct {
		Authority Authority
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}

	req, err := http.NewRequest("GET", "http://example.com/provisioners?cursor=foo&limit=20", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	reqLimitFail, err := http.NewRequest("GET", "http://example.com/provisioners?limit=abc", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	var key jose.JSONWebKey
	if err := json.Unmarshal([]byte(pubKey), &key); err != nil {
		t.Fatal(err)
	}

	p := provisioner.List{
		&provisioner.JWK{
			Type:         "JWK",
			Name:         "max",
			EncryptedKey: "abc",
			Key:          &key,
		},
		&provisioner.JWK{
			Type:         "JWK",
			Name:         "mariano",
			EncryptedKey: "def",
			Key:          &key,
		},
	}
	pr := ProvisionersResponse{
		Provisioners: p,
	}

	tests := []struct {
		name       string
		fields     fields
		args       args
		statusCode int
	}{
		{"ok", fields{&mockAuthority{ret1: p, ret2: ""}}, args{httptest.NewRecorder(), req}, 200},
		{"fail", fields{&mockAuthority{ret1: p, ret2: "", err: fmt.Errorf("the error")}}, args{httptest.NewRecorder(), req}, 500},
		{"limit fail", fields{&mockAuthority{ret1: p, ret2: ""}}, args{httptest.NewRecorder(), reqLimitFail}, 400},
	}

	expected, err := json.Marshal(pr)
	if err != nil {
		t.Fatal(err)
	}

	expectedError400 := errs.BadRequest("limit 'abc' is not an integer")
	expectedError400Bytes, err := json.Marshal(expectedError400)
	assert.FatalError(t, err)
	expectedError500 := errs.InternalServer("force")
	expectedError500Bytes, err := json.Marshal(expectedError500)
	assert.FatalError(t, err)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, tt.fields.Authority)
			Provisioners(tt.args.w, tt.args.r)

			rec := tt.args.w.(*httptest.ResponseRecorder)
			res := rec.Result()
			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.Provisioners StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.Provisioners unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), expected) {
					t.Errorf("caHandler.Provisioners Body = %s, wants %s", body, expected)
				}
			} else {
				switch tt.statusCode {
				case 400:
					if !bytes.Equal(bytes.TrimSpace(body), expectedError400Bytes) {
						t.Errorf("caHandler.Provisioners Body = %s, wants %s", body, expectedError400Bytes)
					}
				case 500:
					if !bytes.Equal(bytes.TrimSpace(body), expectedError500Bytes) {
						t.Errorf("caHandler.Provisioners Body = %s, wants %s", body, expectedError500Bytes)
					}
				default:
					t.Errorf("caHandler.Provisioner unexpected status code = %d", tt.statusCode)
				}

			}
		})
	}
}

func Test_ProvisionerKey(t *testing.T) {
	type fields struct {
		Authority Authority
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("kid", "oV1p0MJeGQ7qBlK6B-oyfVdBRjh_e7VSK_YSEEqgW00")
	req := httptest.NewRequest("GET", "http://example.com/provisioners/oV1p0MJeGQ7qBlK6B-oyfVdBRjh_e7VSK_YSEEqgW00/encrypted-key", nil)
	req = req.WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx))

	tests := []struct {
		name       string
		fields     fields
		args       args
		statusCode int
	}{
		{"ok", fields{&mockAuthority{ret1: privKey}}, args{httptest.NewRecorder(), req}, 200},
		{"fail", fields{&mockAuthority{ret1: "", err: fmt.Errorf("not found")}}, args{httptest.NewRecorder(), req}, 404},
	}

	expected := []byte(`{"key":"` + privKey + `"}`)
	expectedError404 := errs.NotFound("force")
	expectedError404Bytes, err := json.Marshal(expectedError404)
	assert.FatalError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, tt.fields.Authority)
			ProvisionerKey(tt.args.w, tt.args.r)

			rec := tt.args.w.(*httptest.ResponseRecorder)
			res := rec.Result()
			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.Provisioners StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.Provisioners unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), expected) {
					t.Errorf("caHandler.Provisioners Body = %s, wants %s", body, expected)
				}
			} else {
				if !bytes.Equal(bytes.TrimSpace(body), expectedError404Bytes) {
					t.Errorf("caHandler.Provisioners Body = %s, wants %s", body, expectedError404Bytes)
				}
			}
		})
	}
}

func Test_Roots(t *testing.T) {
	cs := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{parseCertificate(certPEM)},
	}
	tests := []struct {
		name       string
		tls        *tls.ConnectionState
		cert       *x509.Certificate
		root       *x509.Certificate
		err        error
		statusCode int
	}{
		{"ok", cs, parseCertificate(certPEM), parseCertificate(rootPEM), nil, http.StatusCreated},
		{"no peer certificates", &tls.ConnectionState{}, parseCertificate(certPEM), parseCertificate(rootPEM), nil, http.StatusCreated},
		{"fail", cs, nil, nil, fmt.Errorf("an error"), http.StatusForbidden},
	}

	expected := []byte(`{"crts":["` + strings.ReplaceAll(rootPEM, "\n", `\n`) + `\n"]}`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{ret1: []*x509.Certificate{tt.root}, err: tt.err})
			req := httptest.NewRequest("GET", "http://example.com/roots", nil)
			req.TLS = tt.tls
			w := httptest.NewRecorder()
			Roots(w, req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.Roots StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.Roots unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), expected) {
					t.Errorf("caHandler.Roots Body = %s, wants %s", body, expected)
				}
			}
		})
	}
}

func Test_caHandler_RootsPEM(t *testing.T) {
	parsedRoot := parseCertificate(rootPEM)
	tests := []struct {
		name       string
		roots      []*x509.Certificate
		err        error
		statusCode int
		expect     string
	}{
		{"one root", []*x509.Certificate{parsedRoot}, nil, http.StatusOK, rootPEM},
		{"two roots", []*x509.Certificate{parsedRoot, parsedRoot}, nil, http.StatusOK, rootPEM + "\n" + rootPEM},
		{"fail", nil, errors.New("an error"), http.StatusInternalServerError, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{ret1: tt.roots, err: tt.err})
			req := httptest.NewRequest("GET", "https://example.com/roots", nil)
			w := httptest.NewRecorder()
			RootsPEM(w, req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.RootsPEM StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.RootsPEM unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), []byte(tt.expect)) {
					t.Errorf("caHandler.RootsPEM Body = %s, wants %s", body, tt.expect)
				}
			}
		})
	}
}

func Test_Federation(t *testing.T) {
	cs := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{parseCertificate(certPEM)},
	}
	tests := []struct {
		name       string
		tls        *tls.ConnectionState
		cert       *x509.Certificate
		root       *x509.Certificate
		err        error
		statusCode int
	}{
		{"ok", cs, parseCertificate(certPEM), parseCertificate(rootPEM), nil, http.StatusCreated},
		{"no peer certificates", &tls.ConnectionState{}, parseCertificate(certPEM), parseCertificate(rootPEM), nil, http.StatusCreated},
		{"fail", cs, nil, nil, fmt.Errorf("an error"), http.StatusForbidden},
	}

	expected := []byte(`{"crts":["` + strings.ReplaceAll(rootPEM, "\n", `\n`) + `\n"]}`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{ret1: []*x509.Certificate{tt.root}, err: tt.err})
			req := httptest.NewRequest("GET", "http://example.com/federation", nil)
			req.TLS = tt.tls
			w := httptest.NewRecorder()
			Federation(w, req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("caHandler.Federation StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Errorf("caHandler.Federation unexpected error = %v", err)
			}
			if tt.statusCode < http.StatusBadRequest {
				if !bytes.Equal(bytes.TrimSpace(body), expected) {
					t.Errorf("caHandler.Federation Body = %s, wants %s", body, expected)
				}
			}
		})
	}
}

func Test_fmtPublicKey(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var dsa2048 dsa.PrivateKey
	if err := dsa.GenerateParameters(&dsa2048.Parameters, rand.Reader, dsa.L2048N256); err != nil {
		t.Fatal(err)
	}
	if err := dsa.GenerateKey(&dsa2048, rand.Reader); err != nil {
		t.Fatal(err)
	}

	type args struct {
		pub, priv interface{}
		cert      *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"p256", args{p256.Public(), p256, nil}, "ECDSA P-256"},
		{"rsa2048", args{rsa2048.Public(), rsa2048, nil}, "RSA 2048"},
		{"ed25519", args{edPub, edPriv, nil}, "Ed25519"},
		{"dsa2048", args{cert: &x509.Certificate{PublicKeyAlgorithm: x509.DSA, PublicKey: &dsa2048.PublicKey}}, "DSA 2048"},
		{"unknown", args{cert: &x509.Certificate{PublicKeyAlgorithm: x509.ECDSA, PublicKey: []byte("12345678")}}, "ECDSA unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cert *x509.Certificate
			if tt.args.cert != nil {
				cert = tt.args.cert
			} else {
				cert = mustCertificate(t, tt.args.pub, tt.args.priv)
			}
			if got := fmtPublicKey(cert); got != tt.want {
				t.Errorf("fmtPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func mustCertificate(t *testing.T, pub, priv interface{}) *x509.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
