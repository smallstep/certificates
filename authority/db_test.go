package authority

import (
	"crypto/x509"

	"github.com/smallstep/certificates/db"
	"golang.org/x/crypto/ssh"
)

type MockAuthDB struct {
	err                  error
	ret1                 interface{}
	isRevoked            func(string) (bool, error)
	isSSHRevoked         func(string) (bool, error)
	revoke               func(rci *db.RevokedCertificateInfo) error
	revokeSSH            func(rci *db.RevokedCertificateInfo) error
	storeCertificate     func(crt *x509.Certificate) error
	useToken             func(id, tok string) (bool, error)
	isSSHHost            func(principal string) (bool, error)
	storeSSHCertificate  func(crt *ssh.Certificate) error
	getSSHHostPrincipals func() ([]string, error)
	shutdown             func() error
}

func (m *MockAuthDB) IsRevoked(sn string) (bool, error) {
	if m.isRevoked != nil {
		return m.isRevoked(sn)
	}
	return m.ret1.(bool), m.err
}

func (m *MockAuthDB) IsSSHRevoked(sn string) (bool, error) {
	if m.isSSHRevoked != nil {
		return m.isSSHRevoked(sn)
	}
	return m.ret1.(bool), m.err
}

func (m *MockAuthDB) UseToken(id, tok string) (bool, error) {
	if m.useToken != nil {
		return m.useToken(id, tok)
	}
	if m.ret1 == nil {
		return false, m.err
	}
	return m.ret1.(bool), m.err
}

func (m *MockAuthDB) Revoke(rci *db.RevokedCertificateInfo) error {
	if m.revoke != nil {
		return m.revoke(rci)
	}
	return m.err
}

func (m *MockAuthDB) RevokeSSH(rci *db.RevokedCertificateInfo) error {
	if m.revokeSSH != nil {
		return m.revokeSSH(rci)
	}
	return m.err
}

func (m *MockAuthDB) StoreCertificate(crt *x509.Certificate) error {
	if m.storeCertificate != nil {
		return m.storeCertificate(crt)
	}
	return m.err
}

func (m *MockAuthDB) IsSSHHost(principal string) (bool, error) {
	if m.isSSHHost != nil {
		return m.isSSHHost(principal)
	}
	return m.ret1.(bool), m.err
}

func (m *MockAuthDB) StoreSSHCertificate(crt *ssh.Certificate) error {
	if m.storeSSHCertificate != nil {
		return m.storeSSHCertificate(crt)
	}
	return m.err
}

func (m *MockAuthDB) GetSSHHostPrincipals() ([]string, error) {
	if m.getSSHHostPrincipals != nil {
		return m.getSSHHostPrincipals()
	}
	return m.ret1.([]string), m.err
}

func (m *MockAuthDB) Shutdown() error {
	if m.shutdown != nil {
		return m.shutdown()
	}
	return m.err
}
