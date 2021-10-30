//go:build cgo && !softhsm2 && !yubihsm2 && !opensc
// +build cgo,!softhsm2,!yubihsm2,!opensc

package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"math/big"

	"github.com/ThalesIgnite/crypto11"
	"github.com/pkg/errors"
)

func mustPKCS11(t TBTesting) *PKCS11 {
	t.Helper()
	testModule = "Golang crypto"
	k := &PKCS11{
		p11: &stubPKCS11{
			signerIndex: make(map[keyType]int),
			certIndex:   make(map[keyType]int),
		},
	}
	for i := range testCerts {
		testCerts[i].Certificates = nil
	}
	teardown(t, k)
	setup(t, k)
	return k
}

type keyType struct {
	id     string
	label  string
	serial string
}

func newKey(id, label []byte, serial *big.Int) keyType {
	var serialString string
	if serial != nil {
		serialString = serial.String()
	}
	return keyType{
		id:     string(id),
		label:  string(label),
		serial: serialString,
	}
}

type stubPKCS11 struct {
	signers     []crypto11.Signer
	certs       []*x509.Certificate
	signerIndex map[keyType]int
	certIndex   map[keyType]int
}

func (s *stubPKCS11) FindKeyPair(id, label []byte) (crypto11.Signer, error) {
	if id == nil && label == nil {
		return nil, errors.New("id and label cannot both be nil")
	}
	if i, ok := s.signerIndex[newKey(id, label, nil)]; ok {
		return s.signers[i], nil
	}
	return nil, nil
}

func (s *stubPKCS11) FindCertificate(id, label []byte, serial *big.Int) (*x509.Certificate, error) {
	if id == nil && label == nil && serial == nil {
		return nil, errors.New("id, label and serial cannot both be nil")
	}
	if i, ok := s.certIndex[newKey(id, label, serial)]; ok {
		return s.certs[i], nil
	}
	return nil, nil

}

func (s *stubPKCS11) ImportCertificateWithAttributes(template crypto11.AttributeSet, cert *x509.Certificate) error {
	var id, label []byte
	if v := template[crypto11.CkaId]; v != nil {
		id = v.Value
	}
	if v := template[crypto11.CkaLabel]; v != nil {
		label = v.Value
	}
	return s.ImportCertificateWithLabel(id, label, cert)
}

func (s *stubPKCS11) ImportCertificateWithLabel(id, label []byte, cert *x509.Certificate) error {
	switch {
	case id == nil:
		return errors.New("id cannot both be nil")
	case label == nil:
		return errors.New("label cannot both be nil")
	case cert == nil:
		return errors.New("certificate cannot be nil")
	}

	i := len(s.certs)
	s.certs = append(s.certs, cert)
	s.certIndex[newKey(id, label, cert.SerialNumber)] = i
	s.certIndex[newKey(id, nil, nil)] = i
	s.certIndex[newKey(nil, label, nil)] = i
	s.certIndex[newKey(nil, nil, cert.SerialNumber)] = i
	s.certIndex[newKey(id, label, nil)] = i
	s.certIndex[newKey(id, nil, cert.SerialNumber)] = i
	s.certIndex[newKey(nil, label, cert.SerialNumber)] = i

	return nil
}

func (s *stubPKCS11) DeleteCertificate(id, label []byte, serial *big.Int) error {
	if id == nil && label == nil && serial == nil {
		return errors.New("id, label and serial cannot both be nil")
	}
	if i, ok := s.certIndex[newKey(id, label, serial)]; ok {
		s.certs[i] = nil
	}
	return nil
}

func (s *stubPKCS11) GenerateRSAKeyPairWithAttributes(public, private crypto11.AttributeSet, bits int) (crypto11.SignerDecrypter, error) {
	var id, label []byte
	if v := public[crypto11.CkaId]; v != nil {
		id = v.Value
	}
	if v := public[crypto11.CkaLabel]; v != nil {
		label = v.Value
	}
	return s.GenerateRSAKeyPairWithLabel(id, label, bits)
}

func (s *stubPKCS11) GenerateRSAKeyPairWithLabel(id, label []byte, bits int) (crypto11.SignerDecrypter, error) {
	if id == nil && label == nil {
		return nil, errors.New("id and label cannot both be nil")
	}
	p, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	k := &privateKey{
		Signer: p,
		index:  len(s.signers),
		stub:   s,
	}
	s.signers = append(s.signers, k)
	s.signerIndex[newKey(id, label, nil)] = k.index
	s.signerIndex[newKey(id, nil, nil)] = k.index
	s.signerIndex[newKey(nil, label, nil)] = k.index
	return k, nil
}

func (s *stubPKCS11) GenerateECDSAKeyPairWithAttributes(public, private crypto11.AttributeSet, curve elliptic.Curve) (crypto11.Signer, error) {
	var id, label []byte
	if v := public[crypto11.CkaId]; v != nil {
		id = v.Value
	}
	if v := public[crypto11.CkaLabel]; v != nil {
		label = v.Value
	}
	return s.GenerateECDSAKeyPairWithLabel(id, label, curve)
}

func (s *stubPKCS11) GenerateECDSAKeyPairWithLabel(id, label []byte, curve elliptic.Curve) (crypto11.Signer, error) {
	if id == nil && label == nil {
		return nil, errors.New("id and label cannot both be nil")
	}
	p, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	k := &privateKey{
		Signer: p,
		index:  len(s.signers),
		stub:   s,
	}
	s.signers = append(s.signers, k)
	s.signerIndex[newKey(id, label, nil)] = k.index
	s.signerIndex[newKey(id, nil, nil)] = k.index
	s.signerIndex[newKey(nil, label, nil)] = k.index
	return k, nil
}

func (s *stubPKCS11) Close() error {
	return nil
}

type privateKey struct {
	crypto.Signer
	index int
	stub  *stubPKCS11
}

func (s *privateKey) Delete() error {
	s.stub.signers[s.index] = nil
	return nil
}

func (s *privateKey) Decrypt(rnd io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	k, ok := s.Signer.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not an rsa key")
	}
	return k.Decrypt(rnd, msg, opts)
}
