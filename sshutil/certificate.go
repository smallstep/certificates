package sshutil

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/randutil"
	"golang.org/x/crypto/ssh"
)

// Certificate is the json representation of ssh.Certificate.
type Certificate struct {
	Nonce           []byte            `json:"nonce"`
	Key             ssh.PublicKey     `json:"-"`
	Serial          uint64            `json:"serial"`
	Type            CertType          `json:"type"`
	KeyID           string            `json:"keyId"`
	Principals      []string          `json:"principals"`
	ValidAfter      uint64            `json:"-"`
	ValidBefore     uint64            `json:"-"`
	CriticalOptions map[string]string `json:"criticalOptions"`
	Extensions      map[string]string `json:"extensions"`
	Reserved        []byte            `json:"reserved"`
	SignatureKey    ssh.PublicKey     `json:"-"`
	Signature       *ssh.Signature    `json:"-"`
}

// NewCertificate creates a new certificate with the given key after parsing a
// template given in the options.
func NewCertificate(cr CertificateRequest, opts ...Option) (*Certificate, error) {
	o, err := new(Options).apply(cr, opts)
	if err != nil {
		return nil, err
	}

	if o.CertBuffer == nil {
		return nil, errors.New("certificate template cannot be empty")
	}

	// With templates
	var cert Certificate
	if err := json.NewDecoder(o.CertBuffer).Decode(&cert); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling certificate")
	}

	// Complete with public key
	cert.Key = cr.Key

	return &cert, nil
}

func (c *Certificate) GetCertificate() *ssh.Certificate {
	return &ssh.Certificate{
		Nonce:           c.Nonce,
		Key:             c.Key,
		Serial:          c.Serial,
		CertType:        uint32(c.Type),
		KeyId:           c.KeyID,
		ValidPrincipals: c.Principals,
		ValidAfter:      c.ValidAfter,
		ValidBefore:     c.ValidBefore,
		Permissions: ssh.Permissions{
			CriticalOptions: c.CriticalOptions,
			Extensions:      c.Extensions,
		},
		Reserved: c.Reserved,
	}
}

// CreateCertificate signs the given certificate with the given signer. If the
// certificate does not have a nonce or a serial, it will create random ones.
func CreateCertificate(cert *ssh.Certificate, signer ssh.Signer) (*ssh.Certificate, error) {
	if len(cert.Nonce) == 0 {
		nonce, err := randutil.ASCII(32)
		if err != nil {
			return nil, err
		}
		cert.Nonce = []byte(nonce)
	}

	if cert.Serial == 0 {
		if err := binary.Read(rand.Reader, binary.BigEndian, &cert.Serial); err != nil {
			return nil, errors.Wrap(err, "error reading random number")
		}
	}

	// Set signer public key.
	cert.SignatureKey = signer.PublicKey()

	// Get bytes for signing trailing the signature length.
	data := cert.Marshal()
	data = data[:len(data)-4]

	// Sign the certificate.
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, errors.Wrap(err, "error signing certificate")
	}
	cert.Signature = sig

	return cert, nil
}
