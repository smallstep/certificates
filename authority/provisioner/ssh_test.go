package provisioner

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"reflect"
	"time"

	"golang.org/x/crypto/ssh"
)

func validateSSHCertificate(cert *ssh.Certificate, opts *SSHOptions) error {
	switch {
	case cert == nil:
		return fmt.Errorf("certificate is nil")
	case cert.Signature == nil:
		return fmt.Errorf("certificate signature is nil")
	case cert.SignatureKey == nil:
		return fmt.Errorf("certificate signature is nil")
	case !reflect.DeepEqual(cert.ValidPrincipals, opts.Principals):
		return fmt.Errorf("certificate principals are not equal, want %v, got %v", opts.Principals, cert.ValidPrincipals)
	case cert.CertType != ssh.UserCert && cert.CertType != ssh.HostCert:
		return fmt.Errorf("certificate type %v is not valid", cert.CertType)
	case opts.CertType == "user" && cert.CertType != ssh.UserCert:
		return fmt.Errorf("certificate type is not valid, want %v, got %v", ssh.UserCert, cert.CertType)
	case opts.CertType == "host" && cert.CertType != ssh.HostCert:
		return fmt.Errorf("certificate type is not valid, want %v, got %v", ssh.HostCert, cert.CertType)
	case cert.ValidAfter != uint64(opts.ValidAfter.Unix()):
		return fmt.Errorf("certificate valid after is not valid, want %v, got %v", opts.ValidAfter.Unix(), time.Unix(int64(cert.ValidAfter), 0))
	case cert.ValidBefore != uint64(opts.ValidBefore.Unix()):
		return fmt.Errorf("certificate valid after is not valid, want %v, got %v", opts.ValidAfter.Unix(), time.Unix(int64(cert.ValidAfter), 0))
	case opts.CertType == "user" && len(cert.Extensions) != 5:
		return fmt.Errorf("certificate extensions number is invalid, want 5, got %d", len(cert.Extensions))
	case opts.CertType == "host" && len(cert.Extensions) != 0:
		return fmt.Errorf("certificate extensions number is invalid, want 0, got %d", len(cert.Extensions))
	default:
		return nil
	}
}

func signSSHCertificate(key crypto.PublicKey, opts SSHOptions, signOpts []SignOption, signKey crypto.Signer) (*ssh.Certificate, error) {
	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		return nil, err
	}

	var mods []SSHCertificateModifier
	var validators []SSHCertificateValidator

	for _, op := range signOpts {
		switch o := op.(type) {
		// modify the ssh.Certificate
		case SSHCertificateModifier:
			mods = append(mods, o)
		// modify the ssh.Certificate given the SSHOptions
		case SSHCertificateOptionModifier:
			mods = append(mods, o.Option(opts))
		// validate the ssh.Certificate
		case SSHCertificateValidator:
			validators = append(validators, o)
		// validate the given SSHOptions
		case SSHCertificateOptionsValidator:
			if err := o.Valid(opts); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("signSSH: invalid extra option type %T", o)
		}
	}

	// Build base certificate with the key and some random values
	cert := &ssh.Certificate{
		Nonce:  []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
		Key:    pub,
		Serial: 1234567890,
	}

	// Use opts to modify the certificate
	if err := opts.Modify(cert); err != nil {
		return nil, err
	}

	// Use provisioner modifiers
	for _, m := range mods {
		if err := m.Modify(cert); err != nil {
			return nil, err
		}
	}

	// Get signer from authority keys
	var signer ssh.Signer
	switch cert.CertType {
	case ssh.UserCert:
		signer, err = ssh.NewSignerFromSigner(signKey)
	case ssh.HostCert:
		signer, err = ssh.NewSignerFromSigner(signKey)
	default:
		return nil, fmt.Errorf("unexpected ssh certificate type: %d", cert.CertType)
	}
	if err != nil {
		return nil, err
	}
	cert.SignatureKey = signer.PublicKey()

	// Get bytes for signing trailing the signature length.
	data := cert.Marshal()
	data = data[:len(data)-4]

	// Sign the certificate
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, err
	}
	cert.Signature = sig

	// User provisioners validators
	for _, v := range validators {
		if err := v.Valid(cert); err != nil {
			return nil, err
		}
	}

	return cert, nil
}
