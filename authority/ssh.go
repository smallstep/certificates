package authority

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/crypto/randutil"
	"golang.org/x/crypto/ssh"
)

func generateSSHPublicKeyID(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

// SignSSH creates a signed SSH certificate with the given public key and options.
func (a *Authority) SignSSH(key ssh.PublicKey, opts provisioner.SSHOptions, signOpts ...provisioner.SignOption) (*ssh.Certificate, error) {
	var mods []provisioner.SSHCertificateModifier
	var validators []provisioner.SSHCertificateValidator

	for _, op := range signOpts {
		switch o := op.(type) {
		// modify the ssh.Certificate
		case provisioner.SSHCertificateModifier:
			mods = append(mods, o)
		// modify the ssh.Certificate given the SSHOptions
		case provisioner.SSHCertificateOptionModifier:
			mods = append(mods, o.Option(opts))
		// validate the ssh.Certificate
		case provisioner.SSHCertificateValidator:
			validators = append(validators, o)
		// validate the given SSHOptions
		case provisioner.SSHCertificateOptionsValidator:
			if err := o.Valid(opts); err != nil {
				return nil, &apiError{err: err, code: http.StatusUnauthorized}
			}
		default:
			return nil, &apiError{
				err:  errors.Errorf("signSSH: invalid extra option type %T", o),
				code: http.StatusInternalServerError,
			}
		}
	}

	nonce, err := randutil.ASCII(32)
	if err != nil {
		return nil, err
	}

	var serial uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &serial); err != nil {
		return nil, errors.Wrap(err, "error reading random number")
	}

	// Build base certificate with the key and some random values
	cert := &ssh.Certificate{
		Nonce:  []byte(nonce),
		Key:    key,
		Serial: serial,
	}

	// Use opts to modify the certificate
	if err := opts.Modify(cert); err != nil {
		return nil, err
	}

	// Use provisioner modifiers
	for _, m := range mods {
		if err := m.Modify(cert); err != nil {
			return nil, &apiError{err: err, code: http.StatusInternalServerError}
		}
	}

	// Get signer from authority keys
	var signer ssh.Signer
	switch cert.CertType {
	case ssh.UserCert:
		if a.sshCAUserCertSignKey == nil {
			return nil, &apiError{
				err:  errors.New("signSSH: user certificate signing is not enabled"),
				code: http.StatusNotImplemented,
			}
		}
		if signer, err = ssh.NewSignerFromSigner(a.sshCAUserCertSignKey); err != nil {
			return nil, &apiError{
				err:  errors.Wrap(err, "signSSH: error creating signer"),
				code: http.StatusInternalServerError,
			}
		}
	case ssh.HostCert:
		if a.sshCAHostCertSignKey == nil {
			return nil, &apiError{
				err:  errors.New("signSSH: host certificate signing is not enabled"),
				code: http.StatusNotImplemented,
			}
		}
		if signer, err = ssh.NewSignerFromSigner(a.sshCAHostCertSignKey); err != nil {
			return nil, &apiError{
				err:  errors.Wrap(err, "signSSH: error creating signer"),
				code: http.StatusInternalServerError,
			}
		}
	default:
		return nil, &apiError{
			err:  errors.Errorf("unexpected ssh certificate type: %d", cert.CertType),
			code: http.StatusInternalServerError,
		}
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
			return nil, &apiError{err: err, code: http.StatusUnauthorized}
		}
	}

	return cert, nil
}
