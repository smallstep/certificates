package provisioner

import (
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/smallstep/certificates/errs"
	"go.step.sm/crypto/sshutil"
	"golang.org/x/crypto/ssh"
)

func validateSSHCertificate(cert *ssh.Certificate, opts *SignSSHOptions) error {
	switch {
	case cert == nil:
		return fmt.Errorf("certificate is nil")
	case cert.Signature == nil:
		return fmt.Errorf("certificate signature is nil")
	case cert.SignatureKey == nil:
		return fmt.Errorf("certificate signature is nil")
	case !reflect.DeepEqual(cert.ValidPrincipals, opts.Principals) && (len(opts.Principals) > 0 || len(cert.ValidPrincipals) > 0):
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

func signSSHCertificate(key crypto.PublicKey, opts SignSSHOptions, signOpts []SignOption, signKey crypto.Signer) (*ssh.Certificate, error) {
	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		return nil, err
	}

	var mods []SSHCertModifier
	var certOptions []sshutil.Option
	var validators []SSHCertValidator

	for _, op := range signOpts {
		switch o := op.(type) {
		case Interface:
		// add options to NewCertificate
		case SSHCertificateOptions:
			certOptions = append(certOptions, o.Options(opts)...)
		// modify the ssh.Certificate
		case SSHCertModifier:
			mods = append(mods, o)
		// validate the ssh.Certificate
		case SSHCertValidator:
			validators = append(validators, o)
		// validate the given SSHOptions
		case SSHCertOptionsValidator:
			if err := o.Valid(opts); err != nil {
				return nil, err
			}
		// call webhooks
		case *WebhookController:
		default:
			return nil, fmt.Errorf("signSSH: invalid extra option type %T", o)
		}
	}

	// Simulated certificate request with request options.
	cr := sshutil.CertificateRequest{
		Type:       opts.CertType,
		KeyID:      opts.KeyID,
		Principals: opts.Principals,
		Key:        pub,
	}

	// Create certificate from template.
	certificate, err := sshutil.NewCertificate(cr, certOptions...)
	if err != nil {
		var templErr *sshutil.TemplateError
		if errors.As(err, &templErr) {
			return nil, errs.NewErr(http.StatusBadRequest, templErr,
				errs.WithMessage(templErr.Error()),
				errs.WithKeyVal("signOptions", signOpts),
			)
		}
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.SignSSH")
	}

	// Get actual *ssh.Certificate and continue with provisioner modifiers.
	cert := certificate.GetCertificate()

	// Use SignSSHOptions to modify the certificate validity. It will be later
	// checked or set if not defined.
	if err := opts.ModifyValidity(cert); err != nil {
		return nil, errs.Wrap(http.StatusBadRequest, err, "authority.SignSSH")
	}

	// Use provisioner modifiers.
	for _, m := range mods {
		if err := m.Modify(cert, opts); err != nil {
			return nil, errs.Wrap(http.StatusForbidden, err, "authority.SignSSH")
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

	// Sign certificate.
	cert, err = sshutil.CreateCertificate(cert, signer)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.SignSSH: error signing certificate")
	}

	// User provisioners validators.
	for _, v := range validators {
		if err := v.Valid(cert, opts); err != nil {
			return nil, errs.Wrap(http.StatusForbidden, err, "authority.SignSSH")
		}
	}

	return cert, nil
}
