package authority

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/ca-component/api"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/tlsutil"
	"github.com/smallstep/cli/crypto/x509util"
	stepx509 "github.com/smallstep/cli/pkg/x509"
)

// GetMinDuration returns the minimum validity of an end-entity (not root or
// intermediate) certificate.
func (a *Authority) GetMinDuration() time.Duration {
	if a.config.AuthorityConfig.MinCertDuration == nil {
		return minCertDuration
	}
	return a.config.AuthorityConfig.MinCertDuration.Duration
}

// GetMaxDuration returns the maximum validity of an end-entity (not root or
// intermediate) certificate.
func (a *Authority) GetMaxDuration() time.Duration {
	if a.config.AuthorityConfig.MaxCertDuration == nil {
		return maxCertDuration
	}
	return a.config.AuthorityConfig.MaxCertDuration.Duration
}

// GetTLSOptions returns the tls options configured.
func (a *Authority) GetTLSOptions() *tlsutil.TLSOptions {
	return a.config.TLS
}

func withDefaultASN1DN(def *x509util.ASN1DN) x509util.WithOption {
	return func(p x509util.Profile) error {
		if def == nil {
			return errors.New("default ASN1DN template cannot be nil")
		}
		crt := p.Subject()

		if len(crt.Subject.Country) == 0 && def.Country != "" {
			crt.Subject.Country = append(crt.Subject.Country, def.Country)
		}
		if len(crt.Subject.Organization) == 0 && def.Organization != "" {
			crt.Subject.Organization = append(crt.Subject.Organization, def.Organization)
		}
		if len(crt.Subject.OrganizationalUnit) == 0 && def.OrganizationalUnit != "" {
			crt.Subject.OrganizationalUnit = append(crt.Subject.OrganizationalUnit, def.OrganizationalUnit)
		}
		if len(crt.Subject.Locality) == 0 && def.Locality != "" {
			crt.Subject.Locality = append(crt.Subject.Locality, def.Locality)
		}
		if len(crt.Subject.Province) == 0 && def.Province != "" {
			crt.Subject.Province = append(crt.Subject.Province, def.Province)
		}
		if len(crt.Subject.StreetAddress) == 0 && def.StreetAddress != "" {
			crt.Subject.StreetAddress = append(crt.Subject.StreetAddress, def.StreetAddress)
		}

		return nil
	}
}

// Sign creates a signed certificate from a certificate signing request.
func (a *Authority) Sign(csr *x509.CertificateRequest, opts api.SignOptions, claims ...api.Claim) (*x509.Certificate, *x509.Certificate, error) {
	if err := ValidateClaims(csr, claims); err != nil {
		return nil, nil, &apiError{err, http.StatusUnauthorized, context{}}
	}

	stepCSR, err := stepx509.ParseCertificateRequest(csr.Raw)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "error converting x509 csr to stepx509 csr"),
			http.StatusInternalServerError, context{}}
	}

	// DNSNames and IPAddresses are validated but to avoid duplications we will
	// clean them as x509util.NewLeafProfileWithCSR will set the right values.
	stepCSR.DNSNames = nil
	stepCSR.IPAddresses = nil

	issIdentity := a.intermediateIdentity
	leaf, err := x509util.NewLeafProfileWithCSR(stepCSR, issIdentity.Crt,
		issIdentity.Key, x509util.WithHosts(csr.Subject.CommonName),
		x509util.WithNotBeforeAfter(opts.NotBefore, opts.NotAfter),
		withDefaultASN1DN(a.config.AuthorityConfig.Template))
	if err != nil {
		return nil, nil, &apiError{err, http.StatusInternalServerError, context{}}
	}
	crtBytes, err := leaf.CreateCertificate()
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "error creating new leaf certificate from input csr"),
			http.StatusInternalServerError, context{}}
	}

	serverCert, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "error parsing new server certificate"),
			http.StatusInternalServerError, context{}}
	}
	caCert, err := x509.ParseCertificate(issIdentity.Crt.Raw)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "error parsing intermediate certificate"),
			http.StatusInternalServerError, context{}}
	}

	return serverCert, caCert, nil
}

// Renew creates a new Certificate identical to the old certificate, except
// with a validity window that begins 'now'.
func (a *Authority) Renew(ocx *x509.Certificate) (*x509.Certificate, *x509.Certificate, error) {
	issIdentity := a.intermediateIdentity

	// Convert a realx509.Certificate to the step x509 Certificate.
	oldCert, err := stepx509.ParseCertificate(ocx.Raw)
	if err != nil {
		return nil, nil, &apiError{
			errors.Wrap(err, "error converting x509.Certificate to stepx509.Certificate"),
			http.StatusInternalServerError, context{},
		}
	}

	now := time.Now().UTC()
	duration := oldCert.NotAfter.Sub(oldCert.NotBefore)
	newCert := &stepx509.Certificate{
		PublicKey:                   oldCert.PublicKey,
		Issuer:                      issIdentity.Crt.Subject,
		Subject:                     oldCert.Subject,
		NotBefore:                   now,
		NotAfter:                    now.Add(duration),
		KeyUsage:                    oldCert.KeyUsage,
		Extensions:                  oldCert.Extensions,
		ExtraExtensions:             oldCert.ExtraExtensions,
		UnhandledCriticalExtensions: oldCert.UnhandledCriticalExtensions,
		ExtKeyUsage:                 oldCert.ExtKeyUsage,
		UnknownExtKeyUsage:          oldCert.UnknownExtKeyUsage,
		BasicConstraintsValid:       oldCert.BasicConstraintsValid,
		IsCA:                        oldCert.IsCA,
		MaxPathLen:                  oldCert.MaxPathLen,
		MaxPathLenZero:              oldCert.MaxPathLenZero,
		OCSPServer:                  oldCert.OCSPServer,
		IssuingCertificateURL:       oldCert.IssuingCertificateURL,
		DNSNames:                    oldCert.DNSNames,
		EmailAddresses:              oldCert.EmailAddresses,
		IPAddresses:                 oldCert.IPAddresses,
		URIs:                        oldCert.URIs,
		PermittedDNSDomainsCritical: oldCert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         oldCert.PermittedDNSDomains,
		ExcludedDNSDomains:          oldCert.ExcludedDNSDomains,
		PermittedIPRanges:           oldCert.PermittedIPRanges,
		ExcludedIPRanges:            oldCert.ExcludedIPRanges,
		PermittedEmailAddresses:     oldCert.PermittedEmailAddresses,
		ExcludedEmailAddresses:      oldCert.ExcludedEmailAddresses,
		PermittedURIDomains:         oldCert.PermittedURIDomains,
		ExcludedURIDomains:          oldCert.ExcludedURIDomains,
		CRLDistributionPoints:       oldCert.CRLDistributionPoints,
		PolicyIdentifiers:           oldCert.PolicyIdentifiers,
	}

	leaf, err := x509util.NewLeafProfileWithTemplate(newCert,
		issIdentity.Crt, issIdentity.Key)
	if err != nil {
		return nil, nil, &apiError{err, http.StatusInternalServerError, context{}}
	}
	crtBytes, err := leaf.CreateCertificate()
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "error renewing certificate from existing server certificate"),
			http.StatusInternalServerError, context{}}
	}

	serverCert, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "error parsing new server certificate"),
			http.StatusInternalServerError, context{}}
	}
	caCert, err := x509.ParseCertificate(issIdentity.Crt.Raw)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "error parsing intermediate certificate"),
			http.StatusInternalServerError, context{}}
	}

	return serverCert, caCert, nil
}

// GetTLSCertificate creates a new leaf certificate to be used by the CA HTTPS server.
func (a *Authority) GetTLSCertificate() (*tls.Certificate, error) {
	profile, err := x509util.NewLeafProfile("Step Online CA",
		a.intermediateIdentity.Crt, a.intermediateIdentity.Key,
		x509util.WithHosts(strings.Join(a.config.DNSNames, ",")))
	if err != nil {
		return nil, err
	}

	crtBytes, err := profile.CreateCertificate()
	if err != nil {
		return nil, err
	}

	keyPEM, err := pemutil.Serialize(profile.SubjectPrivateKey())
	if err != nil {
		return nil, err
	}

	crtPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	})

	// Load the x509 key pair (combining server and intermediate blocks)
	// to a tls.Certificate.
	intermediatePEM, err := pemutil.Serialize(a.intermediateIdentity.Crt)
	if err != nil {
		return nil, err
	}
	tlsCrt, err := tls.X509KeyPair(append(crtPEM,
		pem.EncodeToMemory(intermediatePEM)...),
		pem.EncodeToMemory(keyPEM))
	if err != nil {
		return nil, errors.Wrap(err, "error creating tls certificate")
	}

	// Get the 'leaf' certificate and set the attribute accordingly.
	leaf, err := x509.ParseCertificate(tlsCrt.Certificate[0])
	if err != nil {
		return nil, errors.Wrap(err, "error parsing tls certificate")
	}
	tlsCrt.Leaf = leaf

	return &tlsCrt, nil
}
