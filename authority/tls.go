package authority

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/tlsutil"
	"github.com/smallstep/cli/crypto/x509util"
	stepx509 "github.com/smallstep/cli/pkg/x509"
)

// GetTLSOptions returns the tls options configured.
func (a *Authority) GetTLSOptions() *tlsutil.TLSOptions {
	return a.config.TLS
}

// SignOptions contains the options that can be passed to the Authority.Sign
// method.
type SignOptions struct {
	NotAfter  time.Time `json:"notAfter"`
	NotBefore time.Time `json:"notBefore"`
}

var (
	// Step extensions OIDs
	stepOIDRoot               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64}
	stepOIDProvisioner        = append(asn1.ObjectIdentifier(nil), append(stepOIDRoot, 1)...)
	oidAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	// Certificate transparency extensions OIDs
	ctPoisonOID                     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	ctSigendCertificateTimestampOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

type stepProvisionerASN1 struct {
	Type         int
	Name         []byte
	CredentialID []byte
}

const provisionerTypeJWK = 1

func withProvisionerOID(name, kid string) x509util.WithOption {
	return func(p x509util.Profile) error {
		crt := p.Subject()

		b, err := asn1.Marshal(stepProvisionerASN1{
			Type:         provisionerTypeJWK,
			Name:         []byte(name),
			CredentialID: []byte(kid),
		})
		if err != nil {
			return err
		}
		crt.ExtraExtensions = append(crt.ExtraExtensions, pkix.Extension{
			Id:       stepOIDProvisioner,
			Critical: false,
			Value:    b,
		})

		return nil
	}
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
func (a *Authority) Sign(csr *x509.CertificateRequest, signOpts SignOptions, extraOpts ...interface{}) (*x509.Certificate, *x509.Certificate, error) {
	var (
		errContext = context{"csr": csr, "signOptions": signOpts}
		claims     = []certClaim{}
		mods       = []x509util.WithOption{}
	)
	for _, op := range extraOpts {
		switch k := op.(type) {
		case certClaim:
			claims = append(claims, k)
		case x509util.WithOption:
			mods = append(mods, k)
		case *Provisioner:
			m, c, err := k.getTLSApps(signOpts)
			if err != nil {
				return nil, nil, &apiError{err, http.StatusInternalServerError, errContext}
			}
			mods = append(mods, m...)
			mods = append(mods, []x509util.WithOption{
				withDefaultASN1DN(a.config.AuthorityConfig.Template),
			}...)
			claims = append(claims, c...)
		default:
			return nil, nil, &apiError{errors.Errorf("sign: invalid extra option type %T", k),
				http.StatusInternalServerError, errContext}
		}
	}

	// Add CT Poison extension
	if a.ctClient != nil {
		mods = append(mods, x509util.WithCTPoison())
	}

	stepCSR, err := stepx509.ParseCertificateRequest(csr.Raw)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "sign: error converting x509 csr to stepx509 csr"),
			http.StatusInternalServerError, errContext}
	}

	issIdentity := a.intermediateIdentity
	leaf, err := x509util.NewLeafProfileWithCSR(stepCSR, issIdentity.Crt,
		issIdentity.Key, mods...)
	if err != nil {
		return nil, nil, &apiError{errors.Wrapf(err, "sign"), http.StatusInternalServerError, errContext}
	}

	if err := validateClaims(leaf.Subject(), claims); err != nil {
		return nil, nil, &apiError{errors.Wrapf(err, "sign"), http.StatusUnauthorized, errContext}
	}

	crtBytes, err := leaf.CreateCertificate()
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "sign: error creating new leaf certificate"),
			http.StatusInternalServerError, errContext}
	}

	if a.ctClient != nil {
		// Submit precertificate chain and get SCTs
		scts, err := a.ctClient.GetSCTs(crtBytes, issIdentity.Crt.Raw)
		if err != nil {
			return nil, nil, &apiError{errors.Wrap(err, "sign: error getting SCTs for certificate"),
				http.StatusBadGateway, errContext}
		}

		// Remove ct poison extension and add sct extension
		leaf.RemoveExtension(ctPoisonOID)
		leaf.AddExtension(scts.GetExtension())

		// Recreate final certificate
		if crtBytes, err = leaf.CreateCertificate(); err != nil {
			return nil, nil, &apiError{errors.Wrap(err, "sign: error creating final leaf certificate"),
				http.StatusInternalServerError, errContext}
		}
	}

	serverCert, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "sign: error parsing new leaf certificate"),
			http.StatusInternalServerError, errContext}
	}

	caCert, err := x509.ParseCertificate(issIdentity.Crt.Raw)
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "sign: error parsing intermediate certificate"),
			http.StatusInternalServerError, errContext}
	}

	if a.ctClient != nil {
		// Submit final certificate chain
		if _, err := a.ctClient.SubmitToLogs(serverCert.Raw, caCert.Raw); err != nil {
			return nil, nil, &apiError{errors.Wrap(err, "sign: error submitting final certificate to ct logs"),
				http.StatusBadGateway, errContext}
		}
	}

	return serverCert, caCert, nil
}

// Renew creates a new Certificate identical to the old certificate, except
// with a validity window that begins 'now'.
func (a *Authority) Renew(ocx *x509.Certificate) (*x509.Certificate, *x509.Certificate, error) {
	// Check step provisioner extensions
	if err := a.authorizeRenewal(ocx); err != nil {
		return nil, nil, err
	}

	// Issuer
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

	// Copy all extensions except for Authority Key Identifier. This one might
	// be different if we rotate the intermediate certificate and it will cause
	// a TLS bad certificate error.
	for _, ext := range oldCert.Extensions {
		if !ext.Id.Equal(oidAuthorityKeyIdentifier) {
			newCert.ExtraExtensions = append(newCert.ExtraExtensions, ext)
		}
	}

	opts := []x509util.WithOption{}
	// Add CT Poison extension
	if a.ctClient != nil {
		opts = append(opts, x509util.WithCTPoison())
	}

	leaf, err := x509util.NewLeafProfileWithTemplate(newCert, issIdentity.Crt, issIdentity.Key, opts...)
	if err != nil {
		return nil, nil, &apiError{err, http.StatusInternalServerError, context{}}
	}

	// Remove previous SCTs if any
	leaf.RemoveExtension(ctSigendCertificateTimestampOID)

	crtBytes, err := leaf.CreateCertificate()
	if err != nil {
		return nil, nil, &apiError{errors.Wrap(err, "error renewing certificate from existing server certificate"),
			http.StatusInternalServerError, context{}}
	}

	if a.ctClient != nil {
		// Submit precertificate chain and get SCTs
		scts, err := a.ctClient.GetSCTs(crtBytes, issIdentity.Crt.Raw)
		if err != nil {
			return nil, nil, &apiError{errors.Wrap(err, "renew: error getting SCTs for certificate"),
				http.StatusBadGateway, context{}}
		}

		// Remove ct poison extension and add sct extension
		leaf.RemoveExtension(ctPoisonOID)
		leaf.AddExtension(scts.GetExtension())

		// Recreate final certificate
		if crtBytes, err = leaf.CreateCertificate(); err != nil {
			return nil, nil, &apiError{errors.Wrap(err, "renew: error creating final leaf certificate"),
				http.StatusInternalServerError, context{}}
		}
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

	if a.ctClient != nil {
		// Submit final certificate chain
		if _, err := a.ctClient.SubmitToLogs(serverCert.Raw, caCert.Raw); err != nil {
			return nil, nil, &apiError{errors.Wrap(err, "renew: error submitting final certificate to ct logs"),
				http.StatusBadGateway, context{}}
		}
	}

	return serverCert, caCert, nil
}

// GetTLSCertificate creates a new leaf certificate to be used by the CA HTTPS server.
func (a *Authority) GetTLSCertificate() (*tls.Certificate, error) {
	opts := []x509util.WithOption{
		x509util.WithHosts(strings.Join(a.config.DNSNames, ",")),
	}

	// Add CT Poison extension
	if a.ctClient != nil {
		opts = append(opts, x509util.WithCTPoison())
	}

	profile, err := x509util.NewLeafProfile("Step Online CA",
		a.intermediateIdentity.Crt, a.intermediateIdentity.Key, opts...)
	if err != nil {
		return nil, err
	}

	crtBytes, err := profile.CreateCertificate()
	if err != nil {
		return nil, err
	}

	if a.ctClient != nil {
		// Submit precertificate chain and get SCTs
		scts, err := a.ctClient.GetSCTs(crtBytes, a.intermediateIdentity.Crt.Raw)
		if err != nil {
			return nil, errors.Wrap(err, "error getting SCTs for certificate")
		}

		// Remove ct poison extension and add sct extension
		profile.RemoveExtension(ctPoisonOID)
		profile.AddExtension(scts.GetExtension())

		// Recreate final certificate
		if crtBytes, err = profile.CreateCertificate(); err != nil {
			return nil, errors.Wrap(err, "error creating final leaf certificate")
		}
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

	if a.ctClient != nil {
		// Submit final certificate chain
		if _, err := a.ctClient.SubmitToLogs(crtBytes, intermediatePEM.Bytes); err != nil {
			return nil, errors.Wrap(err, "error submitting final certificate to ct logs")
		}
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
