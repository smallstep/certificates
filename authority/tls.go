package authority

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/tlsutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/jose"
)

// GetTLSOptions returns the tls options configured.
func (a *Authority) GetTLSOptions() *tlsutil.TLSOptions {
	return a.config.TLS
}

var oidAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}

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
func (a *Authority) Sign(csr *x509.CertificateRequest, signOpts provisioner.Options, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
	var (
		errContext     = apiCtx{"csr": csr, "signOptions": signOpts}
		mods           = []x509util.WithOption{withDefaultASN1DN(a.config.AuthorityConfig.Template)}
		certValidators = []provisioner.CertificateValidator{}
		// issIdentity    = a.intermediateIdentity
	)

	// Set backdate with the configured value
	signOpts.Backdate = a.config.AuthorityConfig.Backdate.Duration

	for _, op := range extraOpts {
		switch k := op.(type) {
		case provisioner.CertificateValidator:
			certValidators = append(certValidators, k)
		case provisioner.CertificateRequestValidator:
			if err := k.Valid(csr); err != nil {
				return nil, &apiError{errors.Wrap(err, "sign"), http.StatusUnauthorized, errContext}
			}
		case provisioner.ProfileModifier:
			mods = append(mods, k.Option(signOpts))
		default:
			return nil, &apiError{errors.Errorf("sign: invalid extra option type %T", k),
				http.StatusInternalServerError, errContext}
		}
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, &apiError{errors.Wrap(err, "sign: invalid certificate request"),
			http.StatusBadRequest, errContext}
	}

	leaf, err := x509util.NewLeafProfileWithCSR(csr, a.x509Issuer, a.x509Signer, mods...)
	if err != nil {
		return nil, &apiError{errors.Wrapf(err, "sign"), http.StatusInternalServerError, errContext}
	}

	for _, v := range certValidators {
		if err := v.Valid(leaf.Subject()); err != nil {
			return nil, &apiError{errors.Wrap(err, "sign"), http.StatusUnauthorized, errContext}
		}
	}

	crtBytes, err := leaf.CreateCertificate()
	if err != nil {
		return nil, &apiError{errors.Wrap(err, "sign: error creating new leaf certificate"),
			http.StatusInternalServerError, errContext}
	}

	serverCert, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, &apiError{errors.Wrap(err, "sign: error parsing new leaf certificate"),
			http.StatusInternalServerError, errContext}
	}

	// caCert, err := x509.ParseCertificate(a.x509SignerCert.Raw)
	// if err != nil {
	// 	return nil, &apiError{errors.Wrap(err, "sign: error parsing intermediate certificate"),
	// 		http.StatusInternalServerError, errContext}
	// }

	if err = a.db.StoreCertificate(serverCert); err != nil {
		if err != db.ErrNotImplemented {
			return nil, &apiError{errors.Wrap(err, "sign: error storing certificate in db"),
				http.StatusInternalServerError, errContext}
		}
	}

	return []*x509.Certificate{serverCert, a.x509Issuer}, nil
}

// Renew creates a new Certificate identical to the old certificate, except
// with a validity window that begins 'now'.
func (a *Authority) Renew(oldCert *x509.Certificate) ([]*x509.Certificate, error) {
	// Check step provisioner extensions
	if err := a.authorizeRenew(oldCert); err != nil {
		return nil, err
	}

	// Issuer
	// issIdentity := a.intermediateIdentity

	// Durations
	backdate := a.config.AuthorityConfig.Backdate.Duration
	duration := oldCert.NotAfter.Sub(oldCert.NotBefore)
	now := time.Now().UTC()

	newCert := &x509.Certificate{
		PublicKey:                   oldCert.PublicKey,
		Issuer:                      a.x509Issuer.Subject,
		Subject:                     oldCert.Subject,
		NotBefore:                   now.Add(-1 * backdate),
		NotAfter:                    now.Add(duration - backdate),
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

	leaf, err := x509util.NewLeafProfileWithTemplate(newCert, a.x509Issuer, a.x509Signer)
	if err != nil {
		return nil, &apiError{err, http.StatusInternalServerError, apiCtx{}}
	}
	crtBytes, err := leaf.CreateCertificate()
	if err != nil {
		return nil, &apiError{errors.Wrap(err, "error renewing certificate from existing server certificate"),
			http.StatusInternalServerError, apiCtx{}}
	}

	serverCert, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, &apiError{errors.Wrap(err, "error parsing new server certificate"),
			http.StatusInternalServerError, apiCtx{}}
	}
	caCert, err := x509.ParseCertificate(a.x509Issuer.Raw)
	if err != nil {
		return nil, &apiError{errors.Wrap(err, "error parsing intermediate certificate"),
			http.StatusInternalServerError, apiCtx{}}
	}

	if err = a.db.StoreCertificate(serverCert); err != nil {
		if err != db.ErrNotImplemented {
			return nil, &apiError{errors.Wrap(err, "error storing certificate in db"),
				http.StatusInternalServerError, apiCtx{}}
		}
	}

	return []*x509.Certificate{serverCert, caCert}, nil
}

// RevokeOptions are the options for the Revoke API.
type RevokeOptions struct {
	Serial      string
	Reason      string
	ReasonCode  int
	PassiveOnly bool
	MTLS        bool
	Crt         *x509.Certificate
	OTT         string
}

// Revoke revokes a certificate.
//
// NOTE: Only supports passive revocation - prevent existing certificates from
// being renewed.
//
// TODO: Add OCSP and CRL support.
func (a *Authority) Revoke(ctx context.Context, opts *RevokeOptions) error {
	errContext := apiCtx{
		"serialNumber": opts.Serial,
		"reasonCode":   opts.ReasonCode,
		"reason":       opts.Reason,
		"passiveOnly":  opts.PassiveOnly,
		"mTLS":         opts.MTLS,
		"context":      string(provisioner.MethodFromContext(ctx)),
	}
	if opts.MTLS {
		errContext["certificate"] = base64.StdEncoding.EncodeToString(opts.Crt.Raw)
	} else {
		errContext["ott"] = opts.OTT
	}

	rci := &db.RevokedCertificateInfo{
		Serial:     opts.Serial,
		ReasonCode: opts.ReasonCode,
		Reason:     opts.Reason,
		MTLS:       opts.MTLS,
		RevokedAt:  time.Now().UTC(),
	}

	var (
		p   provisioner.Interface
		err error
	)
	// If not mTLS then get the TokenID of the token.
	if !opts.MTLS {
		// Validate payload
		token, err := jose.ParseSigned(opts.OTT)
		if err != nil {
			return &apiError{errors.Wrapf(err, "revoke: error parsing token"),
				http.StatusUnauthorized, errContext}
		}

		// Get claims w/out verification. We should have already verified this token
		// earlier with a call to authorizeSSHRevoke.
		var claims Claims
		if err = token.UnsafeClaimsWithoutVerification(&claims); err != nil {
			return &apiError{errors.Wrap(err, "revoke"), http.StatusUnauthorized, errContext}
		}

		// This method will also validate the audiences for JWK provisioners.
		var ok bool
		p, ok = a.provisioners.LoadByToken(token, &claims.Claims)
		if !ok {
			return &apiError{
				errors.Errorf("revoke: provisioner not found"),
				http.StatusInternalServerError, errContext}
		}
		rci.TokenID, err = p.GetTokenID(opts.OTT)
		if err != nil {
			return &apiError{errors.Wrap(err, "revoke: could not get ID for token"),
				http.StatusInternalServerError, errContext}
		}
		errContext["tokenID"] = rci.TokenID
	} else {
		// Load the Certificate provisioner if one exists.
		p, err = a.LoadProvisionerByCertificate(opts.Crt)
		if err != nil {
			return &apiError{
				errors.Wrap(err, "revoke: unable to load certificate provisioner"),
				http.StatusUnauthorized, errContext}
		}
	}
	rci.ProvisionerID = p.GetID()
	errContext["provisionerID"] = rci.ProvisionerID

	if provisioner.MethodFromContext(ctx) == provisioner.RevokeSSHMethod {
		err = a.db.RevokeSSH(rci)
	} else { // default to revoke x509
		err = a.db.Revoke(rci)
	}
	switch err {
	case nil:
		return nil
	case db.ErrNotImplemented:
		return &apiError{errors.New("revoke: no persistence layer configured"),
			http.StatusNotImplemented, errContext}
	case db.ErrAlreadyExists:
		return &apiError{errors.Errorf("revoke: certificate with serial number %s has already been revoked", rci.Serial),
			http.StatusBadRequest, errContext}
	default:
		return &apiError{err, http.StatusInternalServerError, errContext}
	}
}

// GetTLSCertificate creates a new leaf certificate to be used by the CA HTTPS server.
func (a *Authority) GetTLSCertificate() (*tls.Certificate, error) {
	profile, err := x509util.NewLeafProfile("Step Online CA",
		a.x509Issuer, a.x509Signer,
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
	intermediatePEM, err := pemutil.Serialize(a.x509Issuer)
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
