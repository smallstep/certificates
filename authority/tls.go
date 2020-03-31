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
	"github.com/smallstep/certificates/errs"
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
		opts            = []interface{}{errs.WithKeyVal("csr", csr), errs.WithKeyVal("signOptions", signOpts)}
		mods            = []x509util.WithOption{withDefaultASN1DN(a.config.AuthorityConfig.Template)}
		certValidators  = []provisioner.CertificateValidator{}
		forcedModifiers = []provisioner.CertificateEnforcer{}
	)

	// Set backdate with the configured value
	signOpts.Backdate = a.config.AuthorityConfig.Backdate.Duration

	for _, op := range extraOpts {
		switch k := op.(type) {
		case provisioner.CertificateValidator:
			certValidators = append(certValidators, k)
		case provisioner.CertificateRequestValidator:
			if err := k.Valid(csr); err != nil {
				return nil, errs.Wrap(http.StatusUnauthorized, err, "authority.Sign", opts...)
			}
		case provisioner.ProfileModifier:
			mods = append(mods, k.Option(signOpts))
		case provisioner.CertificateEnforcer:
			forcedModifiers = append(forcedModifiers, k)
		default:
			return nil, errs.InternalServer("authority.Sign; invalid extra option type %T", append([]interface{}{k}, opts...)...)
		}
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, errs.Wrap(http.StatusBadRequest, err, "authority.Sign; invalid certificate request", opts...)
	}

	leaf, err := x509util.NewLeafProfileWithCSR(csr, a.x509Issuer, a.x509Signer, mods...)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.Sign", opts...)
	}

	// Certificate validation
	for _, v := range certValidators {
		if err := v.Valid(leaf.Subject(), signOpts); err != nil {
			return nil, errs.Wrap(http.StatusUnauthorized, err, "authority.Sign", opts...)
		}
	}

	// Certificate modifier after validation
	for _, m := range forcedModifiers {
		if err := m.Enforce(leaf.Subject()); err != nil {
			return nil, errs.Wrap(http.StatusUnauthorized, err, "authority.Sign", opts...)
		}
	}

	crtBytes, err := leaf.CreateCertificate()
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err,
			"authority.Sign; error creating new leaf certificate", opts...)
	}

	serverCert, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err,
			"authority.Sign; error parsing new leaf certificate", opts...)
	}

	if err = a.db.StoreCertificate(serverCert); err != nil {
		if err != db.ErrNotImplemented {
			return nil, errs.Wrap(http.StatusInternalServerError, err,
				"authority.Sign; error storing certificate in db", opts...)
		}
	}

	return []*x509.Certificate{serverCert, a.x509Issuer}, nil
}

// Renew creates a new Certificate identical to the old certificate, except
// with a validity window that begins 'now'.
func (a *Authority) Renew(oldCert *x509.Certificate) ([]*x509.Certificate, error) {
	opts := []interface{}{errs.WithKeyVal("serialNumber", oldCert.SerialNumber.String())}

	// Check step provisioner extensions
	if err := a.authorizeRenew(oldCert); err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.Renew", opts...)
	}

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
		PermittedDNSDomainsCritical: oldCert.PermittedDNSDomainsCritical,
		PermittedEmailAddresses:     oldCert.PermittedEmailAddresses,
		DNSNames:                    oldCert.DNSNames,
		EmailAddresses:              oldCert.EmailAddresses,
		IPAddresses:                 oldCert.IPAddresses,
		URIs:                        oldCert.URIs,
		PermittedDNSDomains:         oldCert.PermittedDNSDomains,
		ExcludedDNSDomains:          oldCert.ExcludedDNSDomains,
		PermittedIPRanges:           oldCert.PermittedIPRanges,
		ExcludedIPRanges:            oldCert.ExcludedIPRanges,
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
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.Renew", opts...)
	}
	crtBytes, err := leaf.CreateCertificate()
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err,
			"authority.Renew; error renewing certificate from existing server certificate", opts...)
	}

	serverCert, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err,
			"authority.Renew; error parsing new server certificate", opts...)
	}

	if err = a.db.StoreCertificate(serverCert); err != nil {
		if err != db.ErrNotImplemented {
			return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.Renew; error storing certificate in db", opts...)
		}
	}

	return []*x509.Certificate{serverCert, a.x509Issuer}, nil
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
func (a *Authority) Revoke(ctx context.Context, revokeOpts *RevokeOptions) error {
	opts := []interface{}{
		errs.WithKeyVal("serialNumber", revokeOpts.Serial),
		errs.WithKeyVal("reasonCode", revokeOpts.ReasonCode),
		errs.WithKeyVal("reason", revokeOpts.Reason),
		errs.WithKeyVal("passiveOnly", revokeOpts.PassiveOnly),
		errs.WithKeyVal("MTLS", revokeOpts.MTLS),
		errs.WithKeyVal("context", string(provisioner.MethodFromContext(ctx))),
	}
	if revokeOpts.MTLS {
		opts = append(opts, errs.WithKeyVal("certificate", base64.StdEncoding.EncodeToString(revokeOpts.Crt.Raw)))
	} else {
		opts = append(opts, errs.WithKeyVal("token", revokeOpts.OTT))
	}

	rci := &db.RevokedCertificateInfo{
		Serial:     revokeOpts.Serial,
		ReasonCode: revokeOpts.ReasonCode,
		Reason:     revokeOpts.Reason,
		MTLS:       revokeOpts.MTLS,
		RevokedAt:  time.Now().UTC(),
	}

	var (
		p   provisioner.Interface
		err error
	)
	// If not mTLS then get the TokenID of the token.
	if !revokeOpts.MTLS {
		token, err := jose.ParseSigned(revokeOpts.OTT)
		if err != nil {
			return errs.Wrap(http.StatusUnauthorized, err,
				"authority.Revoke; error parsing token", opts...)
		}

		// Get claims w/out verification.
		var claims Claims
		if err = token.UnsafeClaimsWithoutVerification(&claims); err != nil {
			return errs.Wrap(http.StatusUnauthorized, err, "authority.Revoke", opts...)
		}

		// This method will also validate the audiences for JWK provisioners.
		var ok bool
		p, ok = a.provisioners.LoadByToken(token, &claims.Claims)
		if !ok {
			return errs.InternalServer("authority.Revoke; provisioner not found", opts...)
		}
		rci.TokenID, err = p.GetTokenID(revokeOpts.OTT)
		if err != nil {
			return errs.Wrap(http.StatusInternalServerError, err,
				"authority.Revoke; could not get ID for token")
		}
		opts = append(opts, errs.WithKeyVal("tokenID", rci.TokenID))
	} else {
		// Load the Certificate provisioner if one exists.
		p, err = a.LoadProvisionerByCertificate(revokeOpts.Crt)
		if err != nil {
			return errs.Wrap(http.StatusUnauthorized, err,
				"authority.Revoke: unable to load certificate provisioner", opts...)
		}
	}
	rci.ProvisionerID = p.GetID()
	opts = append(opts, errs.WithKeyVal("provisionerID", rci.ProvisionerID))

	if provisioner.MethodFromContext(ctx) == provisioner.SSHRevokeMethod {
		err = a.db.RevokeSSH(rci)
	} else { // default to revoke x509
		err = a.db.Revoke(rci)
	}
	switch err {
	case nil:
		return nil
	case db.ErrNotImplemented:
		return errs.NotImplemented("authority.Revoke; no persistence layer configured", opts...)
	case db.ErrAlreadyExists:
		return errs.BadRequest("authority.Revoke; certificate with serial "+
			"number %s has already been revoked", append([]interface{}{rci.Serial}, opts...)...)
	default:
		return errs.Wrap(http.StatusInternalServerError, err, "authority.Revoke", opts...)
	}
}

// GetTLSCertificate creates a new leaf certificate to be used by the CA HTTPS server.
func (a *Authority) GetTLSCertificate() (*tls.Certificate, error) {
	profile, err := x509util.NewLeafProfile("Step Online CA", a.x509Issuer, a.x509Signer,
		x509util.WithHosts(strings.Join(a.config.DNSNames, ",")))
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.GetTLSCertificate")
	}

	crtBytes, err := profile.CreateCertificate()
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.GetTLSCertificate")
	}

	keyPEM, err := pemutil.Serialize(profile.SubjectPrivateKey())
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.GetTLSCertificate")
	}

	crtPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	})

	// Load the x509 key pair (combining server and intermediate blocks)
	// to a tls.Certificate.
	intermediatePEM, err := pemutil.Serialize(a.x509Issuer)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.GetTLSCertificate")
	}
	tlsCrt, err := tls.X509KeyPair(append(crtPEM,
		pem.EncodeToMemory(intermediatePEM)...),
		pem.EncodeToMemory(keyPEM))
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err,
			"authority.GetTLSCertificate; error creating tls certificate")
	}

	// Get the 'leaf' certificate and set the attribute accordingly.
	leaf, err := x509.ParseCertificate(tlsCrt.Certificate[0])
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err,
			"authority.GetTLSCertificate; error parsing tls certificate")
	}
	tlsCrt.Leaf = leaf

	return &tlsCrt, nil
}
