package authority

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	casapi "github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/webhook"
	"github.com/smallstep/nosql/database"
)

type tokenKey struct{}

// NewTokenContext adds the given token to the context.
func NewTokenContext(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey{}, token)
}

// TokenFromContext returns the token from the given context.
func TokenFromContext(ctx context.Context) (token string, ok bool) {
	token, ok = ctx.Value(tokenKey{}).(string)
	return
}

// GetTLSOptions returns the tls options configured.
func (a *Authority) GetTLSOptions() *config.TLSOptions {
	return a.config.TLS
}

var (
	oidAuthorityKeyIdentifier            = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidSubjectKeyIdentifier              = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
)

func withDefaultASN1DN(def *config.ASN1DN) provisioner.CertificateModifierFunc {
	return func(crt *x509.Certificate, _ provisioner.SignOptions) error {
		if def == nil {
			return errors.New("default ASN1DN template cannot be nil")
		}
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
		if crt.Subject.SerialNumber == "" && def.SerialNumber != "" {
			crt.Subject.SerialNumber = def.SerialNumber
		}
		if crt.Subject.CommonName == "" && def.CommonName != "" {
			crt.Subject.CommonName = def.CommonName
		}
		return nil
	}
}

// Sign creates a signed certificate from a certificate signing request. It
// creates a new context.Context, and calls into SignWithContext.
//
// Deprecated: Use authority.SignWithContext with an actual context.Context.
func (a *Authority) Sign(csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
	return a.SignWithContext(context.Background(), csr, signOpts, extraOpts...)
}

// SignWithContext creates a signed certificate from a certificate signing
// request, taking the provided context.Context.
func (a *Authority) SignWithContext(ctx context.Context, csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
	chain, prov, err := a.signX509(ctx, csr, signOpts, extraOpts...)
	a.meter.X509Signed(prov, err)
	return chain, err
}

func (a *Authority) signX509(ctx context.Context, csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, provisioner.Interface, error) {
	var (
		certOptions    []x509util.Option
		certValidators []provisioner.CertificateValidator
		certModifiers  []provisioner.CertificateModifier
		certEnforcers  []provisioner.CertificateEnforcer
	)

	opts := []any{errs.WithKeyVal("csr", csr), errs.WithKeyVal("signOptions", signOpts)}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, errs.ApplyOptions(
			errs.BadRequestErr(err, "invalid certificate request"),
			opts...,
		)
	}

	// Set backdate with the configured value
	signOpts.Backdate = a.config.AuthorityConfig.Backdate.Duration

	var (
		prov       provisioner.Interface
		pInfo      *casapi.ProvisionerInfo
		attData    *provisioner.AttestationData
		webhookCtl webhookController
	)
	for _, op := range extraOpts {
		switch k := op.(type) {
		// Capture current provisioner
		case provisioner.Interface:
			prov = k
			pInfo = &casapi.ProvisionerInfo{
				ID:   prov.GetID(),
				Type: prov.GetType().String(),
				Name: prov.GetName(),
			}
		// Adds new options to NewCertificate
		case provisioner.CertificateOptions:
			certOptions = append(certOptions, k.Options(signOpts)...)

		// Validate the given certificate request.
		case provisioner.CertificateRequestValidator:
			if err := k.Valid(csr); err != nil {
				return nil, prov, errs.ApplyOptions(
					errs.ForbiddenErr(err, "error validating certificate request"),
					opts...,
				)
			}

		// Validates the unsigned certificate template.
		case provisioner.CertificateValidator:
			certValidators = append(certValidators, k)

		// Modifies a certificate before validating it.
		case provisioner.CertificateModifier:
			certModifiers = append(certModifiers, k)

		// Modifies a certificate after validating it.
		case provisioner.CertificateEnforcer:
			certEnforcers = append(certEnforcers, k)

		// Extra information from ACME attestations.
		case provisioner.AttestationData:
			attData = &k

		// Capture the provisioner's webhook controller
		case webhookController:
			webhookCtl = k

		default:
			return nil, prov, errs.InternalServer("authority.Sign; invalid extra option type %T", append([]any{k}, opts...)...)
		}
	}

	if err := a.callEnrichingWebhooksX509(ctx, prov, webhookCtl, attData, csr); err != nil {
		return nil, prov, errs.ApplyOptions(
			errs.ForbiddenErr(err, err.Error()),
			errs.WithKeyVal("csr", csr),
			errs.WithKeyVal("signOptions", signOpts),
		)
	}

	crt, err := x509util.NewCertificate(csr, certOptions...)
	if err != nil {
		var te *x509util.TemplateError
		switch {
		case errors.As(err, &te):
			return nil, prov, errs.ApplyOptions(
				errs.BadRequestErr(err, err.Error()),
				errs.WithKeyVal("csr", csr),
				errs.WithKeyVal("signOptions", signOpts),
			)
		case strings.HasPrefix(err.Error(), "error unmarshaling certificate"):
			// explicitly check for unmarshaling errors, which are most probably caused by JSON template (syntax) errors
			return nil, prov, errs.InternalServerErr(templatingError(err),
				errs.WithKeyVal("csr", csr),
				errs.WithKeyVal("signOptions", signOpts),
				errs.WithMessage("error applying certificate template"),
			)
		default:
			return nil, prov, errs.Wrap(http.StatusInternalServerError, err, "authority.Sign", opts...)
		}
	}

	// Certificate modifiers before validation
	leaf := crt.GetCertificate()

	// Set default subject
	if err := withDefaultASN1DN(a.config.AuthorityConfig.Template).Modify(leaf, signOpts); err != nil {
		return nil, prov, errs.ApplyOptions(
			errs.ForbiddenErr(err, "error creating certificate"),
			opts...,
		)
	}

	for _, m := range certModifiers {
		if err := m.Modify(leaf, signOpts); err != nil {
			return nil, prov, errs.ApplyOptions(
				errs.ForbiddenErr(err, "error creating certificate"),
				opts...,
			)
		}
	}

	// Certificate validation.
	for _, v := range certValidators {
		if err := v.Valid(leaf, signOpts); err != nil {
			return nil, prov, errs.ApplyOptions(
				errs.ForbiddenErr(err, "error validating certificate"),
				opts...,
			)
		}
	}

	// Certificate modifiers after validation
	for _, m := range certEnforcers {
		if err = m.Enforce(leaf); err != nil {
			return nil, prov, errs.ApplyOptions(
				errs.ForbiddenErr(err, "error creating certificate"),
				opts...,
			)
		}
	}

	// Process injected modifiers after validation
	for _, m := range a.x509Enforcers {
		if err = m.Enforce(leaf); err != nil {
			return nil, prov, errs.ApplyOptions(
				errs.ForbiddenErr(err, "error creating certificate"),
				opts...,
			)
		}
	}

	// Check if authority is allowed to sign the certificate
	if err = a.isAllowedToSignX509Certificate(leaf); err != nil {
		var ee *errs.Error
		if errors.As(err, &ee) {
			return nil, prov, errs.ApplyOptions(ee, opts...)
		}
		return nil, prov, errs.InternalServerErr(err,
			errs.WithKeyVal("csr", csr),
			errs.WithKeyVal("signOptions", signOpts),
			errs.WithMessage("error creating certificate"),
		)
	}

	// Send certificate to webhooks for authorization
	if err := a.callAuthorizingWebhooksX509(ctx, prov, webhookCtl, crt, leaf, attData); err != nil {
		return nil, prov, errs.ApplyOptions(
			errs.ForbiddenErr(err, "error creating certificate"),
			opts...,
		)
	}

	// Sign certificate
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore.Add(signOpts.Backdate))

	resp, err := a.x509CAService.CreateCertificate(&casapi.CreateCertificateRequest{
		Template:    leaf,
		CSR:         csr,
		Lifetime:    lifetime,
		Backdate:    signOpts.Backdate,
		Provisioner: pInfo,
	})
	if err != nil {
		return nil, prov, errs.Wrap(http.StatusInternalServerError, err, "authority.Sign; error creating certificate", opts...)
	}

	chain := append([]*x509.Certificate{resp.Certificate}, resp.CertificateChain...)

	// Wrap provisioner with extra information, if not nil
	if prov != nil {
		prov = wrapProvisioner(prov, attData)
	}

	// Store certificate in the db.
	if err := a.storeCertificate(prov, chain); err != nil && !errors.Is(err, db.ErrNotImplemented) {
		return nil, prov, errs.Wrap(http.StatusInternalServerError, err, "authority.Sign; error storing certificate in db", opts...)
	}

	return chain, prov, nil
}

// isAllowedToSignX509Certificate checks if the Authority is allowed
// to sign the X.509 certificate.
func (a *Authority) isAllowedToSignX509Certificate(cert *x509.Certificate) error {
	if err := a.constraintsEngine.ValidateCertificate(cert); err != nil {
		return err
	}
	return a.policyEngine.IsX509CertificateAllowed(cert)
}

// AreSANsAllowed evaluates the provided sans against the
// authority X.509 policy.
func (a *Authority) AreSANsAllowed(_ context.Context, sans []string) error {
	return a.policyEngine.AreSANsAllowed(sans)
}

// Renew creates a new Certificate identical to the old certificate, except with
// a validity window that begins 'now'.
func (a *Authority) Renew(oldCert *x509.Certificate) ([]*x509.Certificate, error) {
	return a.RenewContext(context.Background(), oldCert, nil)
}

// Rekey is used for rekeying and renewing based on the public key. If the
// public key is 'nil' then it's assumed that the cert should be renewed using
// the existing public key. If the public key is not 'nil' then it's assumed
// that the cert should be rekeyed.
//
// For both Rekey and Renew all other attributes of the new certificate should
// match the old certificate. The exceptions are 'AuthorityKeyId' (which may
// have changed), 'SubjectKeyId' (different in case of rekey), and
// 'NotBefore/NotAfter' (the validity duration of the new certificate should be
// equal to the old one, but starting 'now').
func (a *Authority) Rekey(oldCert *x509.Certificate, pk crypto.PublicKey) ([]*x509.Certificate, error) {
	return a.RenewContext(context.Background(), oldCert, pk)
}

// RenewContext creates a new certificate identical to the old one, but it can
// optionally replace the public key with the given one. When running on RA
// mode, it can only renew a certificate using a renew token instead.
//
// For both rekey and renew operations, all other attributes of the new
// certificate should match the old certificate. The exceptions are
// 'AuthorityKeyId' (which may have changed), 'SubjectKeyId' (different in case
// of rekey), and 'NotBefore/NotAfter' (the validity duration of the new
// certificate should be equal to the old one, but starting 'now').
func (a *Authority) RenewContext(ctx context.Context, oldCert *x509.Certificate, pk crypto.PublicKey) ([]*x509.Certificate, error) {
	chain, prov, err := a.renewContext(ctx, oldCert, pk)
	if pk == nil {
		a.meter.X509Renewed(prov, err)
	} else {
		a.meter.X509Rekeyed(prov, err)
	}
	return chain, err
}

func (a *Authority) renewContext(ctx context.Context, oldCert *x509.Certificate, pk crypto.PublicKey) ([]*x509.Certificate, provisioner.Interface, error) {
	isRekey := (pk != nil)
	opts := []errs.Option{
		errs.WithKeyVal("serialNumber", oldCert.SerialNumber.String()),
	}

	// Check step provisioner extensions
	prov, err := a.authorizeRenew(ctx, oldCert)
	if err != nil {
		return nil, prov, errs.StatusCodeError(http.StatusInternalServerError, err, opts...)
	}

	// Durations
	backdate := a.config.AuthorityConfig.Backdate.Duration
	duration := oldCert.NotAfter.Sub(oldCert.NotBefore)
	lifetime := duration - backdate

	// Create new certificate from previous values.
	// Issuer, NotBefore, NotAfter and SubjectKeyId will be set by the CAS.
	newCert := &x509.Certificate{
		RawSubject:                  oldCert.RawSubject,
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

	if isRekey {
		newCert.PublicKey = pk
	} else {
		newCert.PublicKey = oldCert.PublicKey
	}

	// Copy all extensions except:
	//
	//  1. Authority Key Identifier - This one might be different if we rotate
	//  the intermediate certificate and it will cause a TLS bad certificate
	//  error.
	//
	//  2. Subject Key Identifier, if rekey - For rekey, SubjectKeyIdentifier
	//  extension will be calculated for the new public key by
	//  x509util.CreateCertificate()
	for _, ext := range oldCert.Extensions {
		if ext.Id.Equal(oidAuthorityKeyIdentifier) {
			continue
		}
		if ext.Id.Equal(oidSubjectKeyIdentifier) && isRekey {
			newCert.SubjectKeyId = nil
			continue
		}
		newCert.ExtraExtensions = append(newCert.ExtraExtensions, ext)
	}

	// Check if the certificate is allowed to be renewed, name constraints might
	// change over time.
	//
	// TODO(hslatman,maraino): consider adding policies too and consider if
	// RenewSSH should check policies.
	if err = a.constraintsEngine.ValidateCertificate(newCert); err != nil {
		var ee *errs.Error
		switch {
		case errors.As(err, &ee):
			return nil, prov, errs.StatusCodeError(ee.StatusCode(), err, opts...)
		default:
			return nil, prov, errs.InternalServerErr(err,
				errs.WithKeyVal("serialNumber", oldCert.SerialNumber.String()),
				errs.WithMessage("error renewing certificate"),
			)
		}
	}

	// The token can optionally be in the context. If the CA is running in RA
	// mode, this can be used to renew a certificate.
	token, _ := TokenFromContext(ctx)

	resp, err := a.x509CAService.RenewCertificate(&casapi.RenewCertificateRequest{
		Template: newCert,
		Lifetime: lifetime,
		Backdate: backdate,
		Token:    token,
	})
	if err != nil {
		return nil, prov, errs.StatusCodeError(http.StatusInternalServerError, err, opts...)
	}

	chain := append([]*x509.Certificate{resp.Certificate}, resp.CertificateChain...)

	if err = a.storeRenewedCertificate(oldCert, chain); err != nil && !errors.Is(err, db.ErrNotImplemented) {
		return nil, prov, errs.StatusCodeError(http.StatusInternalServerError, err, opts...)
	}

	return chain, prov, nil
}

// storeCertificate allows to use an extension of the db.AuthDB interface that
// can log the full chain of certificates.
//
// TODO: at some point we should replace the db.AuthDB interface to implement
// `StoreCertificate(...*x509.Certificate) error` instead of just
// `StoreCertificate(*x509.Certificate) error`.
func (a *Authority) storeCertificate(prov provisioner.Interface, fullchain []*x509.Certificate) error {
	type certificateChainStorer interface {
		StoreCertificateChain(provisioner.Interface, ...*x509.Certificate) error
	}
	type certificateChainSimpleStorer interface {
		StoreCertificateChain(...*x509.Certificate) error
	}

	// Store certificate in linkedca
	switch s := a.adminDB.(type) {
	case certificateChainStorer:
		return s.StoreCertificateChain(prov, fullchain...)
	case certificateChainSimpleStorer:
		return s.StoreCertificateChain(fullchain...)
	}

	// Store certificate in local db
	switch s := a.db.(type) {
	case certificateChainStorer:
		return s.StoreCertificateChain(prov, fullchain...)
	case certificateChainSimpleStorer:
		return s.StoreCertificateChain(fullchain...)
	case db.CertificateStorer:
		return s.StoreCertificate(fullchain[0])
	default:
		return nil
	}
}

// storeRenewedCertificate allows to use an extension of the db.AuthDB interface
// that can log if a certificate has been renewed or rekeyed.
//
// TODO: at some point we should implement this in the standard implementation.
func (a *Authority) storeRenewedCertificate(oldCert *x509.Certificate, fullchain []*x509.Certificate) error {
	type renewedCertificateChainStorer interface {
		StoreRenewedCertificate(*x509.Certificate, ...*x509.Certificate) error
	}

	// Store certificate in linkedca
	if s, ok := a.adminDB.(renewedCertificateChainStorer); ok {
		return s.StoreRenewedCertificate(oldCert, fullchain...)
	}

	// Store certificate in local db
	switch s := a.db.(type) {
	case renewedCertificateChainStorer:
		return s.StoreRenewedCertificate(oldCert, fullchain...)
	case db.CertificateStorer:
		return s.StoreCertificate(fullchain[0])
	default:
		return nil
	}
}

// RevokeOptions are the options for the Revoke API.
type RevokeOptions struct {
	Serial      string
	Reason      string
	ReasonCode  int
	PassiveOnly bool
	MTLS        bool
	ACME        bool
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
		errs.WithKeyVal("ACME", revokeOpts.ACME),
		errs.WithKeyVal("context", provisioner.MethodFromContext(ctx).String()),
	}
	if revokeOpts.MTLS || revokeOpts.ACME {
		opts = append(opts, errs.WithKeyVal("certificate", base64.StdEncoding.EncodeToString(revokeOpts.Crt.Raw)))
	} else {
		opts = append(opts, errs.WithKeyVal("token", revokeOpts.OTT))
	}

	rci := &db.RevokedCertificateInfo{
		Serial:     revokeOpts.Serial,
		ReasonCode: revokeOpts.ReasonCode,
		Reason:     revokeOpts.Reason,
		MTLS:       revokeOpts.MTLS,
		ACME:       revokeOpts.ACME,
		RevokedAt:  time.Now().UTC(),
	}

	// For X509 CRLs attempt to get the expiration date of the certificate.
	if provisioner.MethodFromContext(ctx) == provisioner.RevokeMethod {
		if revokeOpts.Crt == nil {
			cert, err := a.db.GetCertificate(revokeOpts.Serial)
			if err == nil {
				rci.ExpiresAt = cert.NotAfter
			}
		} else {
			rci.ExpiresAt = revokeOpts.Crt.NotAfter
		}
	}

	// If not mTLS nor ACME, then get the TokenID of the token.
	if !(revokeOpts.MTLS || revokeOpts.ACME) {
		token, err := jose.ParseSigned(revokeOpts.OTT)
		if err != nil {
			return errs.Wrap(http.StatusUnauthorized, err, "authority.Revoke; error parsing token", opts...)
		}

		// Get claims w/out verification.
		var claims Claims
		if err = token.UnsafeClaimsWithoutVerification(&claims); err != nil {
			return errs.Wrap(http.StatusUnauthorized, err, "authority.Revoke", opts...)
		}

		// This method will also validate the audiences for JWK provisioners.
		p, err := a.LoadProvisionerByToken(token, &claims.Claims)
		if err != nil {
			return err
		}
		rci.ProvisionerID = p.GetID()
		rci.TokenID, err = p.GetTokenID(revokeOpts.OTT)
		if err != nil && !errors.Is(err, provisioner.ErrAllowTokenReuse) {
			return errs.Wrap(http.StatusInternalServerError, err, "authority.Revoke; could not get ID for token")
		}
		opts = append(opts,
			errs.WithKeyVal("provisionerID", rci.ProvisionerID),
			errs.WithKeyVal("tokenID", rci.TokenID),
		)
	} else if p, err := a.LoadProvisionerByCertificate(revokeOpts.Crt); err == nil {
		// Load the Certificate provisioner if one exists.
		rci.ProvisionerID = p.GetID()
		opts = append(opts, errs.WithKeyVal("provisionerID", rci.ProvisionerID))
	}

	failRevoke := func(err error) error {
		switch {
		case errors.Is(err, db.ErrNotImplemented):
			return errs.NotImplemented("authority.Revoke; no persistence layer configured", opts...)
		case errors.Is(err, db.ErrAlreadyExists):
			return errs.ApplyOptions(
				errs.BadRequest("certificate with serial number '%s' is already revoked", rci.Serial),
				opts...,
			)
		default:
			return errs.Wrap(http.StatusInternalServerError, err, "authority.Revoke", opts...)
		}
	}

	if provisioner.MethodFromContext(ctx) == provisioner.SSHRevokeMethod {
		if err := a.revokeSSH(nil, rci); err != nil {
			return failRevoke(err)
		}
	} else {
		// Revoke an X.509 certificate using CAS. If the certificate is not
		// provided we will try to read it from the db. If the read fails we
		// won't throw an error as it will be responsibility of the CAS
		// implementation to require a certificate.
		var revokedCert *x509.Certificate
		if revokeOpts.Crt != nil {
			revokedCert = revokeOpts.Crt
		} else if rci.Serial != "" {
			revokedCert, _ = a.db.GetCertificate(rci.Serial)
		}

		// CAS operation, note that SoftCAS (default) is a noop.
		// The revoke happens when this is stored in the db.
		_, err := a.x509CAService.RevokeCertificate(&casapi.RevokeCertificateRequest{
			Certificate:  revokedCert,
			SerialNumber: rci.Serial,
			Reason:       rci.Reason,
			ReasonCode:   rci.ReasonCode,
			PassiveOnly:  revokeOpts.PassiveOnly,
		})
		if err != nil {
			return errs.Wrap(http.StatusInternalServerError, err, "authority.Revoke", opts...)
		}

		// Save as revoked in the Db.
		if err := a.revoke(revokedCert, rci); err != nil {
			return failRevoke(err)
		}

		// Generate a new CRL so CRL requesters will always get an up-to-date
		// CRL whenever they request it.
		if a.config.CRL.IsEnabled() && a.config.CRL.GenerateOnRevoke {
			if err := a.GenerateCertificateRevocationList(); err != nil {
				return errs.Wrap(http.StatusInternalServerError, err, "authority.Revoke", opts...)
			}
		}
	}

	return nil
}

func (a *Authority) revoke(crt *x509.Certificate, rci *db.RevokedCertificateInfo) error {
	if lca, ok := a.adminDB.(interface {
		Revoke(*x509.Certificate, *db.RevokedCertificateInfo) error
	}); ok {
		return lca.Revoke(crt, rci)
	}
	return a.db.Revoke(rci)
}

func (a *Authority) revokeSSH(crt *ssh.Certificate, rci *db.RevokedCertificateInfo) error {
	if lca, ok := a.adminDB.(interface {
		RevokeSSH(*ssh.Certificate, *db.RevokedCertificateInfo) error
	}); ok {
		return lca.RevokeSSH(crt, rci)
	}
	return a.db.RevokeSSH(rci)
}

// CertificateRevocationListInfo contains a CRL in DER format and associated metadata.
type CertificateRevocationListInfo struct {
	Number    int64
	ExpiresAt time.Time
	Duration  time.Duration
	Data      []byte
}

// GetCertificateRevocationList will return the currently generated CRL from the DB, or a not implemented
// error if the underlying AuthDB does not support CRLs
func (a *Authority) GetCertificateRevocationList() (*CertificateRevocationListInfo, error) {
	if !a.config.CRL.IsEnabled() {
		return nil, errs.Wrap(http.StatusNotFound, errors.Errorf("Certificate Revocation Lists are not enabled"), "authority.GetCertificateRevocationList")
	}

	crlDB, ok := a.db.(db.CertificateRevocationListDB)
	if !ok {
		return nil, errs.Wrap(http.StatusNotImplemented, errors.Errorf("Database does not support Certificate Revocation Lists"), "authority.GetCertificateRevocationList")
	}

	crlInfo, err := crlDB.GetCRL()
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.GetCertificateRevocationList")
	}

	return &CertificateRevocationListInfo{
		Number:    crlInfo.Number,
		ExpiresAt: crlInfo.ExpiresAt,
		Duration:  crlInfo.Duration,
		Data:      crlInfo.DER,
	}, nil
}

// GenerateCertificateRevocationList generates a DER representation of a signed CRL and stores it in the
// database. Returns nil if CRL generation has been disabled in the config
func (a *Authority) GenerateCertificateRevocationList() error {
	if !a.config.CRL.IsEnabled() {
		return nil
	}

	crlDB, ok := a.db.(db.CertificateRevocationListDB)
	if !ok {
		return errors.Errorf("Database does not support CRL generation")
	}

	// some CAS may not implement the CRLGenerator interface, so check before we proceed
	caCRLGenerator, ok := a.x509CAService.(casapi.CertificateAuthorityCRLGenerator)
	if !ok {
		return errors.Errorf("CA does not support CRL Generation")
	}

	// use a mutex to ensure only one CRL is generated at a time to avoid
	// concurrency issues
	a.crlMutex.Lock()
	defer a.crlMutex.Unlock()

	crlInfo, err := crlDB.GetCRL()
	if err != nil && !database.IsErrNotFound(err) {
		return errors.Wrap(err, "could not retrieve CRL from database")
	}

	now := time.Now().Truncate(time.Second).UTC()
	revokedList, err := crlDB.GetRevokedCertificates()
	if err != nil {
		return errors.Wrap(err, "could not retrieve revoked certificates list from database")
	}

	// Number is a monotonically increasing integer (essentially the CRL version
	// number) that we need to keep track of and increase every time we generate
	// a new CRL
	var bn big.Int
	if crlInfo != nil {
		bn.SetInt64(crlInfo.Number + 1)
	}

	// Convert our database db.RevokedCertificateInfo types into the pkix
	// representation ready for the CAS to sign it
	var revokedCertificates []pkix.RevokedCertificate
	skipExpiredTime := now.Add(-config.DefaultCRLExpiredDuration)
	for _, revokedCert := range *revokedList {
		// skip expired certificates
		if !revokedCert.ExpiresAt.IsZero() && revokedCert.ExpiresAt.Before(skipExpiredTime) {
			continue
		}

		var sn big.Int
		sn.SetString(revokedCert.Serial, 10)
		revokedCertificates = append(revokedCertificates, pkix.RevokedCertificate{
			SerialNumber:   &sn,
			RevocationTime: revokedCert.RevokedAt,
			Extensions:     nil,
		})
	}

	var updateDuration time.Duration
	if a.config.CRL.CacheDuration != nil {
		updateDuration = a.config.CRL.CacheDuration.Duration
	} else if crlInfo != nil {
		updateDuration = crlInfo.Duration
	}

	// Create a RevocationList representation ready for the CAS to sign
	// TODO: allow SignatureAlgorithm to be specified?
	revocationList := x509.RevocationList{
		SignatureAlgorithm:  0,
		RevokedCertificates: revokedCertificates,
		Number:              &bn,
		ThisUpdate:          now,
		NextUpdate:          now.Add(updateDuration),
	}

	// Set CRL IDP to config item, otherwise, leave as default
	var fullName string
	if a.config.CRL.IDPurl != "" {
		fullName = a.config.CRL.IDPurl
	} else {
		fullName = a.config.Audience("/1.0/crl")[0]
	}

	// Add distribution point.
	//
	// Note that this is currently using the port 443 by default.
	if b, err := marshalDistributionPoint(fullName, false); err == nil {
		revocationList.ExtraExtensions = []pkix.Extension{
			{Id: oidExtensionIssuingDistributionPoint, Critical: true, Value: b},
		}
	}

	certificateRevocationList, err := caCRLGenerator.CreateCRL(&casapi.CreateCRLRequest{RevocationList: &revocationList})
	if err != nil {
		return errors.Wrap(err, "could not create CRL")
	}

	// Create a new db.CertificateRevocationListInfo, which stores the new Number we just generated, the
	// expiry time, duration, and the DER-encoded CRL
	newCRLInfo := db.CertificateRevocationListInfo{
		Number:    bn.Int64(),
		ExpiresAt: revocationList.NextUpdate,
		DER:       certificateRevocationList.CRL,
		Duration:  updateDuration,
	}

	// Store the CRL in the database ready for retrieval by api endpoints
	err = crlDB.StoreCRL(&newCRLInfo)
	if err != nil {
		return errors.Wrap(err, "could not store CRL in database")
	}

	return nil
}

// GetTLSCertificate creates a new leaf certificate to be used by the CA HTTPS server.
func (a *Authority) GetTLSCertificate() (*tls.Certificate, error) {
	fatal := func(err error) (*tls.Certificate, error) {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.GetTLSCertificate")
	}

	// Generate default key.
	priv, err := keyutil.GenerateDefaultKey()
	if err != nil {
		return fatal(err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return fatal(errors.New("private key is not a crypto.Signer"))
	}

	// prepare the sans: IPv6 DNS hostname representations are converted to their IP representation
	sans := make([]string, len(a.config.DNSNames))
	for i, san := range a.config.DNSNames {
		if strings.HasPrefix(san, "[") && strings.HasSuffix(san, "]") {
			if ip := net.ParseIP(san[1 : len(san)-1]); ip != nil {
				san = ip.String()
			}
		}
		sans[i] = san
	}

	// Create initial certificate request.
	cr, err := x509util.CreateCertificateRequest(a.config.CommonName, sans, signer)
	if err != nil {
		return fatal(err)
	}

	// Generate certificate template directly from the certificate request.
	template, err := x509util.NewCertificate(cr)
	if err != nil {
		return fatal(err)
	}

	// Get x509 certificate template, set validity and sign it.
	now := time.Now()
	certTpl := template.GetCertificate()
	certTpl.NotBefore = now.Add(-1 * time.Minute)
	certTpl.NotAfter = now.Add(24 * time.Hour)

	// Policy and constraints require this fields to be set. At this moment they
	// are only present in the extra extension.
	certTpl.DNSNames = cr.DNSNames
	certTpl.IPAddresses = cr.IPAddresses
	certTpl.EmailAddresses = cr.EmailAddresses
	certTpl.URIs = cr.URIs

	// Fail if name constraints do not allow the server names.
	if err := a.constraintsEngine.ValidateCertificate(certTpl); err != nil {
		return fatal(err)
	}

	// Set the cert lifetime as follows:
	//   i) If the CA is not a StepCAS RA use 24h, else
	//  ii) if the CA is a StepCAS RA, leave the lifetime empty and
	//      let the provisioner of the CA decide the lifetime of the RA cert.
	var lifetime time.Duration
	if casapi.TypeOf(a.x509CAService) != casapi.StepCAS {
		lifetime = 24 * time.Hour
	}

	resp, err := a.x509CAService.CreateCertificate(&casapi.CreateCertificateRequest{
		Template:       certTpl,
		CSR:            cr,
		Lifetime:       lifetime,
		Backdate:       1 * time.Minute,
		IsCAServerCert: true,
	})
	if err != nil {
		return fatal(err)
	}

	// Generate PEM blocks to create tls.Certificate
	pemBlocks := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: resp.Certificate.Raw,
	})
	for _, crt := range resp.CertificateChain {
		pemBlocks = append(pemBlocks, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		})...)
	}
	keyPEM, err := pemutil.Serialize(priv)
	if err != nil {
		return fatal(err)
	}

	tlsCrt, err := tls.X509KeyPair(pemBlocks, pem.EncodeToMemory(keyPEM))
	if err != nil {
		return fatal(err)
	}
	// Set leaf certificate
	tlsCrt.Leaf = resp.Certificate
	return &tlsCrt, nil
}

// RFC 5280, 5.2.5
type distributionPoint struct {
	DistributionPoint          distributionPointName `asn1:"optional,tag:0"`
	OnlyContainsUserCerts      bool                  `asn1:"optional,tag:1"`
	OnlyContainsCACerts        bool                  `asn1:"optional,tag:2"`
	OnlySomeReasons            asn1.BitString        `asn1:"optional,tag:3"`
	IndirectCRL                bool                  `asn1:"optional,tag:4"`
	OnlyContainsAttributeCerts bool                  `asn1:"optional,tag:5"`
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

func marshalDistributionPoint(fullName string, isCA bool) ([]byte, error) {
	return asn1.Marshal(distributionPoint{
		DistributionPoint: distributionPointName{
			FullName: []asn1.RawValue{
				{Class: 2, Tag: 6, Bytes: []byte(fullName)},
			},
		},
		OnlyContainsUserCerts: !isCA,
		OnlyContainsCACerts:   isCA,
	})
}

// templatingError tries to extract more information about the cause of
// an error related to (most probably) malformed template data and adds
// this to the error message.
func templatingError(err error) error {
	cause := errors.Cause(err)
	var (
		syntaxError *json.SyntaxError
		typeError   *json.UnmarshalTypeError
	)
	if errors.As(err, &syntaxError) {
		// offset is arguably not super clear to the user, but it's the best we can do here
		cause = fmt.Errorf("%w at offset %d", cause, syntaxError.Offset)
	} else if errors.As(err, &typeError) {
		// slightly rewriting the default error message to include the offset
		cause = fmt.Errorf("cannot unmarshal %s at offset %d into Go value of type %s", typeError.Value, typeError.Offset, typeError.Type)
	}
	return errors.Wrap(cause, "error applying certificate template")
}

func (a *Authority) callEnrichingWebhooksX509(ctx context.Context, prov provisioner.Interface, webhookCtl webhookController, attData *provisioner.AttestationData, csr *x509.CertificateRequest) (err error) {
	if webhookCtl == nil {
		return
	}
	defer func() { a.meter.X509WebhookEnriched(prov, err) }()

	var attested *webhook.AttestationData
	if attData != nil {
		attested = &webhook.AttestationData{
			PermanentIdentifier: attData.PermanentIdentifier,
		}
	}

	var whEnrichReq *webhook.RequestBody
	if whEnrichReq, err = webhook.NewRequestBody(
		webhook.WithX509CertificateRequest(csr),
		webhook.WithAttestationData(attested),
	); err == nil {
		err = webhookCtl.Enrich(ctx, whEnrichReq)
	}

	return
}

func (a *Authority) callAuthorizingWebhooksX509(ctx context.Context, prov provisioner.Interface, webhookCtl webhookController, cert *x509util.Certificate, leaf *x509.Certificate, attData *provisioner.AttestationData) (err error) {
	if webhookCtl == nil {
		return
	}
	defer func() { a.meter.X509WebhookAuthorized(prov, err) }()

	var attested *webhook.AttestationData
	if attData != nil {
		attested = &webhook.AttestationData{
			PermanentIdentifier: attData.PermanentIdentifier,
		}
	}

	var whAuthBody *webhook.RequestBody
	if whAuthBody, err = webhook.NewRequestBody(
		webhook.WithX509Certificate(cert, leaf),
		webhook.WithAttestationData(attested),
	); err == nil {
		err = webhookCtl.Authorize(ctx, whAuthBody)
	}

	return
}
