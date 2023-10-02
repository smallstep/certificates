package scep

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	microx509util "github.com/micromdm/scep/v2/cryptoutil/x509util"
	microscep "github.com/micromdm/scep/v2/scep"
	"go.mozilla.org/pkcs7"

	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/authority/provisioner"
)

// Authority is the layer that handles all SCEP interactions.
type Authority struct {
	signAuth             SignAuthority
	roots                []*x509.Certificate
	intermediates        []*x509.Certificate
	defaultSigner        crypto.Signer
	signerCertificate    *x509.Certificate
	defaultDecrypter     crypto.Decrypter
	decrypterCertificate *x509.Certificate
	scepProvisionerNames []string

	provisionersMutex        sync.RWMutex
	encryptionAlgorithmMutex sync.Mutex
}

type authorityKey struct{}

// NewContext adds the given authority to the context.
func NewContext(ctx context.Context, a *Authority) context.Context {
	return context.WithValue(ctx, authorityKey{}, a)
}

// FromContext returns the current authority from the given context.
func FromContext(ctx context.Context) (a *Authority, ok bool) {
	a, ok = ctx.Value(authorityKey{}).(*Authority)
	return
}

// MustFromContext returns the current authority from the given context. It will
// panic if the authority is not in the context.
func MustFromContext(ctx context.Context) *Authority {
	if a, ok := FromContext(ctx); !ok {
		panic("scep authority is not in the context")
	} else {
		return a
	}
}

// SignAuthority is the interface for a signing authority
type SignAuthority interface {
	Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	LoadProvisionerByName(string) (provisioner.Interface, error)
}

// New returns a new Authority that implements the SCEP interface.
func New(signAuth SignAuthority, opts Options) (*Authority, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	return &Authority{
		signAuth:             signAuth, // TODO: provide signAuth through context instead?
		roots:                opts.Roots,
		intermediates:        opts.Intermediates,
		defaultSigner:        opts.Signer,
		signerCertificate:    opts.SignerCert,
		defaultDecrypter:     opts.Decrypter,
		decrypterCertificate: opts.SignerCert, // the intermediate signer cert is also the decrypter cert (if RSA)
		scepProvisionerNames: opts.SCEPProvisionerNames,
	}, nil
}

// Validate validates if the SCEP Authority has a valid configuration.
// The validation includes a check if a decrypter is available, either
// an authority wide decrypter, or a provisioner specific decrypter.
func (a *Authority) Validate() error {
	if a == nil {
		return nil
	}

	a.provisionersMutex.RLock()
	defer a.provisionersMutex.RUnlock()

	noDefaultDecrypterAvailable := a.defaultDecrypter == nil
	for _, name := range a.scepProvisionerNames {
		p, err := a.LoadProvisionerByName(name)
		if err != nil {
			return fmt.Errorf("failed loading provisioner %q: %w", name, err)
		}
		if scepProv, ok := p.(*provisioner.SCEP); ok {
			cert, decrypter := scepProv.GetDecrypter()
			// TODO(hs): return sentinel/typed error, to be able to ignore/log these cases during init?
			if cert == nil && noDefaultDecrypterAvailable {
				return fmt.Errorf("SCEP provisioner %q does not have a decrypter certificate", name)
			}
			if decrypter == nil && noDefaultDecrypterAvailable {
				return fmt.Errorf("SCEP provisioner %q does not have decrypter", name)
			}
		}
	}

	return nil
}

// UpdateProvisioners updates the SCEP Authority with the new, and hopefully
// current SCEP provisioners configured. This allows the Authority to be
// validated with the latest data.
func (a *Authority) UpdateProvisioners(scepProvisionerNames []string) {
	if a == nil {
		return
	}

	a.provisionersMutex.Lock()
	defer a.provisionersMutex.Unlock()

	a.scepProvisionerNames = scepProvisionerNames
}

var (
	// TODO: check the default capabilities; https://tools.ietf.org/html/rfc8894#section-3.5.2
	defaultCapabilities = []string{
		"Renewal", // NOTE: removing this will result in macOS SCEP client stating the server doesn't support renewal, but it uses PKCSreq to do so.
		"SHA-1",
		"SHA-256",
		"AES",
		"DES3",
		"SCEPStandard",
		"POSTPKIOperation",
	}
)

// LoadProvisionerByName calls out to the SignAuthority interface to load a
// provisioner by name.
func (a *Authority) LoadProvisionerByName(name string) (provisioner.Interface, error) {
	return a.signAuth.LoadProvisionerByName(name)
}

// GetCACertificates returns the certificate (chain) for the CA.
//
// This methods returns the "SCEP Server (RA)" certificate, the issuing CA up to and excl. the root.
// Some clients do need the root certificate however; also see: https://github.com/openxpki/openxpki/issues/73
//
// In case a provisioner specific decrypter is available, this is used as the "SCEP Server (RA)" certificate
// instead of the CA intermediate directly. This uses a distinct instance of a KMS for doing the SCEP key
// operations, so that RSA can be used for just SCEP.
//
// Using an RA does not seem to exist in https://tools.ietf.org/html/rfc8894, but is mentioned in
// https://tools.ietf.org/id/draft-nourse-scep-21.html.
func (a *Authority) GetCACertificates(ctx context.Context) (certs []*x509.Certificate, err error) {
	p := provisionerFromContext(ctx)

	// if a provisioner specific RSA decrypter is available, it is returned as
	// the first certificate.
	if decrypterCertificate, _ := p.GetDecrypter(); decrypterCertificate != nil {
		certs = append(certs, decrypterCertificate)
	}

	// the CA intermediate is added to the chain by default. It's possible to
	// exclude it from being added through configuration. This can be useful in
	// environments where the SCEP client doesn't select the right RSA decrypter
	// certificate, resulting in the wrong recipient in the PKCS7 message.
	if p.ShouldIncludeIntermediateInChain() || len(certs) == 0 {
		// TODO(hs): ensure logic is in place that checks the signer is the first
		// intermediate and that there are no double certificates.
		certs = append(certs, a.intermediates...)
	}

	// the CA roots are added for completeness when configured to do so. Clients
	// are responsible to select the right cert(s) to store and use.
	if p.ShouldIncludeRootInChain() {
		certs = append(certs, a.roots...)
	}

	return certs, nil
}

// DecryptPKIEnvelope decrypts an enveloped message
func (a *Authority) DecryptPKIEnvelope(ctx context.Context, msg *PKIMessage) error {
	p7c, err := pkcs7.Parse(msg.P7.Content)
	if err != nil {
		return fmt.Errorf("error parsing pkcs7 content: %w", err)
	}

	cert, decrypter, err := a.selectDecrypter(ctx)
	if err != nil {
		return fmt.Errorf("failed selecting decrypter: %w", err)
	}

	envelope, err := p7c.Decrypt(cert, decrypter)
	if err != nil {
		return fmt.Errorf("error decrypting encrypted pkcs7 content: %w", err)
	}

	msg.pkiEnvelope = envelope

	switch msg.MessageType {
	case microscep.CertRep:
		certs, err := microscep.CACerts(msg.pkiEnvelope)
		if err != nil {
			return fmt.Errorf("error extracting CA certs from pkcs7 degenerate data: %w", err)
		}
		msg.CertRepMessage.Certificate = certs[0]
		return nil
	case microscep.PKCSReq, microscep.UpdateReq, microscep.RenewalReq:
		csr, err := x509.ParseCertificateRequest(msg.pkiEnvelope)
		if err != nil {
			return fmt.Errorf("parse CSR from pkiEnvelope: %w", err)
		}
		if err := csr.CheckSignature(); err != nil {
			return fmt.Errorf("invalid CSR signature; %w", err)
		}
		// extract the challenge password
		cp, err := microx509util.ParseChallengePassword(msg.pkiEnvelope)
		if err != nil {
			return fmt.Errorf("parse challenge password in pkiEnvelope: %w", err)
		}
		msg.CSRReqMessage = &microscep.CSRReqMessage{
			RawDecrypted:      msg.pkiEnvelope,
			CSR:               csr,
			ChallengePassword: cp,
		}
		return nil
	case microscep.GetCRL, microscep.GetCert, microscep.CertPoll:
		return errors.New("not implemented")
	}

	return nil
}

// SignCSR creates an x509.Certificate based on a CSR template and Cert Authority credentials
// returns a new PKIMessage with CertRep data
func (a *Authority) SignCSR(ctx context.Context, csr *x509.CertificateRequest, msg *PKIMessage) (*PKIMessage, error) {
	// TODO: intermediate storage of the request? In SCEP it's possible to request a csr/certificate
	// to be signed, which can be performed asynchronously / out-of-band. In that case a client can
	// poll for the status. It seems to be similar as what can happen in ACME, so might want to model
	// the implementation after the one in the ACME authority. Requires storage, etc.

	p := provisionerFromContext(ctx)

	// check if CSRReqMessage has already been decrypted
	if msg.CSRReqMessage.CSR == nil {
		if err := a.DecryptPKIEnvelope(ctx, msg); err != nil {
			return nil, err
		}
		csr = msg.CSRReqMessage.CSR
	}

	// Template data
	sans := []string{}
	sans = append(sans, csr.DNSNames...)
	sans = append(sans, csr.EmailAddresses...)
	for _, v := range csr.IPAddresses {
		sans = append(sans, v.String())
	}
	for _, v := range csr.URIs {
		sans = append(sans, v.String())
	}
	if len(sans) == 0 {
		sans = append(sans, csr.Subject.CommonName)
	}
	data := x509util.CreateTemplateData(csr.Subject.CommonName, sans)
	data.SetCertificateRequest(csr)
	data.SetSubject(x509util.Subject{
		Country:            csr.Subject.Country,
		Organization:       csr.Subject.Organization,
		OrganizationalUnit: csr.Subject.OrganizationalUnit,
		Locality:           csr.Subject.Locality,
		Province:           csr.Subject.Province,
		StreetAddress:      csr.Subject.StreetAddress,
		PostalCode:         csr.Subject.PostalCode,
		SerialNumber:       csr.Subject.SerialNumber,
		CommonName:         csr.Subject.CommonName,
	})

	// Get authorizations from the SCEP provisioner.
	ctx = provisioner.NewContextWithMethod(ctx, provisioner.SignMethod)
	signOps, err := p.AuthorizeSign(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("error retrieving authorization options from SCEP provisioner: %w", err)
	}
	// Unlike most of the provisioners, scep's AuthorizeSign method doesn't
	// define the templates, and the template data used in WebHooks is not
	// available.
	for _, signOp := range signOps {
		if wc, ok := signOp.(*provisioner.WebhookController); ok {
			wc.TemplateData = data
		}
	}

	opts := provisioner.SignOptions{}
	templateOptions, err := provisioner.TemplateOptions(p.GetOptions(), data)
	if err != nil {
		return nil, fmt.Errorf("error creating template options from SCEP provisioner: %w", err)
	}
	signOps = append(signOps, templateOptions)

	certChain, err := a.signAuth.Sign(csr, opts, signOps...)
	if err != nil {
		return nil, fmt.Errorf("error generating certificate for order: %w", err)
	}

	// take the issued certificate (only); https://tools.ietf.org/html/rfc8894#section-3.3.2
	cert := certChain[0]

	// and create a degenerate cert structure
	deg, err := microscep.DegenerateCertificates([]*x509.Certificate{cert})
	if err != nil {
		return nil, fmt.Errorf("failed generating degenerate certificate: %w", err)
	}

	e7, err := a.encrypt(deg, msg.P7.Certificates, p.GetContentEncryptionAlgorithm())
	if err != nil {
		return nil, fmt.Errorf("failed encrypting degenerate certificate: %w", err)
	}

	// PKIMessageAttributes to be signed
	config := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{
				Type:  oidSCEPtransactionID,
				Value: msg.TransactionID,
			},
			{
				Type:  oidSCEPpkiStatus,
				Value: microscep.SUCCESS,
			},
			{
				Type:  oidSCEPmessageType,
				Value: microscep.CertRep,
			},
			{
				Type:  oidSCEPrecipientNonce,
				Value: msg.SenderNonce,
			},
			{
				Type:  oidSCEPsenderNonce,
				Value: msg.SenderNonce,
			},
		},
	}

	signedData, err := pkcs7.NewSignedData(e7)
	if err != nil {
		return nil, err
	}

	// add the certificate into the signed data type
	// this cert must be added before the signedData because the recipient will expect it
	// as the first certificate in the array
	signedData.AddCertificate(cert)

	signerCert, signer, err := a.selectSigner(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed selecting signer: %w", err)
	}

	// sign the attributes
	if err := signedData.AddSigner(signerCert, signer, config); err != nil {
		return nil, err
	}

	certRepBytes, err := signedData.Finish()
	if err != nil {
		return nil, err
	}

	cr := &CertRepMessage{
		PKIStatus:      microscep.SUCCESS,
		RecipientNonce: microscep.RecipientNonce(msg.SenderNonce),
		Certificate:    cert,
		degenerate:     deg,
	}

	// create a CertRep message from the original
	crepMsg := &PKIMessage{
		Raw:            certRepBytes,
		TransactionID:  msg.TransactionID,
		MessageType:    microscep.CertRep,
		CertRepMessage: cr,
	}

	return crepMsg, nil
}

func (a *Authority) encrypt(content []byte, recipients []*x509.Certificate, algorithm int) ([]byte, error) {
	// apparently the pkcs7 library uses a global default setting for the content encryption
	// algorithm to use when en- or decrypting data. We need to restore the current setting after
	// the cryptographic operation, so that other usages of the library are not influenced by
	// this call to Encrypt(). We are not required to use the same algorithm the SCEP client uses.
	a.encryptionAlgorithmMutex.Lock()
	defer a.encryptionAlgorithmMutex.Unlock()

	encryptionAlgorithmToRestore := pkcs7.ContentEncryptionAlgorithm
	defer func() {
		pkcs7.ContentEncryptionAlgorithm = encryptionAlgorithmToRestore
	}()

	pkcs7.ContentEncryptionAlgorithm = algorithm
	e7, err := pkcs7.Encrypt(content, recipients)
	if err != nil {
		return nil, err
	}

	return e7, nil
}

// CreateFailureResponse creates an appropriately signed reply for PKI operations
func (a *Authority) CreateFailureResponse(ctx context.Context, _ *x509.CertificateRequest, msg *PKIMessage, info FailInfoName, infoText string) (*PKIMessage, error) {
	config := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{
				Type:  oidSCEPtransactionID,
				Value: msg.TransactionID,
			},
			{
				Type:  oidSCEPpkiStatus,
				Value: microscep.FAILURE,
			},
			{
				Type:  oidSCEPfailInfo,
				Value: info,
			},
			{
				Type:  oidSCEPfailInfoText,
				Value: infoText,
			},
			{
				Type:  oidSCEPmessageType,
				Value: microscep.CertRep,
			},
			{
				Type:  oidSCEPsenderNonce,
				Value: msg.SenderNonce,
			},
			{
				Type:  oidSCEPrecipientNonce,
				Value: msg.SenderNonce,
			},
		},
	}

	signedData, err := pkcs7.NewSignedData(nil)
	if err != nil {
		return nil, err
	}

	signerCert, signer, err := a.selectSigner(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed selecting signer: %w", err)
	}

	// sign the attributes
	if err := signedData.AddSigner(signerCert, signer, config); err != nil {
		return nil, err
	}

	certRepBytes, err := signedData.Finish()
	if err != nil {
		return nil, err
	}

	cr := &CertRepMessage{
		PKIStatus:      microscep.FAILURE,
		FailInfo:       microscep.FailInfo(info),
		RecipientNonce: microscep.RecipientNonce(msg.SenderNonce),
	}

	// create a CertRep message from the original
	crepMsg := &PKIMessage{
		Raw:            certRepBytes,
		TransactionID:  msg.TransactionID,
		MessageType:    microscep.CertRep,
		CertRepMessage: cr,
	}

	return crepMsg, nil
}

// GetCACaps returns the CA capabilities
func (a *Authority) GetCACaps(ctx context.Context) []string {
	p := provisionerFromContext(ctx)

	caps := p.GetCapabilities()
	if len(caps) == 0 {
		return defaultCapabilities
	}

	// TODO: validate the caps? Ensure they are the right format according to RFC?
	// TODO: ensure that the capabilities are actually "enforced"/"verified" in code too:
	// check that only parts of the spec are used in the implementation belonging to the capabilities.
	// For example for renewals, which we could disable in the provisioner, should then also
	// not be reported in cacaps operation.

	return caps
}

func (a *Authority) ValidateChallenge(ctx context.Context, csr *x509.CertificateRequest, challenge, transactionID string) error {
	p := provisionerFromContext(ctx)
	return p.ValidateChallenge(ctx, csr, challenge, transactionID)
}

func (a *Authority) NotifySuccess(ctx context.Context, csr *x509.CertificateRequest, cert *x509.Certificate, transactionID string) error {
	p := provisionerFromContext(ctx)
	return p.NotifySuccess(ctx, csr, cert, transactionID)
}

func (a *Authority) NotifyFailure(ctx context.Context, csr *x509.CertificateRequest, transactionID string, errorCode int, errorDescription string) error {
	p := provisionerFromContext(ctx)
	return p.NotifyFailure(ctx, csr, transactionID, errorCode, errorDescription)
}

func (a *Authority) selectDecrypter(ctx context.Context) (cert *x509.Certificate, decrypter crypto.Decrypter, err error) {
	p := provisionerFromContext(ctx)
	cert, decrypter = p.GetDecrypter()
	switch {
	case cert != nil && decrypter != nil:
		return
	case cert == nil && decrypter != nil:
		return nil, nil, fmt.Errorf("provisioner %q does not have a decrypter certificate available", p.GetName())
	case cert != nil && decrypter == nil:
		return nil, nil, fmt.Errorf("provisioner %q does not have a decrypter available", p.GetName())
	}

	cert, decrypter = a.decrypterCertificate, a.defaultDecrypter
	switch {
	case cert == nil && decrypter != nil:
		return nil, nil, fmt.Errorf("provisioner %q does not have a default decrypter certificate available", p.GetName())
	case cert != nil && decrypter == nil:
		return nil, nil, fmt.Errorf("provisioner %q does not have a default decrypter available", p.GetName())
	}

	return
}

func (a *Authority) selectSigner(ctx context.Context) (cert *x509.Certificate, signer crypto.Signer, err error) {
	p := provisionerFromContext(ctx)
	cert, signer = p.GetSigner()
	switch {
	case cert != nil && signer != nil:
		return
	case cert == nil && signer != nil:
		return nil, nil, fmt.Errorf("provisioner %q does not have a signer certificate available", p.GetName())
	case cert != nil && signer == nil:
		return nil, nil, fmt.Errorf("provisioner %q does not have a signer available", p.GetName())
	}

	cert, signer = a.signerCertificate, a.defaultSigner
	switch {
	case cert == nil && signer != nil:
		return nil, nil, fmt.Errorf("provisioner %q does not have a default signer certificate available", p.GetName())
	case cert != nil && signer == nil:
		return nil, nil, fmt.Errorf("provisioner %q does not have a default signer available", p.GetName())
	}

	return
}
