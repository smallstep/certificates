package scep

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"

	microx509util "github.com/micromdm/scep/v2/cryptoutil/x509util"
	microscep "github.com/micromdm/scep/v2/scep"
	"go.mozilla.org/pkcs7"

	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/authority/provisioner"
)

// Authority is the layer that handles all SCEP interactions.
type Authority struct {
	prefix                  string
	dns                     string
	intermediateCertificate *x509.Certificate
	caCerts                 []*x509.Certificate // TODO(hs): change to use these instead of root and intermediate
	service                 *Service
	signAuth                SignAuthority
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

// AuthorityOptions required to create a new SCEP Authority.
type AuthorityOptions struct {
	// Service provides the certificate chain, the signer and the decrypter to the Authority
	Service *Service
	// DNS is the host used to generate accurate SCEP links. By default the authority
	// will use the Host from the request, so this value will only be used if
	// request.Host is empty.
	DNS string
	// Prefix is a URL path prefix under which the SCEP api is served. This
	// prefix is required to generate accurate SCEP links.
	Prefix string
}

// SignAuthority is the interface for a signing authority
type SignAuthority interface {
	Sign(cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	LoadProvisionerByName(string) (provisioner.Interface, error)
}

// New returns a new Authority that implements the SCEP interface.
func New(signAuth SignAuthority, ops AuthorityOptions) (*Authority, error) {
	authority := &Authority{
		prefix:   ops.Prefix,
		dns:      ops.DNS,
		signAuth: signAuth,
	}

	// TODO: this is not really nice to do; the Service should be removed
	// in its entirety to make this more interoperable with the rest of
	// step-ca, I think.
	if ops.Service != nil {
		authority.caCerts = ops.Service.certificateChain
		// TODO(hs): look into refactoring SCEP into using just caCerts everywhere, if it makes sense for more elaborate SCEP configuration. Keeping it like this for clarity (for now).
		authority.intermediateCertificate = ops.Service.certificateChain[0]
		authority.service = ops.Service
	}

	return authority, nil
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

// GetLinkExplicit returns the requested link from the directory.
func (a *Authority) GetLinkExplicit(provName string, abs bool, baseURL *url.URL, inputs ...string) string {
	return a.getLinkExplicit(provName, abs, baseURL, inputs...)
}

// getLinkExplicit returns an absolute or partial path to the given resource and a base
// URL dynamically obtained from the request for which the link is being calculated.
func (a *Authority) getLinkExplicit(provisionerName string, abs bool, baseURL *url.URL, inputs ...string) string {
	link := "/" + provisionerName
	if abs {
		// Copy the baseURL value from the pointer. https://github.com/golang/go/issues/38351
		u := url.URL{}
		if baseURL != nil {
			u = *baseURL
		}

		// If no Scheme is set, then default to http (in case of SCEP)
		if u.Scheme == "" {
			u.Scheme = "http"
		}

		// If no Host is set, then use the default (first DNS attr in the ca.json).
		if u.Host == "" {
			u.Host = a.dns
		}

		u.Path = a.prefix + link
		return u.String()
	}

	return link
}

// GetCACertificates returns the certificate (chain) for the CA
func (a *Authority) GetCACertificates(ctx context.Context) ([]*x509.Certificate, error) {
	// TODO: this should return: the "SCEP Server (RA)" certificate, the issuing CA up to and excl. the root
	// Some clients do need the root certificate however; also see: https://github.com/openxpki/openxpki/issues/73
	//
	// This means we might need to think about if we should use the current intermediate CA
	// certificate as the "SCEP Server (RA)" certificate. It might be better to have a distinct
	// RA certificate, with a corresponding rsa.PrivateKey, just for SCEP usage, which is signed by
	// the intermediate CA. Will need to look how we can provide this nicely within step-ca.
	//
	// This might also mean that we might want to use a distinct instance of KMS for doing the key operations,
	// so that we can use RSA just for SCEP.
	//
	// Using an RA does not seem to exist in https://tools.ietf.org/html/rfc8894, but is mentioned in
	// https://tools.ietf.org/id/draft-nourse-scep-21.html. Will continue using the CA directly for now.
	//
	// The certificate to use should probably depend on the (configured) provisioner and may
	// use a distinct certificate, apart from the intermediate.

	p, err := provisionerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if len(a.caCerts) == 0 {
		return nil, errors.New("no intermediate certificate available in SCEP authority")
	}

	certs := []*x509.Certificate{}
	certs = append(certs, a.caCerts[0])

	// NOTE: we're adding the CA roots here, but they are (highly likely) different than what the RFC means.
	// Clients are responsible to select the right cert(s) to use, though.
	if p.ShouldIncludeRootInChain() && len(a.caCerts) > 1 {
		certs = append(certs, a.caCerts[1])
	}

	return certs, nil
}

// DecryptPKIEnvelope decrypts an enveloped message
func (a *Authority) DecryptPKIEnvelope(ctx context.Context, msg *PKIMessage) error {
	p7c, err := pkcs7.Parse(msg.P7.Content)
	if err != nil {
		return fmt.Errorf("error parsing pkcs7 content: %w", err)
	}

	envelope, err := p7c.Decrypt(a.intermediateCertificate, a.service.decrypter)
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
		// check for challengePassword
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

	p, err := provisionerFromContext(ctx)
	if err != nil {
		return nil, err
	}

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
		return nil, err
	}

	// apparently the pkcs7 library uses a global default setting for the content encryption
	// algorithm to use when en- or decrypting data. We need to restore the current setting after
	// the cryptographic operation, so that other usages of the library are not influenced by
	// this call to Encrypt(). We are not required to use the same algorithm the SCEP client uses.
	encryptionAlgorithmToRestore := pkcs7.ContentEncryptionAlgorithm
	pkcs7.ContentEncryptionAlgorithm = p.GetContentEncryptionAlgorithm()
	e7, err := pkcs7.Encrypt(deg, msg.P7.Certificates)
	if err != nil {
		return nil, err
	}
	pkcs7.ContentEncryptionAlgorithm = encryptionAlgorithmToRestore

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

	authCert := a.intermediateCertificate

	// sign the attributes
	if err := signedData.AddSigner(authCert, a.service.signer, config); err != nil {
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

// CreateFailureResponse creates an appropriately signed reply for PKI operations
func (a *Authority) CreateFailureResponse(ctx context.Context, csr *x509.CertificateRequest, msg *PKIMessage, info FailInfoName, infoText string) (*PKIMessage, error) {
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

	// sign the attributes
	if err := signedData.AddSigner(a.intermediateCertificate, a.service.signer, config); err != nil {
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

// MatchChallengePassword verifies a SCEP challenge password
func (a *Authority) MatchChallengePassword(ctx context.Context, password string) (bool, error) {
	p, err := provisionerFromContext(ctx)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare([]byte(p.GetChallengePassword()), []byte(password)) == 1 {
		return true, nil
	}

	// TODO: support dynamic challenges, i.e. a list of challenges instead of one?
	// That's probably a bit harder to configure, though; likely requires some data store
	// that can be interacted with more easily, via some internal API, for example.

	return false, nil
}

// GetCACaps returns the CA capabilities
func (a *Authority) GetCACaps(ctx context.Context) []string {
	p, err := provisionerFromContext(ctx)
	if err != nil {
		return defaultCapabilities
	}

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
