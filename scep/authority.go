package scep

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/smallstep/certificates/authority/provisioner"
	database "github.com/smallstep/certificates/db"

	"go.step.sm/crypto/pemutil"

	"github.com/smallstep/nosql"

	microx509util "github.com/micromdm/scep/crypto/x509util"
	microscep "github.com/micromdm/scep/scep"

	//"github.com/smallstep/certificates/scep/pkcs7"

	"go.mozilla.org/pkcs7"

	"go.step.sm/crypto/x509util"
)

// Interface is the SCEP authority interface.
type Interface interface {
	// GetDirectory(ctx context.Context) (*Directory, error)
	// NewNonce() (string, error)
	// UseNonce(string) error

	// DeactivateAccount(ctx context.Context, accID string) (*Account, error)
	// GetAccount(ctx context.Context, accID string) (*Account, error)
	// GetAccountByKey(ctx context.Context, key *jose.JSONWebKey) (*Account, error)
	// NewAccount(ctx context.Context, ao AccountOptions) (*Account, error)
	// UpdateAccount(context.Context, string, []string) (*Account, error)

	// GetAuthz(ctx context.Context, accID string, authzID string) (*Authz, error)
	// ValidateChallenge(ctx context.Context, accID string, chID string, key *jose.JSONWebKey) (*Challenge, error)

	// FinalizeOrder(ctx context.Context, accID string, orderID string, csr *x509.CertificateRequest) (*Order, error)
	// GetOrder(ctx context.Context, accID string, orderID string) (*Order, error)
	// GetOrdersByAccount(ctx context.Context, accID string) ([]string, error)
	// NewOrder(ctx context.Context, oo OrderOptions) (*Order, error)

	// GetCertificate(string, string) ([]byte, error)

	LoadProvisionerByID(string) (provisioner.Interface, error)
	// GetLink(ctx context.Context, linkType Link, absoluteLink bool, inputs ...string) string
	// GetLinkExplicit(linkType Link, provName string, absoluteLink bool, baseURL *url.URL, inputs ...string) string

	GetCACertificates() ([]*x509.Certificate, error)
	DecryptPKIEnvelope(ctx context.Context, msg *PKIMessage) error
	SignCSR(ctx context.Context, csr *x509.CertificateRequest, msg *PKIMessage) (*PKIMessage, error)
}

// Authority is the layer that handles all SCEP interactions.
type Authority struct {
	backdate provisioner.Duration
	db       nosql.DB
	prefix   string
	dns      string

	// dir      *directory

	intermediateCertificate *x509.Certificate

	service  Service
	signAuth SignAuthority
}

// AuthorityOptions required to create a new SCEP Authority.
type AuthorityOptions struct {
	IntermediateCertificatePath string

	Service Service

	// Backdate
	Backdate provisioner.Duration
	// DB is the database used by nosql.
	DB nosql.DB
	// DNS the host used to generate accurate SCEP links. By default the authority
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
	LoadProvisionerByID(string) (provisioner.Interface, error)
}

// New returns a new Authority that implements the SCEP interface.
func New(signAuth SignAuthority, ops AuthorityOptions) (*Authority, error) {

	if _, ok := ops.DB.(*database.SimpleDB); !ok {
		// TODO: see ACME implementation
	}

	// TODO: the below is a bit similar as what happens in the core Authority class, which
	// creates the full x509 service. However, those aren't accessible directly, which is
	// why I reimplemented this (for now). There might be an alternative that I haven't
	// found yet.
	certificateChain, err := pemutil.ReadCertificateBundle(ops.IntermediateCertificatePath)
	if err != nil {
		return nil, err
	}

	return &Authority{
		backdate:                ops.Backdate,
		db:                      ops.DB,
		prefix:                  ops.Prefix,
		dns:                     ops.DNS,
		intermediateCertificate: certificateChain[0],
		service:                 ops.Service,
		signAuth:                signAuth,
	}, nil
}

// LoadProvisionerByID calls out to the SignAuthority interface to load a
// provisioner by ID.
func (a *Authority) LoadProvisionerByID(id string) (provisioner.Interface, error) {
	return a.signAuth.LoadProvisionerByID(id)
}

// GetCACertificates returns the certificate (chain) for the CA
func (a *Authority) GetCACertificates() ([]*x509.Certificate, error) {

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

	if a.intermediateCertificate == nil {
		return nil, errors.New("no intermediate certificate available in SCEP authority")
	}

	return []*x509.Certificate{a.intermediateCertificate}, nil
}

// DecryptPKIEnvelope decrypts an enveloped message
func (a *Authority) DecryptPKIEnvelope(ctx context.Context, msg *PKIMessage) error {

	data := msg.Raw

	p7, err := pkcs7.Parse(data)
	if err != nil {
		return err
	}

	var tID microscep.TransactionID
	if err := p7.UnmarshalSignedAttribute(oidSCEPtransactionID, &tID); err != nil {
		return err
	}

	var msgType microscep.MessageType
	if err := p7.UnmarshalSignedAttribute(oidSCEPmessageType, &msgType); err != nil {
		return err
	}

	msg.p7 = p7

	p7c, err := pkcs7.Parse(p7.Content)
	if err != nil {
		return err
	}

	envelope, err := p7c.Decrypt(a.intermediateCertificate, a.service.Decrypter)
	if err != nil {
		return err
	}

	msg.pkiEnvelope = envelope

	switch msg.MessageType {
	case microscep.CertRep:
		certs, err := microscep.CACerts(msg.pkiEnvelope)
		if err != nil {
			return err
		}
		msg.CertRepMessage.Certificate = certs[0] // TODO: check correctness of this
		return nil
	case microscep.PKCSReq, microscep.UpdateReq, microscep.RenewalReq:
		csr, err := x509.ParseCertificateRequest(msg.pkiEnvelope)
		if err != nil {
			return fmt.Errorf("parse CSR from pkiEnvelope: %w", err)
		}
		// check for challengePassword
		cp, err := microx509util.ParseChallengePassword(msg.pkiEnvelope)
		if err != nil {
			return fmt.Errorf("scep: parse challenge password in pkiEnvelope: %w", err)
		}
		msg.CSRReqMessage = &microscep.CSRReqMessage{
			RawDecrypted:      msg.pkiEnvelope,
			CSR:               csr,
			ChallengePassword: cp,
		}
		//msg.Certificate = p7.Certificates[0] // TODO: check if this is necessary to add (again)
		return nil
	case microscep.GetCRL, microscep.GetCert, microscep.CertPoll:
		return fmt.Errorf("not implemented") //errNotImplemented
	}

	return nil
}

// SignCSR creates an x509.Certificate based on a CSR template and Cert Authority credentials
// returns a new PKIMessage with CertRep data
//func (msg *PKIMessage) SignCSR(crtAuth *x509.Certificate, keyAuth *rsa.PrivateKey, template *x509.Certificate) (*PKIMessage, error) {
//func (a *Authority) SignCSR(ctx context.Context, msg *PKIMessage, template *x509.Certificate) (*PKIMessage, error) {
func (a *Authority) SignCSR(ctx context.Context, csr *x509.CertificateRequest, msg *PKIMessage) (*PKIMessage, error) {

	// TODO: intermediate storage of the request? In SCEP it's possible to request a csr/certificate
	// to be signed, which can be performed asynchronously / out-of-band. In that case a client can
	// poll for the status. It seems to be similar as what can happen in ACME, so might want to model
	// the implementation after the one in the ACME authority. Requires storage, etc.

	p, err := ProvisionerFromContext(ctx)
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

	// subjectKeyID, err := createKeyIdentifier(csr.PublicKey)
	// if err != nil {
	// 	return nil, err
	// }

	// serial := big.NewInt(int64(rand.Int63())) // TODO: serial logic?
	// days := 40                                // TODO: days

	// // TODO: use information from provisioner, like claims
	// template := &x509.Certificate{
	// 	SerialNumber: serial,
	// 	Subject:      csr.Subject,
	// 	NotBefore:    time.Now().Add(-600).UTC(),
	// 	NotAfter:     time.Now().AddDate(0, 0, days).UTC(),
	// 	SubjectKeyId: subjectKeyID,
	// 	KeyUsage:     x509.KeyUsageDigitalSignature,
	// 	ExtKeyUsage: []x509.ExtKeyUsage{
	// 		x509.ExtKeyUsageClientAuth,
	// 	},
	// 	SignatureAlgorithm: csr.SignatureAlgorithm,
	// 	EmailAddresses:     csr.EmailAddresses,
	// 	DNSNames:           csr.DNSNames,
	// }

	// Template data
	data := x509util.NewTemplateData()
	data.SetCommonName(csr.Subject.CommonName)
	data.SetSANs(csr.DNSNames)
	data.SetCertificateRequest(csr)

	// Get authorizations from the SCEP provisioner.
	ctx = provisioner.NewContextWithMethod(ctx, provisioner.SignMethod)
	signOps, err := p.AuthorizeSign(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("error retrieving authorization options from SCEP provisioner: %w", err)
	}

	opts := provisioner.SignOptions{
		// NotBefore: provisioner.NewTimeDuration(o.NotBefore),
		// NotAfter:  provisioner.NewTimeDuration(o.NotAfter),
	}

	templateOptions, err := provisioner.TemplateOptions(p.GetOptions(), data)
	if err != nil {
		return nil, fmt.Errorf("error creating template options from SCEP provisioner: %w", err)
	}
	signOps = append(signOps, templateOptions)

	certChain, err := a.signAuth.Sign(csr, opts, signOps...)
	if err != nil {
		return nil, fmt.Errorf("error generating certificate for order %w", err)
	}

	cert := certChain[0]

	// fmt.Println("CERT")
	// fmt.Println(cert)
	// fmt.Println(fmt.Sprintf("%T", cert))
	// fmt.Println(cert.Issuer)
	// fmt.Println(cert.Subject)
	// fmt.Println(cert.SerialNumber)
	// fmt.Println(string(cert.SubjectKeyId))

	// create a degenerate cert structure
	deg, err := DegenerateCertificates([]*x509.Certificate{cert})
	if err != nil {
		return nil, err
	}

	e7, err := pkcs7.Encrypt(deg, msg.p7.Certificates)
	if err != nil {
		return nil, err
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
	if err := signedData.AddSigner(authCert, a.service.Signer, config); err != nil {
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

// DegenerateCertificates creates degenerate certificates pkcs#7 type
func DegenerateCertificates(certs []*x509.Certificate) ([]byte, error) {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	degenerate, err := pkcs7.DegenerateCertificate(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return degenerate, nil
}

// createKeyIdentifier creates an identifier for public keys
// according to the first method in RFC5280 section 4.2.1.2.
func createKeyIdentifier(pub crypto.PublicKey) ([]byte, error) {

	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	id := sha1.Sum(keyBytes)

	return id[:], nil
}

// Interface guards
var (
	_ Interface = (*Authority)(nil)
)
