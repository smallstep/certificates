package api

import (
	"context"
<<<<<<< HEAD
	"crypto/x509"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/scep"
	"go.mozilla.org/pkcs7"

	"github.com/pkg/errors"

	microscep "github.com/micromdm/scep/v2/scep"
=======
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/scep"

	microscep "github.com/micromdm/scep/scep"
>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
)

const (
	opnGetCACert    = "GetCACert"
	opnGetCACaps    = "GetCACaps"
	opnPKIOperation = "PKIOperation"
<<<<<<< HEAD

	// TODO: add other (more optional) operations and handling
)

const maxPayloadSize = 2 << 20

type nextHTTP = func(http.ResponseWriter, *http.Request)

const (
	certChainHeader    = "application/x-x509-ca-ra-cert"
	leafHeader         = "application/x-x509-ca-cert"
	pkiOperationHeader = "application/x-pki-message"
=======
>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
)

// SCEPRequest is a SCEP server request.
type SCEPRequest struct {
	Operation string
	Message   []byte
}

// SCEPResponse is a SCEP server response.
type SCEPResponse struct {
<<<<<<< HEAD
	Operation   string
	CACertNum   int
	Data        []byte
	Certificate *x509.Certificate
	Error       error
=======
	Operation string
	CACertNum int
	Data      []byte
	Err       error
>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
}

// Handler is the SCEP request handler.
type Handler struct {
	Auth scep.Interface
}

// New returns a new SCEP API router.
func New(scepAuth scep.Interface) api.RouterHandler {
	return &Handler{scepAuth}
}

// Route traffic and implement the Router interface.
func (h *Handler) Route(r api.Router) {
<<<<<<< HEAD
	getLink := h.Auth.GetLinkExplicit
	r.MethodFunc(http.MethodGet, getLink("{provisionerID}", false, nil), h.lookupProvisioner(h.Get))
	r.MethodFunc(http.MethodPost, getLink("{provisionerID}", false, nil), h.lookupProvisioner(h.Post))
}

// Get handles all SCEP GET requests
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {

	request, err := decodeSCEPRequest(r)
	if err != nil {
		writeError(w, errors.Wrap(err, "invalid scep get request"))
		return
	}

	ctx := r.Context()
	var response SCEPResponse

	switch request.Operation {
	case opnGetCACert:
		response, err = h.GetCACert(ctx)
	case opnGetCACaps:
		response, err = h.GetCACaps(ctx)
	case opnPKIOperation:
		// TODO: implement the GET for PKI operation? Default CACAPS doesn't specify this is in use, though
	default:
		err = errors.Errorf("unknown operation: %s", request.Operation)
	}

	if err != nil {
		writeError(w, errors.Wrap(err, "scep get request failed"))
		return
	}

	writeSCEPResponse(w, response)
}

// Post handles all SCEP POST requests
func (h *Handler) Post(w http.ResponseWriter, r *http.Request) {

	request, err := decodeSCEPRequest(r)
	if err != nil {
		writeError(w, errors.Wrap(err, "invalid scep post request"))
		return
	}

	ctx := r.Context()
	var response SCEPResponse

	switch request.Operation {
	case opnPKIOperation:
		response, err = h.PKIOperation(ctx, request)
	default:
		err = errors.Errorf("unknown operation: %s", request.Operation)
	}

	if err != nil {
		writeError(w, errors.Wrap(err, "scep post request failed"))
		return
	}

	writeSCEPResponse(w, response)
}

=======
	//getLink := h.Auth.GetLinkExplicit
	//fmt.Println(getLink)

	//r.MethodFunc("GET", "/bla", h.baseURLFromRequest(h.lookupProvisioner(nil)))
	//r.MethodFunc("GET", getLink(acme.NewNonceLink, "{provisionerID}", false, nil), h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.GetNonce))))

	r.MethodFunc(http.MethodGet, "/", h.lookupProvisioner(h.Get))
	r.MethodFunc(http.MethodPost, "/", h.lookupProvisioner(h.Post))

}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {

	scepRequest, err := decodeSCEPRequest(r)
	if err != nil {
		fmt.Println(err)
		fmt.Println("not a scep get request")
		w.WriteHeader(500)
	}

	scepResponse := SCEPResponse{Operation: scepRequest.Operation}

	switch scepRequest.Operation {
	case opnGetCACert:
		err := h.GetCACert(w, r, scepResponse)
		if err != nil {
			fmt.Println(err)
		}

	case opnGetCACaps:
		err := h.GetCACaps(w, r, scepResponse)
		if err != nil {
			fmt.Println(err)
		}
	case opnPKIOperation:

	default:

	}
}

func (h *Handler) Post(w http.ResponseWriter, r *http.Request) {
	scepRequest, err := decodeSCEPRequest(r)
	if err != nil {
		fmt.Println(err)
		fmt.Println("not a scep post request")
		w.WriteHeader(500)
	}

	scepResponse := SCEPResponse{Operation: scepRequest.Operation}

	switch scepRequest.Operation {
	case opnPKIOperation:
		err := h.PKIOperation(w, r, scepRequest, scepResponse)
		if err != nil {
			fmt.Println(err)
		}
	default:

	}

}

const maxPayloadSize = 2 << 20

>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
func decodeSCEPRequest(r *http.Request) (SCEPRequest, error) {

	defer r.Body.Close()

	method := r.Method
	query := r.URL.Query()

	var operation string
	if _, ok := query["operation"]; ok {
		operation = query.Get("operation")
	}

	switch method {
	case http.MethodGet:
		switch operation {
		case opnGetCACert, opnGetCACaps:
			return SCEPRequest{
				Operation: operation,
				Message:   []byte{},
			}, nil
		case opnPKIOperation:
			var message string
			if _, ok := query["message"]; ok {
				message = query.Get("message")
			}
<<<<<<< HEAD
			// TODO: verify this; it seems like it should be StdEncoding instead of URLEncoding
=======
>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
			decodedMessage, err := base64.URLEncoding.DecodeString(message)
			if err != nil {
				return SCEPRequest{}, err
			}
			return SCEPRequest{
				Operation: operation,
				Message:   decodedMessage,
			}, nil
		default:
<<<<<<< HEAD
			return SCEPRequest{}, errors.Errorf("unsupported operation: %s", operation)
=======
			return SCEPRequest{}, fmt.Errorf("unsupported operation: %s", operation)
>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
		}
	case http.MethodPost:
		body, err := ioutil.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
		if err != nil {
			return SCEPRequest{}, err
		}
		return SCEPRequest{
			Operation: operation,
			Message:   body,
		}, nil
	default:
<<<<<<< HEAD
		return SCEPRequest{}, errors.Errorf("unsupported method: %s", method)
	}
}

=======
		return SCEPRequest{}, fmt.Errorf("unsupported method: %s", method)
	}
}

type nextHTTP = func(http.ResponseWriter, *http.Request)

>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
// lookupProvisioner loads the provisioner associated with the request.
// Responds 404 if the provisioner does not exist.
func (h *Handler) lookupProvisioner(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {

<<<<<<< HEAD
		name := chi.URLParam(r, "provisionerID")
		provisionerID, err := url.PathUnescape(name)
		if err != nil {
			api.WriteError(w, errors.Errorf("error url unescaping provisioner id '%s'", name))
			return
		}

		p, err := h.Auth.LoadProvisionerByID("scep/" + provisionerID)
=======
		// TODO: make this configurable; and we might want to look at being able to provide multiple,
		// like the actual ACME one? The below assumes a SCEP provider (scep/) called "scep1" exists.
		p, err := h.Auth.LoadProvisionerByID("scep/scep1")
>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
		if err != nil {
			api.WriteError(w, err)
			return
		}

<<<<<<< HEAD
		provisioner, ok := p.(*provisioner.SCEP)
=======
		scepProvisioner, ok := p.(*provisioner.SCEP)
>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
		if !ok {
			api.WriteError(w, errors.New("provisioner must be of type SCEP"))
			return
		}

		ctx := r.Context()
<<<<<<< HEAD
		ctx = context.WithValue(ctx, scep.ProvisionerContextKey, scep.Provisioner(provisioner))
=======
		ctx = context.WithValue(ctx, acme.ProvisionerContextKey, scep.Provisioner(scepProvisioner))
>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
		next(w, r.WithContext(ctx))
	}
}

<<<<<<< HEAD
// GetCACert returns the CA certificates in a SCEP response
func (h *Handler) GetCACert(ctx context.Context) (SCEPResponse, error) {

	certs, err := h.Auth.GetCACertificates()
	if err != nil {
		return SCEPResponse{}, err
	}

	if len(certs) == 0 {
		return SCEPResponse{}, errors.New("missing CA cert")
	}

	response := SCEPResponse{
		Operation: opnGetCACert,
		CACertNum: len(certs),
	}

	if len(certs) == 1 {
		response.Data = certs[0].Raw
	} else {
		// create degenerate pkcs7 certificate structure, according to
		// https://tools.ietf.org/html/rfc8894#section-4.2.1.2, because
		// not signed or encrypted data has to be returned.
		data, err := microscep.DegenerateCertificates(certs)
		if err != nil {
			return SCEPResponse{}, err
		}
		response.Data = data
	}

	return response, nil
}

// GetCACaps returns the CA capabilities in a SCEP response
func (h *Handler) GetCACaps(ctx context.Context) (SCEPResponse, error) {

	caps := h.Auth.GetCACaps(ctx)

	response := SCEPResponse{
		Operation: opnGetCACaps,
		Data:      formatCapabilities(caps),
	}

	return response, nil
}

// PKIOperation performs PKI operations and returns a SCEP response
func (h *Handler) PKIOperation(ctx context.Context, request SCEPRequest) (SCEPResponse, error) {

	// parse the message using microscep implementation
	microMsg, err := microscep.ParsePKIMessage(request.Message)
	if err != nil {
		// return the error, because we can't use the msg for creating a CertRep
		return SCEPResponse{}, err
	}

	// this is essentially doing the same as microscep.ParsePKIMessage, but
	// gives us access to the p7 itself in scep.PKIMessage. Essentially a small
	// wrapper for the microscep implementation.
	p7, err := pkcs7.Parse(microMsg.Raw)
	if err != nil {
		return SCEPResponse{}, err
	}

	// copy over properties to our internal PKIMessage
	msg := &scep.PKIMessage{
		TransactionID: microMsg.TransactionID,
		MessageType:   microMsg.MessageType,
		SenderNonce:   microMsg.SenderNonce,
		Raw:           microMsg.Raw,
		P7:            p7,
	}

	if err := h.Auth.DecryptPKIEnvelope(ctx, msg); err != nil {
		return SCEPResponse{}, err
	}

	// NOTE: at this point we have sufficient information for returning nicely signed CertReps
	csr := msg.CSRReqMessage.CSR

	if msg.MessageType == microscep.PKCSReq {

		challengeMatches, err := h.Auth.MatchChallengePassword(ctx, msg.CSRReqMessage.ChallengePassword)
		if err != nil {
			return h.createFailureResponse(ctx, csr, msg, microscep.BadRequest, errors.New("error when checking password"))
		}

		if !challengeMatches {
			// TODO: can this be returned safely to the client? In the end, if the password was correct, that gains a bit of info too.
			return h.createFailureResponse(ctx, csr, msg, microscep.BadRequest, errors.New("wrong password provided"))
		}
	}

	// TODO: check if CN already exists, if renewal is allowed and if existing should be revoked; fail if not

	certRep, err := h.Auth.SignCSR(ctx, csr, msg)
	if err != nil {
		return h.createFailureResponse(ctx, csr, msg, microscep.BadRequest, errors.Wrap(err, "error when signing new certificate"))
	}

	response := SCEPResponse{
		Operation:   opnPKIOperation,
		Data:        certRep.Raw,
		Certificate: certRep.Certificate,
	}

	return response, nil
}

func formatCapabilities(caps []string) []byte {
	return []byte(strings.Join(caps, "\r\n"))
}

// writeSCEPResponse writes a SCEP response back to the SCEP client.
func writeSCEPResponse(w http.ResponseWriter, response SCEPResponse) {

	if response.Error != nil {
		api.LogError(w, response.Error)
	}

	if response.Certificate != nil {
		api.LogCertificate(w, response.Certificate)
	}

	w.Header().Set("Content-Type", contentHeader(response))
	_, err := w.Write(response.Data)
	if err != nil {
		writeError(w, errors.Wrap(err, "error when writing scep response")) // This could end up as an error again
	}
}

func writeError(w http.ResponseWriter, err error) {
	scepError := &scep.Error{
		Message: err.Error(),
		Status:  http.StatusInternalServerError, // TODO: make this a param?
	}
	api.WriteError(w, scepError)
}

func (h *Handler) createFailureResponse(ctx context.Context, csr *x509.CertificateRequest, msg *scep.PKIMessage, info microscep.FailInfo, failError error) (SCEPResponse, error) {
	certRepMsg, err := h.Auth.CreateFailureResponse(ctx, csr, msg, scep.FailInfoName(info), failError.Error())
	if err != nil {
		return SCEPResponse{}, err
	}
	return SCEPResponse{
		Operation: opnPKIOperation,
		Data:      certRepMsg.Raw,
		Error:     failError,
	}, nil
}

func contentHeader(r SCEPResponse) string {
	switch r.Operation {
	case opnGetCACert:
		if r.CACertNum > 1 {
=======
func (h *Handler) GetCACert(w http.ResponseWriter, r *http.Request, scepResponse SCEPResponse) error {

	certs, err := h.Auth.GetCACertificates()
	if err != nil {
		return err
	}

	if len(certs) == 0 {
		scepResponse.CACertNum = 0
		scepResponse.Err = errors.New("missing CA Cert")
	} else if len(certs) == 1 {
		scepResponse.Data = certs[0].Raw
		scepResponse.CACertNum = 1
	} else {
		data, err := microscep.DegenerateCertificates(certs)
		scepResponse.Data = data
		scepResponse.Err = err
	}

	return writeSCEPResponse(w, scepResponse)
}

func (h *Handler) GetCACaps(w http.ResponseWriter, r *http.Request, scepResponse SCEPResponse) error {

	ctx := r.Context()

	_, err := ProvisionerFromContext(ctx)
	if err != nil {
		return err
	}

	// TODO: get the actual capabilities from provisioner config
	scepResponse.Data = formatCapabilities(defaultCapabilities)

	return writeSCEPResponse(w, scepResponse)
}

func (h *Handler) PKIOperation(w http.ResponseWriter, r *http.Request, scepRequest SCEPRequest, scepResponse SCEPResponse) error {

	msg, err := microscep.ParsePKIMessage(scepRequest.Message)
	if err != nil {
		return err
	}

	certs, err := h.Auth.GetCACertificates()
	if err != nil {
		return err
	}

	// TODO: instead of getting the key to decrypt, add a decrypt function to the auth; less leaky
	key, err := h.Auth.GetSigningKey()
	if err != nil {
		return err
	}

	ca := certs[0]
	if err := msg.DecryptPKIEnvelope(ca, key); err != nil {
		return err
	}

	if msg.MessageType == microscep.PKCSReq {
		// TODO: CSR validation, like challenge password
	}

	csr := msg.CSRReqMessage.CSR
	id, err := createKeyIdentifier(csr.PublicKey)
	if err != nil {
		return err
	}

	serial := big.NewInt(int64(rand.Int63())) // TODO: serial logic?

	days := 40

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-600).UTC(),
		NotAfter:     time.Now().AddDate(0, 0, days).UTC(),
		SubjectKeyId: id,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		SignatureAlgorithm: csr.SignatureAlgorithm,
		EmailAddresses:     csr.EmailAddresses,
	}

	certRep, err := msg.SignCSR(ca, key, template)
	if err != nil {
		return err
	}

	//cert := certRep.CertRepMessage.Certificate
	//name := certName(cert)

	// TODO: check if CN already exists, if renewal is allowed and if existing should be revoked; fail if not
	// TODO: store the new cert for CN locally; should go into the DB

	scepResponse.Data = certRep.Raw

	api.LogCertificate(w, certRep.Certificate)

	return writeSCEPResponse(w, scepResponse)
}

func certName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return string(cert.Signature)
}

// createKeyIdentifier create an identifier for public keys
// according to the first method in RFC5280 section 4.2.1.2.
func createKeyIdentifier(pub crypto.PublicKey) ([]byte, error) {

	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	id := sha1.Sum(keyBytes)

	return id[:], nil
}

func formatCapabilities(caps []string) []byte {
	return []byte(strings.Join(caps, "\n"))
}

// writeSCEPResponse writes a SCEP response back to the SCEP client.
func writeSCEPResponse(w http.ResponseWriter, response SCEPResponse) error {
	if response.Err != nil {
		http.Error(w, response.Err.Error(), http.StatusInternalServerError)
		return nil
	}
	w.Header().Set("Content-Type", contentHeader(response.Operation, response.CACertNum))
	w.Write(response.Data)
	return nil
}

var (
	// TODO: check the default capabilities
	defaultCapabilities = []string{
		"Renewal",
		"SHA-1",
		"SHA-256",
		"AES",
		"DES3",
		"SCEPStandard",
		"POSTPKIOperation",
	}
)

const (
	certChainHeader = "application/x-x509-ca-ra-cert"
	leafHeader      = "application/x-x509-ca-cert"
	pkiOpHeader     = "application/x-pki-message"
)

func contentHeader(operation string, certNum int) string {
	switch operation {
	case opnGetCACert:
		if certNum > 1 {
>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
			return certChainHeader
		}
		return leafHeader
	case opnPKIOperation:
<<<<<<< HEAD
		return pkiOperationHeader
=======
		return pkiOpHeader
>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
	default:
		return "text/plain"
	}
}
<<<<<<< HEAD
=======

// ProvisionerFromContext searches the context for a provisioner. Returns the
// provisioner or an error.
func ProvisionerFromContext(ctx context.Context) (scep.Provisioner, error) {
	val := ctx.Value(acme.ProvisionerContextKey)
	if val == nil {
		return nil, errors.New("provisioner expected in request context")
	}
	pval, ok := val.(scep.Provisioner)
	if !ok || pval == nil {
		return nil, errors.New("provisioner in context is not a SCEP provisioner")
	}
	return pval, nil
}
>>>>>>> 3390397 (Refactor SCEP authority initialization and clean some code)
