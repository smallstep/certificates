package api

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
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

	microscep "github.com/micromdm/scep/scep"
)

const (
	opnGetCACert    = "GetCACert"
	opnGetCACaps    = "GetCACaps"
	opnPKIOperation = "PKIOperation"

	// TODO: add other (more optional) operations and handling
)

const maxPayloadSize = 2 << 20

type nextHTTP = func(http.ResponseWriter, *http.Request)

const (
	certChainHeader = "application/x-x509-ca-ra-cert"
	leafHeader      = "application/x-x509-ca-cert"
	pkiOpHeader     = "application/x-pki-message"
)

// SCEPRequest is a SCEP server request.
type SCEPRequest struct {
	Operation string
	Message   []byte
}

// SCEPResponse is a SCEP server response.
type SCEPResponse struct {
	Operation   string
	CACertNum   int
	Data        []byte
	Certificate *x509.Certificate
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
	getLink := h.Auth.GetLinkExplicit
	r.MethodFunc(http.MethodGet, getLink("{provisionerID}", false, nil), h.lookupProvisioner(h.Get))
	r.MethodFunc(http.MethodPost, getLink("{provisionerID}", false, nil), h.lookupProvisioner(h.Post))
}

// Get handles all SCEP GET requests
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {

	request, err := decodeSCEPRequest(r)
	if err != nil {
		writeError(w, fmt.Errorf("not a scep get request: %w", err))
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
		err = fmt.Errorf("unknown operation: %s", request.Operation)
	}

	if err != nil {
		writeError(w, fmt.Errorf("get request failed: %w", err))
		return
	}

	writeSCEPResponse(w, response)
}

// Post handles all SCEP POST requests
func (h *Handler) Post(w http.ResponseWriter, r *http.Request) {

	request, err := decodeSCEPRequest(r)
	if err != nil {
		writeError(w, fmt.Errorf("not a scep post request: %w", err))
		return
	}

	ctx := r.Context()
	var response SCEPResponse

	switch request.Operation {
	case opnPKIOperation:
		response, err = h.PKIOperation(ctx, request)
	default:
		err = fmt.Errorf("unknown operation: %s", request.Operation)
	}

	if err != nil {
		writeError(w, fmt.Errorf("post request failed: %w", err))
		return
	}

	// TODO: fix cases in which we get here and there's no certificate (i.e. wrong password, waiting for cert, etc)
	// We should generate an appropriate response and it should be signed
	api.LogCertificate(w, response.Certificate)

	writeSCEPResponse(w, response)
}

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
			// TODO: verify this; it seems like it should be StdEncoding instead of URLEncoding
			decodedMessage, err := base64.URLEncoding.DecodeString(message)
			if err != nil {
				return SCEPRequest{}, err
			}
			return SCEPRequest{
				Operation: operation,
				Message:   decodedMessage,
			}, nil
		default:
			return SCEPRequest{}, fmt.Errorf("unsupported operation: %s", operation)
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
		return SCEPRequest{}, fmt.Errorf("unsupported method: %s", method)
	}
}

// lookupProvisioner loads the provisioner associated with the request.
// Responds 404 if the provisioner does not exist.
func (h *Handler) lookupProvisioner(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {

		name := chi.URLParam(r, "provisionerID")
		provisionerID, err := url.PathUnescape(name)
		if err != nil {
			api.WriteError(w, fmt.Errorf("error url unescaping provisioner id '%s'", name))
			return
		}

		p, err := h.Auth.LoadProvisionerByID("scep/" + provisionerID)
		if err != nil {
			writeError(w, err)
			return
		}

		provisioner, ok := p.(*provisioner.SCEP)
		if !ok {
			writeError(w, errors.New("provisioner must be of type SCEP"))
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, scep.ProvisionerContextKey, scep.Provisioner(provisioner))
		next(w, r.WithContext(ctx))
	}
}

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
		return SCEPResponse{}, err
	}

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

	if msg.MessageType == microscep.PKCSReq {

		challengeMatches, err := h.Auth.MatchChallengePassword(ctx, msg.CSRReqMessage.ChallengePassword)
		if err != nil {
			return SCEPResponse{}, err
		}

		if !challengeMatches {
			return SCEPResponse{}, errors.New("wrong password provided")
		}
	}

	csr := msg.CSRReqMessage.CSR

	certRep, err := h.Auth.SignCSR(ctx, csr, msg)
	if err != nil {
		return SCEPResponse{}, err
	}

	// //cert := certRep.CertRepMessage.Certificate
	// //name := certName(cert)

	// // TODO: check if CN already exists, if renewal is allowed and if existing should be revoked; fail if not
	// // TODO: store the new cert for CN locally; should go into the DB

	response := SCEPResponse{
		Operation:   opnPKIOperation,
		Data:        certRep.Raw,
		Certificate: certRep.Certificate,
	}

	return response, nil
}

func certName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return string(cert.Signature)
}

func formatCapabilities(caps []string) []byte {
	return []byte(strings.Join(caps, "\r\n"))
}

// writeSCEPResponse writes a SCEP response back to the SCEP client.
func writeSCEPResponse(w http.ResponseWriter, response SCEPResponse) {
	w.Header().Set("Content-Type", contentHeader(response))
	_, err := w.Write(response.Data)
	if err != nil {
		writeError(w, fmt.Errorf("error when writing scep response: %w", err)) // This could end up as an error again
	}
}

func writeError(w http.ResponseWriter, err error) {
	// TODO: this probably needs to use SCEP specific errors (i.e. failInfo)
	scepError := &scep.Error{
		Message: err.Error(),
		Status:  http.StatusInternalServerError, // TODO: make this a param?
	}
	api.WriteError(w, scepError)
}

func contentHeader(r SCEPResponse) string {
	switch r.Operation {
	case opnGetCACert:
		if r.CACertNum > 1 {
			return certChainHeader
		}
		return leafHeader
	case opnPKIOperation:
		return pkiOpHeader
	default:
		return "text/plain"
	}
}
