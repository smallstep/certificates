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
	"strings"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/scep"

	microscep "github.com/micromdm/scep/scep"
)

const (
	opnGetCACert    = "GetCACert"
	opnGetCACaps    = "GetCACaps"
	opnPKIOperation = "PKIOperation"

	// TODO: add other (more optional) operations and handling
)

// SCEPRequest is a SCEP server request.
type SCEPRequest struct {
	Operation string
	Message   []byte
}

// SCEPResponse is a SCEP server response.
type SCEPResponse struct {
	Operation string
	CACertNum int
	Data      []byte
	Err       error
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

type nextHTTP = func(http.ResponseWriter, *http.Request)

// lookupProvisioner loads the provisioner associated with the request.
// Responds 404 if the provisioner does not exist.
func (h *Handler) lookupProvisioner(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {

		// name := chi.URLParam(r, "provisionerID")
		// provisionerID, err := url.PathUnescape(name)
		// if err != nil {
		// 	api.WriteError(w, fmt.Errorf("error url unescaping provisioner id '%s'", name))
		// 	return
		// }

		// TODO: make this configurable; and we might want to look at being able to provide multiple,
		// like the ACME one? The below assumes a SCEP provider (scep/) called "scep1" exists.
		provisionerID := "scep1"

		p, err := h.Auth.LoadProvisionerByID("scep/" + provisionerID)
		if err != nil {
			api.WriteError(w, err)
			return
		}

		scepProvisioner, ok := p.(*provisioner.SCEP)
		if !ok {
			api.WriteError(w, errors.New("provisioner must be of type SCEP"))
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, acme.ProvisionerContextKey, scep.Provisioner(scepProvisioner))
		next(w, r.WithContext(ctx))
	}
}

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
		scepResponse.CACertNum = len(certs)
		scepResponse.Data = data
		scepResponse.Err = err
	}

	return writeSCEPResponse(w, scepResponse)
}

func (h *Handler) GetCACaps(w http.ResponseWriter, r *http.Request, scepResponse SCEPResponse) error {

	//ctx := r.Context()

	// _, err := ProvisionerFromContext(ctx)
	// if err != nil {
	// 	return err
	// }

	// TODO: get the actual capabilities from provisioner config
	scepResponse.Data = formatCapabilities(defaultCapabilities)

	return writeSCEPResponse(w, scepResponse)
}

func (h *Handler) PKIOperation(w http.ResponseWriter, r *http.Request, scepRequest SCEPRequest, scepResponse SCEPResponse) error {

	ctx := r.Context()

	microMsg, err := microscep.ParsePKIMessage(scepRequest.Message)
	if err != nil {
		return err
	}

	msg := &scep.PKIMessage{
		TransactionID: microMsg.TransactionID,
		MessageType:   microMsg.MessageType,
		SenderNonce:   microMsg.SenderNonce,
		Raw:           microMsg.Raw,
	}

	if err := h.Auth.DecryptPKIEnvelope(ctx, msg); err != nil {
		return err
	}

	if msg.MessageType == microscep.PKCSReq {
		// TODO: CSR validation, like challenge password
	}

	csr := msg.CSRReqMessage.CSR

	certRep, err := h.Auth.SignCSR(ctx, csr, msg)
	if err != nil {
		return err
	}

	// //cert := certRep.CertRepMessage.Certificate
	// //name := certName(cert)

	// // TODO: check if CN already exists, if renewal is allowed and if existing should be revoked; fail if not
	// // TODO: store the new cert for CN locally; should go into the DB

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

func formatCapabilities(caps []string) []byte {
	return []byte(strings.Join(caps, "\r\n"))
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
	// TODO: check the default capabilities; https://tools.ietf.org/html/rfc8894#section-3.5.2
	// TODO: move capabilities to Authority or Provisioner, so that they can be configured?
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
			return certChainHeader
		}
		return leafHeader
	case opnPKIOperation:
		return pkiOpHeader
	default:
		return "text/plain"
	}
}
