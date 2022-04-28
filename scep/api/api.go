// Package api implements a SCEP HTTP server.
package api

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi"
	microscep "github.com/micromdm/scep/v2/scep"
	"go.mozilla.org/pkcs7"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/log"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/scep"
)

const (
	opnGetCACert    = "GetCACert"
	opnGetCACaps    = "GetCACaps"
	opnPKIOperation = "PKIOperation"

	// TODO: add other (more optional) operations and handling
)

const maxPayloadSize = 2 << 20

// request is a SCEP server request.
type request struct {
	Operation string
	Message   []byte
}

// response is a SCEP server response.
type response struct {
	Operation   string
	CACertNum   int
	Data        []byte
	Certificate *x509.Certificate
	Error       error
}

// handler is the SCEP request handler.
type handler struct{}

// Route traffic and implement the Router interface.
//
// Deprecated: use scep.Route(r api.Router)
func (h *handler) Route(r api.Router) {
	Route(r)
}

// New returns a new SCEP API router.
//
// Deprecated: use scep.Route(r api.Router)
func New(auth *scep.Authority) api.RouterHandler {
	return &handler{}
}

// Route traffic and implement the Router interface.
func Route(r api.Router) {
	r.MethodFunc(http.MethodGet, "/{provisionerName}/*", lookupProvisioner(Get))
	r.MethodFunc(http.MethodGet, "/{provisionerName}", lookupProvisioner(Get))
	r.MethodFunc(http.MethodPost, "/{provisionerName}/*", lookupProvisioner(Post))
	r.MethodFunc(http.MethodPost, "/{provisionerName}", lookupProvisioner(Post))
}

// Get handles all SCEP GET requests
func Get(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		fail(w, fmt.Errorf("invalid scep get request: %w", err))
		return
	}

	ctx := r.Context()
	var res response

	switch req.Operation {
	case opnGetCACert:
		res, err = GetCACert(ctx)
	case opnGetCACaps:
		res, err = GetCACaps(ctx)
	case opnPKIOperation:
		// TODO: implement the GET for PKI operation? Default CACAPS doesn't specify this is in use, though
	default:
		err = fmt.Errorf("unknown operation: %s", req.Operation)
	}

	if err != nil {
		fail(w, fmt.Errorf("scep get request failed: %w", err))
		return
	}

	writeResponse(w, res)
}

// Post handles all SCEP POST requests
func Post(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		fail(w, fmt.Errorf("invalid scep post request: %w", err))
		return
	}

	var res response
	switch req.Operation {
	case opnPKIOperation:
		res, err = PKIOperation(r.Context(), req)
	default:
		err = fmt.Errorf("unknown operation: %s", req.Operation)
	}

	if err != nil {
		fail(w, fmt.Errorf("scep post request failed: %w", err))
		return
	}

	writeResponse(w, res)
}

func decodeRequest(r *http.Request) (request, error) {
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
			return request{
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
				return request{}, err
			}
			return request{
				Operation: operation,
				Message:   decodedMessage,
			}, nil
		default:
			return request{}, fmt.Errorf("unsupported operation: %s", operation)
		}
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
		if err != nil {
			return request{}, err
		}
		return request{
			Operation: operation,
			Message:   body,
		}, nil
	default:
		return request{}, fmt.Errorf("unsupported method: %s", method)
	}
}

// lookupProvisioner loads the provisioner associated with the request.
// Responds 404 if the provisioner does not exist.
func lookupProvisioner(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "provisionerName")
		provisionerName, err := url.PathUnescape(name)
		if err != nil {
			fail(w, fmt.Errorf("error url unescaping provisioner name '%s'", name))
			return
		}

		ctx := r.Context()
		auth := scep.MustFromContext(ctx)
		p, err := auth.LoadProvisionerByName(provisionerName)
		if err != nil {
			fail(w, err)
			return
		}

		prov, ok := p.(*provisioner.SCEP)
		if !ok {
			fail(w, errors.New("provisioner must be of type SCEP"))
			return
		}

		ctx = context.WithValue(ctx, scep.ProvisionerContextKey, scep.Provisioner(prov))
		next(w, r.WithContext(ctx))
	}
}

// GetCACert returns the CA certificates in a SCEP response
func GetCACert(ctx context.Context) (response, error) {
	auth := scep.MustFromContext(ctx)
	certs, err := auth.GetCACertificates(ctx)
	if err != nil {
		return response{}, err
	}

	if len(certs) == 0 {
		return response{}, errors.New("missing CA cert")
	}

	res := response{
		Operation: opnGetCACert,
		CACertNum: len(certs),
	}

	if len(certs) == 1 {
		res.Data = certs[0].Raw
	} else {
		// create degenerate pkcs7 certificate structure, according to
		// https://tools.ietf.org/html/rfc8894#section-4.2.1.2, because
		// not signed or encrypted data has to be returned.
		data, err := microscep.DegenerateCertificates(certs)
		if err != nil {
			return response{}, err
		}
		res.Data = data
	}

	return res, nil
}

// GetCACaps returns the CA capabilities in a SCEP response
func GetCACaps(ctx context.Context) (response, error) {
	auth := scep.MustFromContext(ctx)
	caps := auth.GetCACaps(ctx)

	res := response{
		Operation: opnGetCACaps,
		Data:      formatCapabilities(caps),
	}

	return res, nil
}

// PKIOperation performs PKI operations and returns a SCEP response
func PKIOperation(ctx context.Context, req request) (response, error) {
	// parse the message using microscep implementation
	microMsg, err := microscep.ParsePKIMessage(req.Message)
	if err != nil {
		// return the error, because we can't use the msg for creating a CertRep
		return response{}, err
	}

	// this is essentially doing the same as microscep.ParsePKIMessage, but
	// gives us access to the p7 itself in scep.PKIMessage. Essentially a small
	// wrapper for the microscep implementation.
	p7, err := pkcs7.Parse(microMsg.Raw)
	if err != nil {
		return response{}, err
	}

	// copy over properties to our internal PKIMessage
	msg := &scep.PKIMessage{
		TransactionID: microMsg.TransactionID,
		MessageType:   microMsg.MessageType,
		SenderNonce:   microMsg.SenderNonce,
		Raw:           microMsg.Raw,
		P7:            p7,
	}

	auth := scep.MustFromContext(ctx)
	if err := auth.DecryptPKIEnvelope(ctx, msg); err != nil {
		return response{}, err
	}

	// NOTE: at this point we have sufficient information for returning nicely signed CertReps
	csr := msg.CSRReqMessage.CSR

	// NOTE: we're blocking the RenewalReq if the challenge does not match, because otherwise we don't have any authentication.
	// The macOS SCEP client performs renewals using PKCSreq. The CertNanny SCEP client will use PKCSreq with challenge too, it seems,
	// even if using the renewal flow as described in the README.md. MicroMDM SCEP client also only does PKCSreq by default, unless
	// a certificate exists; then it will use RenewalReq. Adding the challenge check here may be a small breaking change for clients.
	// We'll have to see how it works out.
	if msg.MessageType == microscep.PKCSReq || msg.MessageType == microscep.RenewalReq {
		challengeMatches, err := auth.MatchChallengePassword(ctx, msg.CSRReqMessage.ChallengePassword)
		if err != nil {
			return createFailureResponse(ctx, csr, msg, microscep.BadRequest, errors.New("error when checking password"))
		}
		if !challengeMatches {
			// TODO: can this be returned safely to the client? In the end, if the password was correct, that gains a bit of info too.
			return createFailureResponse(ctx, csr, msg, microscep.BadRequest, errors.New("wrong password provided"))
		}
	}

	// TODO: authorize renewal: we can authorize renewals with the challenge password (if reusable secrets are used).
	// Renewals OPTIONALLY include the challenge if the existing cert is used as authentication, but client SHOULD omit the challenge.
	// This means that for renewal requests we should check the certificate provided to be signed before by the CA. We could
	// enforce use of the challenge if we want too. That way we could be more flexible in terms of authentication scheme (i.e. reusing
	// tokens from other provisioners, calling a webhook, storing multiple secrets, allowing them to be multi-use, etc).
	// Authentication by the (self-signed) certificate with an optional challenge is required; supporting renewals incl. verification
	// of the client cert is not.

	certRep, err := auth.SignCSR(ctx, csr, msg)
	if err != nil {
		return createFailureResponse(ctx, csr, msg, microscep.BadRequest, fmt.Errorf("error when signing new certificate: %w", err))
	}

	res := response{
		Operation:   opnPKIOperation,
		Data:        certRep.Raw,
		Certificate: certRep.Certificate,
	}

	return res, nil
}

func formatCapabilities(caps []string) []byte {
	return []byte(strings.Join(caps, "\r\n"))
}

// writeResponse writes a SCEP response back to the SCEP client.
func writeResponse(w http.ResponseWriter, res response) {

	if res.Error != nil {
		log.Error(w, res.Error)
	}

	if res.Certificate != nil {
		api.LogCertificate(w, res.Certificate)
	}

	w.Header().Set("Content-Type", contentHeader(res))
	_, _ = w.Write(res.Data)
}

func fail(w http.ResponseWriter, err error) {
	log.Error(w, err)

	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func createFailureResponse(ctx context.Context, csr *x509.CertificateRequest, msg *scep.PKIMessage, info microscep.FailInfo, failError error) (response, error) {
	auth := scep.MustFromContext(ctx)
	certRepMsg, err := auth.CreateFailureResponse(ctx, csr, msg, scep.FailInfoName(info), failError.Error())
	if err != nil {
		return response{}, err
	}
	return response{
		Operation: opnPKIOperation,
		Data:      certRepMsg.Raw,
		Error:     failError,
	}, nil
}

func contentHeader(r response) string {
	switch r.Operation {
	default:
		return "text/plain"
	case opnGetCACert:
		if r.CACertNum > 1 {
			return "application/x-x509-ca-ra-cert"
		}
		return "application/x-x509-ca-cert"
	case opnPKIOperation:
		return "application/x-pki-message"
	}
}
