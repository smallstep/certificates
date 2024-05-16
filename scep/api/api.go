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

	"github.com/go-chi/chi/v5"
	"github.com/smallstep/pkcs7"
	smallscep "github.com/smallstep/scep"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/log"
	"github.com/smallstep/certificates/authority"
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

// Response is a SCEP server Response.
type Response struct {
	Operation   string
	CACertNum   int
	Data        []byte
	Certificate *x509.Certificate
	Error       error
}

// handler is the SCEP request handler.
type handler struct {
	auth *scep.Authority
}

// Route traffic and implement the Router interface.
//
// Deprecated: use scep.Route(r api.Router)
func (h *handler) Route(r api.Router) {
	route(r, func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := scep.NewContext(r.Context(), h.auth)
			next(w, r.WithContext(ctx))
		}
	})
}

// New returns a new SCEP API router.
//
// Deprecated: use scep.Route(r api.Router)
func New(auth *scep.Authority) api.RouterHandler {
	return &handler{auth: auth}
}

// Route traffic and implement the Router interface.
func Route(r api.Router) {
	route(r, nil)
}

func route(r api.Router, middleware func(next http.HandlerFunc) http.HandlerFunc) {
	getHandler := lookupProvisioner(Get)
	postHandler := lookupProvisioner(Post)

	// For backward compatibility.
	if middleware != nil {
		getHandler = middleware(getHandler)
		postHandler = middleware(postHandler)
	}

	r.MethodFunc(http.MethodGet, "/{provisionerName}/*", getHandler)
	r.MethodFunc(http.MethodGet, "/{provisionerName}", getHandler)
	r.MethodFunc(http.MethodPost, "/{provisionerName}/*", postHandler)
	r.MethodFunc(http.MethodPost, "/{provisionerName}", postHandler)
}

// Get handles all SCEP GET requests
func Get(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		fail(w, r, fmt.Errorf("invalid scep get request: %w", err))
		return
	}

	ctx := r.Context()
	var res Response

	switch req.Operation {
	case opnGetCACert:
		res, err = GetCACert(ctx)
	case opnGetCACaps:
		res, err = GetCACaps(ctx)
	case opnPKIOperation:
		res, err = PKIOperation(ctx, req)
	default:
		err = fmt.Errorf("unknown operation: %s", req.Operation)
	}

	if err != nil {
		fail(w, r, fmt.Errorf("scep get request failed: %w", err))
		return
	}

	writeResponse(w, r, res)
}

// Post handles all SCEP POST requests
func Post(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
		fail(w, r, fmt.Errorf("invalid scep post request: %w", err))
		return
	}

	var res Response
	switch req.Operation {
	case opnPKIOperation:
		res, err = PKIOperation(r.Context(), req)
	default:
		err = fmt.Errorf("unknown operation: %s", req.Operation)
	}

	if err != nil {
		fail(w, r, fmt.Errorf("scep post request failed: %w", err))
		return
	}

	writeResponse(w, r, res)
}

func decodeRequest(r *http.Request) (request, error) {
	defer r.Body.Close()

	method := r.Method
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return request{}, fmt.Errorf("failed parsing URL query: %w", err)
	}

	operation := query.Get("operation")
	if operation == "" {
		return request{}, errors.New("no operation provided")
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
			message := query.Get("message")
			decodedMessage, err := decodeMessage(message, r)
			if err != nil {
				return request{}, fmt.Errorf("failed decoding message: %w", err)
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
			return request{}, fmt.Errorf("failed reading request body: %w", err)
		}
		return request{
			Operation: operation,
			Message:   body,
		}, nil
	default:
		return request{}, fmt.Errorf("unsupported method: %s", method)
	}
}

func decodeMessage(message string, r *http.Request) ([]byte, error) {
	if message == "" {
		return nil, errors.New("message must not be empty")
	}

	// decode the message, which should be base64 standard encoded. Any characters that
	// were escaped in the original query, were unescaped as part of url.ParseQuery, so
	// that doesn't need to be performed here. Return early if successful.
	decodedMessage, err := base64.StdEncoding.DecodeString(message)
	if err == nil {
		return decodedMessage, nil
	}

	// only interested in corrupt input errors below this. This type of error is the
	// most likely to return, but better safe than sorry.
	var cie base64.CorruptInputError
	if !errors.As(err, &cie) {
		return nil, fmt.Errorf("failed base64 decoding message: %w", err)
	}

	// the below code is a workaround for macOS when it sends a GET PKIOperation, which seems to result
	// in a query with the '+' and '/' not being percent encoded; only the padding ('=') is encoded.
	// When that is unescaped in the code before this, this results in invalid base64. The workaround
	// is to obtain the original query, extract the message, apply transformation(s) to make it valid
	// base64 and try decoding it again. If it succeeds, the happy path can be followed with the patched
	// message. Otherwise we still return an error.
	rawQuery, err := parseRawQuery(r.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw query: %w", err)
	}

	rawMessage := rawQuery.Get("message")
	if rawMessage == "" {
		return nil, errors.New("no message in raw query")
	}

	rawMessage = strings.ReplaceAll(rawMessage, "%3D", "=") // apparently the padding arrives encoded; the others (+, /) not?
	decodedMessage, err = base64.StdEncoding.DecodeString(rawMessage)
	if err != nil {
		return nil, fmt.Errorf("failed base64 decoding raw message: %w", err)
	}

	return decodedMessage, nil
}

// parseRawQuery parses a URL query into url.Values. It skips
// unescaping keys and values. This code is based on url.ParseQuery.
func parseRawQuery(query string) (url.Values, error) {
	m := make(url.Values)
	err := parseRawQueryWithoutUnescaping(m, query)
	return m, err
}

// parseRawQueryWithoutUnescaping parses the raw query into url.Values, skipping
// unescaping of the parts. This code is based on url.parseQuery.
func parseRawQueryWithoutUnescaping(m url.Values, query string) (err error) {
	for query != "" {
		var key string
		key, query, _ = strings.Cut(query, "&")
		if strings.Contains(key, ";") {
			return errors.New("invalid semicolon separator in query")
		}
		if key == "" {
			continue
		}
		key, value, _ := strings.Cut(key, "=")
		m[key] = append(m[key], value)
	}
	return err
}

// lookupProvisioner loads the provisioner associated with the request.
// Responds 404 if the provisioner does not exist.
func lookupProvisioner(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "provisionerName")
		provisionerName, err := url.PathUnescape(name)
		if err != nil {
			fail(w, r, fmt.Errorf("error url unescaping provisioner name '%s'", name))
			return
		}

		ctx := r.Context()
		auth := authority.MustFromContext(ctx)
		p, err := auth.LoadProvisionerByName(provisionerName)
		if err != nil {
			fail(w, r, err)
			return
		}

		prov, ok := p.(*provisioner.SCEP)
		if !ok {
			fail(w, r, errors.New("provisioner must be of type SCEP"))
			return
		}

		ctx = scep.NewProvisionerContext(ctx, scep.Provisioner(prov))
		next(w, r.WithContext(ctx))
	}
}

// GetCACert returns the CA certificates in a SCEP response
func GetCACert(ctx context.Context) (Response, error) {
	auth := scep.MustFromContext(ctx)
	certs, err := auth.GetCACertificates(ctx)
	if err != nil {
		return Response{}, err
	}

	if len(certs) == 0 {
		return Response{}, errors.New("missing CA cert")
	}

	res := Response{
		Operation: opnGetCACert,
		CACertNum: len(certs),
	}

	if len(certs) == 1 {
		res.Data = certs[0].Raw
	} else {
		// create degenerate pkcs7 certificate structure, according to
		// https://tools.ietf.org/html/rfc8894#section-4.2.1.2, because
		// not signed or encrypted data has to be returned.
		data, err := smallscep.DegenerateCertificates(certs)
		if err != nil {
			return Response{}, err
		}
		res.Data = data
	}

	return res, nil
}

// GetCACaps returns the CA capabilities in a SCEP response
func GetCACaps(ctx context.Context) (Response, error) {
	auth := scep.MustFromContext(ctx)
	caps := auth.GetCACaps(ctx)

	res := Response{
		Operation: opnGetCACaps,
		Data:      formatCapabilities(caps),
	}

	return res, nil
}

// PKIOperation performs PKI operations and returns a SCEP response
func PKIOperation(ctx context.Context, req request) (Response, error) {
	// parse the message using smallscep implementation
	microMsg, err := smallscep.ParsePKIMessage(req.Message)
	if err != nil {
		// return the error, because we can't use the msg for creating a CertRep
		return Response{}, err
	}

	// this is essentially doing the same as smallscep.ParsePKIMessage, but
	// gives us access to the p7 itself in scep.PKIMessage. Essentially a small
	// wrapper for the smallscep implementation.
	p7, err := pkcs7.Parse(microMsg.Raw)
	if err != nil {
		return Response{}, err
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
		return Response{}, err
	}

	// NOTE: at this point we have sufficient information for returning nicely signed CertReps
	csr := msg.CSRReqMessage.CSR
	transactionID := string(msg.TransactionID)
	challengePassword := msg.CSRReqMessage.ChallengePassword

	// NOTE: we're blocking the RenewalReq if the challenge does not match, because otherwise we don't have any authentication.
	// The macOS SCEP client performs renewals using PKCSreq. The CertNanny SCEP client will use PKCSreq with challenge too, it seems,
	// even if using the renewal flow as described in the README.md. MicroMDM SCEP client also only does PKCSreq by default, unless
	// a certificate exists; then it will use RenewalReq. Adding the challenge check here may be a small breaking change for clients.
	// We'll have to see how it works out.
	if msg.MessageType == smallscep.PKCSReq || msg.MessageType == smallscep.RenewalReq {
		if err := auth.ValidateChallenge(ctx, csr, challengePassword, transactionID); err != nil {
			if errors.Is(err, provisioner.ErrSCEPChallengeInvalid) {
				return createFailureResponse(ctx, csr, msg, smallscep.BadRequest, err.Error(), err)
			}
			scepErr := errors.New("failed validating challenge password")
			return createFailureResponse(ctx, csr, msg, smallscep.BadRequest, scepErr.Error(), scepErr)
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
		if notifyErr := auth.NotifyFailure(ctx, csr, transactionID, 0, err.Error()); notifyErr != nil {
			// TODO(hs): ignore this error case? It's not critical if the notification fails; but logging it might be good
			_ = notifyErr
		}
		return createFailureResponse(ctx, csr, msg, smallscep.BadRequest, "internal server error; please see the certificate authority logs for more info", fmt.Errorf("error when signing new certificate: %w", err))
	}

	if notifyErr := auth.NotifySuccess(ctx, csr, certRep.Certificate, transactionID); notifyErr != nil {
		// TODO(hs): ignore this error case? It's not critical if the notification fails; but logging it might be good
		_ = notifyErr
	}

	res := Response{
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
func writeResponse(w http.ResponseWriter, r *http.Request, res Response) {
	if res.Error != nil {
		log.Error(w, r, res.Error)
	}

	if res.Certificate != nil {
		api.LogCertificate(w, res.Certificate)
	}

	w.Header().Set("Content-Type", contentHeader(res))
	_, _ = w.Write(res.Data)
}

func fail(w http.ResponseWriter, r *http.Request, err error) {
	log.Error(w, r, err)

	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func createFailureResponse(ctx context.Context, csr *x509.CertificateRequest, msg *scep.PKIMessage, info smallscep.FailInfo, infoText string, failError error) (Response, error) {
	auth := scep.MustFromContext(ctx)
	certRepMsg, err := auth.CreateFailureResponse(ctx, csr, msg, scep.FailInfoName(info), infoText)
	if err != nil {
		return Response{}, err
	}
	return Response{
		Operation: opnPKIOperation,
		Data:      certRepMsg.Raw,
		Error:     failError,
	}, nil
}

func contentHeader(r Response) string {
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
