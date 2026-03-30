// Package api implements an EST HTTP server.
package api

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/log"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/est"
)

const (
	maxPayloadSize = 2 << 20
)

// Util to extract bearer token from request
func BearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}
	return auth[len(prefix):], true
}

// Route configures the EST routes under the provided router.
func Route(r api.Router) {
	r.MethodFunc(http.MethodGet, "/{provisionerName}/cacerts", getCACerts)
	r.MethodFunc(http.MethodGet, "/{provisionerName}/csrattrs", getCSRAttrs)
	r.MethodFunc(http.MethodPost, "/{provisionerName}/simpleenroll", enroll)
	r.MethodFunc(http.MethodPost, "/{provisionerName}/simplereenroll", enroll)
}

func lookupProvisioner(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "provisionerName")
		if name == "" || name == "/" {
			name = r.URL.Query().Get("provisioner")
		}
		if name == "" {
			fail(w, r, errors.New("missing provisioner name"))
			return
		}
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

		prov, ok := p.(*provisioner.EST)
		if !ok {
			fail(w, r, errors.New("provisioner must be of type EST"))
			return
		}

		ctx = est.NewProvisionerContext(ctx, est.Provisioner(prov))
		next(w, r.WithContext(ctx))
	}
}

func getCACerts(w http.ResponseWriter, r *http.Request) {
	lookupProvisioner(getCACertsHandler)(w, r)
}

func getCACertsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	auth := est.MustFromContext(ctx)

	certs, err := auth.GetCACertificates(ctx)
	if err != nil {
		fail(w, r, fmt.Errorf("failed to get CA certificates: %w", err))
		return
	}

	data, err := auth.BuildResponse(ctx, certs)
	if err != nil {
		fail(w, r, fmt.Errorf("failed to encode CA certificates: %w", err))
		return
	}

	writeResponse(w, r, data, "application/pkcs7-mime; smime-type=certs-only", http.StatusOK)
}

func getCSRAttrs(w http.ResponseWriter, r *http.Request) {
	lookupProvisioner(getCSRAttrsHandler)(w, r)
}

func getCSRAttrsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov := est.ProvisionerFromContext(ctx)

	attrs, err := prov.GetCSRAttributes(ctx)
	if err != nil {
		fail(w, r, fmt.Errorf("failed to get CSR attributes: %w", err))
		return
	}
	if attrs == nil {
		attrs = []byte{}
	}
	// Minimal implementation: allow provisioner to return nil/empty for "no attributes".
	writeResponse(w, r, attrs, "application/csrattrs", http.StatusOK)
}

func enroll(w http.ResponseWriter, r *http.Request) {
	lookupProvisioner(enrollHandler)(w, r)
}

func enrollHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx, err := authContextFromRequest(ctx, r)
	if err != nil {
		failWithStatus(w, r, http.StatusUnauthorized, err)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
	if err != nil {
		failWithStatus(w, r, http.StatusBadRequest, fmt.Errorf("failed reading request body: %w", err))
		return
	}

	if err := requireContentType(r, "application/pkcs10"); err != nil {
		failWithStatus(w, r, http.StatusUnsupportedMediaType, err)
		return
	}

	der, err := decodeBase64Payload(body)
	if err != nil {
		failWithStatus(w, r, http.StatusBadRequest, err)
		return
	}

	csr, err := parseCSR(der)
	if err != nil {
		failWithStatus(w, r, http.StatusBadRequest, fmt.Errorf("failed parsing CSR: %w", err))
		return
	}
	if err := csr.CheckSignature(); err != nil {
		failWithStatus(w, r, http.StatusBadRequest, fmt.Errorf("invalid CSR signature: %w", err))
		return
	}

	opts, err := authorizeEnrollRequest(ctx, csr)
	if err != nil {
		failWithStatus(w, r, http.StatusUnauthorized, err)
		return
	}

	r = r.WithContext(ctx)
	auth := est.MustFromContext(ctx)

	issued, err := auth.SignCSR(ctx, csr, opts...)
	if err != nil {
		failWithStatus(w, r, http.StatusInternalServerError, fmt.Errorf("failed issuing certificate: %w", err))
		return
	}

	signed, err := auth.BuildResponse(ctx, []*x509.Certificate{issued})
	if err != nil {
		failWithStatus(w, r, http.StatusInternalServerError, fmt.Errorf("failed encoding issued certificate: %w", err))
		return
	}

	writeResponse(w, r, signed, "application/pkcs7-mime; smime-type=certs-only", http.StatusOK)
}

var errMissingAuth = errors.New("missing authentication material")

// authContextFromRequest extracts auth material from the request into the context.
func authContextFromRequest(ctx context.Context, r *http.Request) (context.Context, error) {
	if r.TLS == nil {
		return ctx, errors.New("missing TLS connection")
	}

	if len(r.TLS.PeerCertificates) > 0 {
		ctx = est.NewClientCertificateContext(ctx, r.TLS.PeerCertificates[0])
		ctx = est.NewClientCertificateChainContext(ctx, r.TLS.PeerCertificates)
	}

	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		ctx = est.NewAuthenticationHeaderContext(ctx, authHeader)
		if token, ok := BearerToken(r); ok {
			ctx = est.NewBearerTokenContext(ctx, token)
		} else if username, password, ok := r.BasicAuth(); ok {
			ctx = est.NewBasicAuthContext(ctx, est.BasicAuth{
				Username: username,
				Password: password,
			})
		}
	}

	if _, ok := est.ClientCertificateFromContext(ctx); !ok {
		if _, ok := est.AuthenticationHeaderFromContext(ctx); !ok {
			return ctx, errMissingAuth
		}
	}
	return ctx, nil
}

// authorizeEnrollRequest validates the request against provisioner-configured auth methods.
func authorizeEnrollRequest(ctx context.Context, csr *x509.CertificateRequest) ([]provisioner.SignCSROption, error) {
	prov := est.ProvisionerFromContext(ctx)
	ca := authority.MustFromContext(ctx)

	req := provisioner.ESTAuthRequest{
		CSR:             csr,
		CARoots:         ca.GetRootCertificates(),
		CAIntermediates: ca.GetIntermediateCertificates(),
	}
	if cert, ok := est.ClientCertificateFromContext(ctx); ok {
		req.ClientCertificate = cert
		req.ClientCertificateChain, _ = est.ClientCertificateChainFromContext(ctx)
	}
	if authHeader, ok := est.AuthenticationHeaderFromContext(ctx); ok {
		req.AuthenticationHeader = authHeader
		if auth, ok := est.BasicAuthFromContext(ctx); ok {
			req.BasicAuthUsername = auth.Username
			req.BasicAuthPassword = auth.Password
		}
		if token, ok := est.BearerTokenFromContext(ctx); ok {
			req.BearerToken = token
		}
	}

	opts, err := prov.AuthorizeRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return opts, nil
}

func parseCSR(body []byte) (*x509.CertificateRequest, error) {
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}

	return x509.ParseCertificateRequest(body)
}

func decodeBase64Payload(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}

	trimmed := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		default:
			return r
		}
	}, string(body))

	if trimmed == "" {
		return nil, errors.New("empty base64 payload")
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	n, err := base64.StdEncoding.Decode(decoded, []byte(trimmed))
	if err != nil {
		return nil, fmt.Errorf("invalid base64 payload: %w", err)
	}

	return decoded[:n], nil
}

func requireContentType(r *http.Request, want string) error {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return errors.New("missing Content-Type header")
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return fmt.Errorf("invalid Content-Type header: %w", err)
	}
	if mt != want {
		return fmt.Errorf("unsupported Content-Type %q", mt)
	}
	return nil
}

func writeResponse(w http.ResponseWriter, r *http.Request, data []byte, contentType string, status int) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(status)

	encoder := base64.NewEncoder(base64.StdEncoding, w)
	_, _ = encoder.Write(data)
	_ = encoder.Close()
}

func fail(w http.ResponseWriter, r *http.Request, err error) {
	log.Error(w, r, err)
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func failWithStatus(w http.ResponseWriter, r *http.Request, status int, err error) {
	log.Error(w, r, err)
	http.Error(w, err.Error(), status)
}
