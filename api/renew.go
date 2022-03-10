package api

import (
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	"github.com/smallstep/certificates/errs"
	"go.step.sm/crypto/jose"
)

const (
	authorizationHeader = "Authorization"
	bearerScheme        = "Bearer"
)

// Renew uses the information of certificate in the TLS connection to create a
// new one.
func (h *caHandler) Renew(w http.ResponseWriter, r *http.Request) {
	cert, err := h.getPeerCertificate(r)
	if err != nil {
		WriteError(w, err)
		return
	}

	certChain, err := h.Authority.Renew(cert)
	if err != nil {
		WriteError(w, errs.Wrap(http.StatusInternalServerError, err, "cahandler.Renew"))
		return
	}
	certChainPEM := certChainToPEM(certChain)
	var caPEM Certificate
	if len(certChainPEM) > 1 {
		caPEM = certChainPEM[1]
	}

	LogCertificate(w, certChain[0])
	JSONStatus(w, &SignResponse{
		ServerPEM:    certChainPEM[0],
		CaPEM:        caPEM,
		CertChainPEM: certChainPEM,
		TLSOptions:   h.Authority.GetTLSOptions(),
	}, http.StatusCreated)
}

func (h *caHandler) getPeerCertificate(r *http.Request) (*x509.Certificate, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0], nil
	}

	if s := r.Header.Get(authorizationHeader); s != "" {
		if parts := strings.SplitN(s, bearerScheme+" ", 2); len(parts) == 2 {
			roots, err := h.Authority.GetRoots()
			if err != nil {
				return nil, errs.BadRequestErr(err, "missing client certificate")
			}
			jwt, chain, err := jose.ParseX5cInsecure(parts[1], roots)
			if err != nil {
				return nil, errs.UnauthorizedErr(err, errs.WithMessage("error validating client certificate"))
			}

			var claims jose.Claims
			leaf := chain[0][0]
			if err := jwt.Claims(leaf.PublicKey, &claims); err != nil {
				return nil, errs.InternalServerErr(err, errs.WithMessage("error validating client certificate"))
			}

			// According to "rfc7519 JSON Web Token" acceptable skew should be no
			// more than a few minutes.
			if err = claims.ValidateWithLeeway(jose.Expected{
				Time: time.Now().UTC(),
			}, time.Minute); err != nil {
				return nil, errs.UnauthorizedErr(err, errs.WithMessage("error validating client certificate"))
			}

			return leaf, nil
		}
	}

	return nil, errs.BadRequest("missing client certificate")
}
