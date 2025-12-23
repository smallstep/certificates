package provisioner

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/smallstep/certificates/webhook"
)

var (
	ErrESTAuthMethodDisabled = errors.New("est authentication method disabled")
	ErrESTAuthDenied         = errors.New("est authentication denied")
)

// ESTAuthMethod identifies the EST authentication method used.
type ESTAuthMethod string

const (
	ESTAuthMethodTLSClientCertificate         ESTAuthMethod = "tls-client-certificate"
	ESTAuthMethodTLSExternalClientCertificate ESTAuthMethod = "tls-external-client-certificate"
	ESTAuthMethodHTTPBasicAuth                ESTAuthMethod = "http-basic-auth"
)

// ESTAuthRequest contains authentication material extracted from the request.
type ESTAuthRequest struct {
	CSR                    *x509.CertificateRequest
	ClientCertificate      *x509.Certificate
	ClientCertificateChain []*x509.Certificate
	CARoots                []*x509.Certificate
	CAIntermediates        []*x509.Certificate
	BasicAuthUsername      string
	BasicAuthPassword      string
}

// AuthorizeRequest validates the request against configured EST auth methods.
func (s *EST) AuthorizeRequest(ctx context.Context, req ESTAuthRequest) (ESTAuthMethod, error) {
	if s.hasAuthWebhooks() {
		return s.authorizeRequestWithWebhook(ctx, req)
	}
	return s.authorizeRequestLocal(ctx, req)
}

// AuthorizeTLSClientCertificate validates a CA-issued client certificate.
func (s *EST) AuthorizeTLSClientCertificate(ctx context.Context, cert *x509.Certificate, chain, roots, intermediates []*x509.Certificate) error {
	method, err := s.AuthorizeRequest(ctx, ESTAuthRequest{
		ClientCertificate:      cert,
		ClientCertificateChain: chain,
		CARoots:                roots,
		CAIntermediates:        intermediates,
	})
	if err != nil {
		return err
	}
	if method != ESTAuthMethodTLSClientCertificate {
		return ErrESTAuthDenied
	}
	return nil
}

// AuthorizeTLSExternalClientCertificate validates a client certificate against external roots.
func (s *EST) AuthorizeTLSExternalClientCertificate(ctx context.Context, cert *x509.Certificate, chain []*x509.Certificate) error {
	method, err := s.AuthorizeRequest(ctx, ESTAuthRequest{
		ClientCertificate:      cert,
		ClientCertificateChain: chain,
	})
	if err != nil {
		return err
	}
	if method != ESTAuthMethodTLSExternalClientCertificate {
		return ErrESTAuthDenied
	}
	return nil
}

// AuthorizeHTTPBasicAuth validates a username/password pair for EST.
func (s *EST) AuthorizeHTTPBasicAuth(ctx context.Context, csr *x509.CertificateRequest, username, password string) error {
	method, err := s.AuthorizeRequest(ctx, ESTAuthRequest{
		CSR:               csr,
		BasicAuthUsername: username,
		BasicAuthPassword: password,
	})
	if err != nil {
		return err
	}
	if method != ESTAuthMethodHTTPBasicAuth {
		return ErrESTAuthDenied
	}
	return nil
}

// authorizeRequestWithWebhook delegates authentication to EST webhooks.
func (s *EST) authorizeRequestWithWebhook(ctx context.Context, req ESTAuthRequest) (ESTAuthMethod, error) {
	if req.ClientCertificate != nil {
		method, err := s.preferredCertAuthMethod()
		if err != nil {
			return "", err
		}
		if err := s.authorizeWithWebhook(ctx, req.ClientCertificate, req.CSR, ""); err != nil {
			return "", err
		}
		return method, nil
	}

	if req.hasBasicAuth() {
		method, err := s.preferredBasicAuthMethod()
		if err != nil {
			return "", err
		}
		if method == ESTAuthMethodHTTPBasicAuth {
			if req.BasicAuthPassword == "" {
				return "", errors.New("missing basic auth credentials")
			}
		}
		if req.CSR == nil {
			return "", errors.New("missing CSR for basic auth validation")
		}
		opts := []webhook.RequestBodyOption{}
		if req.BasicAuthUsername != "" {
			opts = append(opts, webhook.WithAuthorizationPrincipal(req.BasicAuthUsername))
		}
		if err := s.authorizeWithWebhook(ctx, nil, req.CSR, req.BasicAuthPassword, opts...); err != nil {
			return "", err
		}
		return method, nil
	}

	return "", errors.New("missing client certificate or basic auth")
}

// authorizeRequestLocal validates the request using provisioner configuration.
func (s *EST) authorizeRequestLocal(ctx context.Context, req ESTAuthRequest) (ESTAuthMethod, error) {
	if req.ClientCertificate != nil {
		var lastErr error
		if boolValue(s.EnableTLSClientCertificate, false) {
			if err := verifyCertificate(req.ClientCertificate, req.ClientCertificateChain, req.CARoots, req.CAIntermediates); err == nil {
				return ESTAuthMethodTLSClientCertificate, nil
			} else {
				lastErr = err
			}
		}
		if s.hasClientCertificateRoots() {
			if s.clientCertificateRootPool == nil {
				lastErr = ErrESTAuthMethodDisabled
			} else if err := verifyCertificateWithPool(req.ClientCertificate, req.ClientCertificateChain, s.clientCertificateRootPool, nil); err == nil {
				return ESTAuthMethodTLSExternalClientCertificate, nil
			} else {
				lastErr = err
			}
		}
		if lastErr != nil {
			return "", lastErr
		}
		return "", ErrESTAuthMethodDisabled
	}

	if req.hasBasicAuth() {
		if boolValue(s.EnableHTTPBasicAuth, false) {
			if req.BasicAuthPassword == "" {
				return "", errors.New("missing basic auth credentials")
			}
			if s.BasicAuthUsername != "" && req.BasicAuthUsername != s.BasicAuthUsername {
				return "", errors.New("invalid basic auth username")
			}
			if err := s.validateBasicAuthPassword(req.BasicAuthPassword); err != nil {
				return "", err
			}
			return ESTAuthMethodHTTPBasicAuth, nil
		}
		return "", ErrESTAuthMethodDisabled
	}

	return "", errors.New("missing client certificate or basic auth")
}

// preferredCertAuthMethod selects the enabled certificate-based auth method.
func (s *EST) preferredCertAuthMethod() (ESTAuthMethod, error) {
	switch {
	case boolValue(s.EnableTLSClientCertificate, false):
		return ESTAuthMethodTLSClientCertificate, nil
	case s.hasClientCertificateRoots():
		return ESTAuthMethodTLSExternalClientCertificate, nil
	default:
		return "", ErrESTAuthMethodDisabled
	}
}

// preferredBasicAuthMethod selects the enabled basic-auth-based method.
func (s *EST) preferredBasicAuthMethod() (ESTAuthMethod, error) {
	switch {
	case boolValue(s.EnableHTTPBasicAuth, false):
		return ESTAuthMethodHTTPBasicAuth, nil
	default:
		return "", ErrESTAuthMethodDisabled
	}
}

// validateBasicAuthPassword verifies the configured basic auth password.
func (s *EST) validateBasicAuthPassword(password string) error {
	if s.BasicAuthPassword == "" {
		return errors.New("basic auth password is not configured")
	}
	if subtleCompare(s.BasicAuthPassword, password) {
		return nil
	}
	return errors.New("invalid basic auth password")
}

// authorizeWithWebhook executes configured webhooks for auth decisions.
func (s *EST) authorizeWithWebhook(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, secret string, opts ...webhook.RequestBodyOption) error {
	if !s.hasAuthWebhooks() {
		return nil
	}

	var (
		req *webhook.RequestBody
		err error
	)
	switch {
	case cert != nil:
		req, err = webhook.NewRequestBody(append(opts, webhook.WithX509Certificate(nil, cert))...)
		if err != nil {
			return fmt.Errorf("failed creating webhook request: %w", err)
		}
		if req.X509Certificate != nil {
			req.X509Certificate.Raw = cert.Raw
		}
	case csr != nil:
		req, err = webhook.NewRequestBody(append(opts, webhook.WithX509CertificateRequest(csr))...)
		if err != nil {
			return fmt.Errorf("failed creating webhook request: %w", err)
		}
	default:
		return errors.New("missing certificate or CSR for webhook validation")
	}

	req.ProvisionerName = s.Name
	if secret != "" {
		// TODO: change this to add a dedicated field in the webhook request body (or rename it but can broken existing webhooks)
		req.SCEPChallenge = secret
	}

	for _, wh := range s.challengeValidationController.webhooks {
		resp, err := wh.DoWithContext(ctx, s.challengeValidationController.client, s.challengeValidationController.wrapTransport, req, nil)
		if err != nil {
			return fmt.Errorf("failed executing webhook request: %w", err)
		}
		if resp.Allow {
			return nil
		}
	}

	return ErrESTAuthDenied
}

// hasBasicAuth reports whether any basic auth data is present.
func (r ESTAuthRequest) hasBasicAuth() bool {
	return r.BasicAuthUsername != "" || r.BasicAuthPassword != ""
}

// hasAuthWebhooks reports whether auth webhooks are configured.
func (s *EST) hasAuthWebhooks() bool {
	return s.challengeValidationController != nil && len(s.challengeValidationController.webhooks) > 0
}

// normalizeAuthConfig applies defaults and validates auth configuration.
func (s *EST) normalizeAuthConfig() error {
	if !s.authMethodsConfigured() {
		enable := true
		s.EnableHTTPBasicAuth = &enable
	}
	if s.EnableHTTPBasicAuth == nil && (s.BasicAuthUsername != "" || s.BasicAuthPassword != "") {
		enable := true
		s.EnableHTTPBasicAuth = &enable
	}
	if boolValue(s.EnableHTTPBasicAuth, false) && s.BasicAuthPassword == "" && !s.hasAuthWebhooks() {
		return errors.New("basic auth password cannot be empty")
	}
	return nil
}

// authMethodsConfigured reports whether any auth method is explicitly configured.
func (s *EST) authMethodsConfigured() bool {
	return s.EnableTLSClientCertificate != nil ||
		s.hasClientCertificateRoots() ||
		s.EnableHTTPBasicAuth != nil
}

// parseClientCertificateRoots loads external client certificate roots.
func (s *EST) parseClientCertificateRoots() error {
	if len(s.ClientCertificateRoots) == 0 {
		return nil
	}
	var (
		block   *pem.Block
		hasCert bool
		rest    = s.ClientCertificateRoots
	)
	s.clientCertificateRootPool = x509.NewCertPool()
	for rest != nil {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.New("error parsing clientCertificateRoots: malformed certificate")
		}
		s.clientCertificateRootPool.AddCert(cert)
		hasCert = true
	}
	if !hasCert {
		return errors.New("error parsing clientCertificateRoots: no certificates found")
	}
	return nil
}

func (s *EST) hasClientCertificateRoots() bool {
	return len(s.ClientCertificateRoots) > 0
}

// verifyCertificate validates the client certificate against CA roots.
func verifyCertificate(cert *x509.Certificate, chain, roots, intermediates []*x509.Certificate) error {
	rootPool := x509.NewCertPool()
	for _, root := range roots {
		if root != nil {
			rootPool.AddCert(root)
		}
	}
	intermediatePool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		if intermediate != nil {
			intermediatePool.AddCert(intermediate)
		}
	}
	return verifyCertificateWithPool(cert, chain, rootPool, intermediatePool)
}

// verifyCertificateWithPool validates the client certificate using explicit pools.
func verifyCertificateWithPool(cert *x509.Certificate, chain []*x509.Certificate, roots, intermediates *x509.CertPool) error {
	if intermediates == nil {
		intermediates = x509.NewCertPool()
	}
	for i, intermediate := range chain {
		if i == 0 || intermediate == nil {
			continue
		}
		intermediates.AddCert(intermediate)
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("invalid client certificate: %w", err)
	}
	return nil
}

// boolValue returns the dereferenced value or a default.
func boolValue(value *bool, defaultValue bool) bool {
	if value == nil {
		return defaultValue
	}
	return *value
}

// subtleCompare compares secrets in constant time.
func subtleCompare(expected, actual string) bool {
	if len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}
