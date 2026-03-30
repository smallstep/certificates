package provisioner

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/smallstep/certificates/webhook"
	"go.step.sm/crypto/x509util"
)

var (
	ErrESTAuthMethodDisabled      = errors.New("est authentication method disabled")
	ErrESTAuthMethodNotFound      = errors.New("no valid est authentication method found")
	ErrESTAuthMethodMisconfigured = errors.New("est authentication method misconfigured")
	ErrESTAuthDenied              = errors.New("est authentication denied")
)

// ClientCertificateConfig holds the EST client certificate authentication configuration.
type ClientCertificateConfig struct {
	Enable                       bool
	ForwardedTLSClientCertHeader string
}

// ESTAuthRequest contains authentication material extracted from the request.
type ESTAuthRequest struct {
	CSR                    *x509.CertificateRequest
	ClientCertificate      *x509.Certificate
	ClientCertificateChain []*x509.Certificate
	CARoots                []*x509.Certificate
	CAIntermediates        []*x509.Certificate
	AuthenticationHeader   string
	BasicAuthUsername      string
	BasicAuthPassword      string
	BearerToken            string
}

func (s *EST) GetClientCertificateConfig() *ClientCertificateConfig {
	return &ClientCertificateConfig{
		Enable:                       boolValue(s.EnableTLSClientCertificate, false),
		ForwardedTLSClientCertHeader: s.ForwardedTLSClientCertHeader,
	}
}

// AuthorizeRequest validates the request against configured EST auth methods.
func (s *EST) AuthorizeRequest(ctx context.Context, req ESTAuthRequest) ([]SignCSROption, error) {
	if s.hasAuthWebhooks() {
		return s.authorizeWithWebhook(ctx, &req)
	}
	return s.authorizeRequestLocal(req)
}

// authorizeRequestLocal validates the request using provisioner configuration.
func (s *EST) authorizeRequestLocal(req ESTAuthRequest) ([]SignCSROption, error) {
	var lastErr error = ErrESTAuthMethodNotFound
	if req.ClientCertificate != nil {
		if boolValue(s.EnableTLSClientCertificate, false) {
			if s.hasClientCertificateRoots() {
				if err := verifyCertificateWithPool(req.ClientCertificate, req.ClientCertificateChain, s.clientCertificateRootPool, nil); err == nil {
					return []SignCSROption{}, nil
				} else {
					lastErr = err
				}
			} else {
				if err := verifyCertificate(req.ClientCertificate, req.ClientCertificateChain, req.CARoots, req.CAIntermediates); err == nil {
					return []SignCSROption{}, nil
				} else {
					lastErr = err
				}
			}
		} else {
			lastErr = ErrESTAuthMethodDisabled
		}
	}

	if req.hasBasicAuth() {
		if boolValue(s.EnableHTTPBasicAuth, false) && s.BasicAuthPassword != "" {
			if err := s.validateBasicAuthPassword(req.BasicAuthUsername, req.BasicAuthPassword); err == nil {
				return []SignCSROption{}, nil
			} else {
				lastErr = err
			}
		} else {
			lastErr = ErrESTAuthMethodDisabled
		}
	}

	return nil, lastErr
}

// validateBasicAuthPassword verifies the configured basic auth password.
func (s *EST) validateBasicAuthPassword(username, password string) error {
	if s.BasicAuthUsername != "" && username != s.BasicAuthUsername {
		return errors.New("invalid basic auth")
	}
	if subtleCompare(s.BasicAuthPassword, password) {
		return nil
	}
	return errors.New("invalid basic auth")
}

// authorizeWithWebhook executes configured webhooks for auth decisions.
func (s *EST) authorizeWithWebhook(ctx context.Context, req *ESTAuthRequest) ([]SignCSROption, error) {
	if !s.hasAuthWebhooks() {
		return nil, ErrESTAuthMethodMisconfigured
	}

	var (
		whreq *webhook.RequestBody
		err   error
	)
	switch {
	case req.ClientCertificate != nil:
		whreq, err = webhook.NewRequestBody(webhook.WithX509CertificateRequest(req.CSR), webhook.WithClientCertificate(req.ClientCertificate))
		if err != nil {
			return nil, fmt.Errorf("failed creating webhook request: %w", err)
		}
	case req.AuthenticationHeader != "":
		whreq, err = webhook.NewRequestBody(webhook.WithX509CertificateRequest(req.CSR), webhook.WithAuthenticationHeader(req.AuthenticationHeader))
		if err != nil {
			return nil, fmt.Errorf("failed creating webhook request: %w", err)
		}
		if req.BearerToken != "" {
			whreq.BearerToken = req.BearerToken
		}
	default:
		return nil, errors.New("missing certificate or basic auth for webhook validation")
	}
	whreq.ProvisionerName = s.Name
	var opts []SignCSROption

	for _, wh := range s.challengeValidationController.webhooks {
		resp, err := wh.DoWithContext(ctx, s.challengeValidationController.client, s.challengeValidationController.wrapTransport, whreq, nil)
		if err != nil {
			return nil, fmt.Errorf("failed executing webhook request: %w", err)
		}
		if resp.Allow {
			opts = append(opts, TemplateDataModifierFunc(func(data x509util.TemplateData) {
				data.SetWebhook(wh.Name, resp.Data)
			}))
		}
	}

	if len(opts) == 0 {
		return nil, ErrESTAuthDenied
	}

	return opts, nil
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
	enable := true
	if !s.authMethodsConfigured() {
		s.EnableHTTPBasicAuth = &enable
	}
	if s.EnableHTTPBasicAuth == nil && (s.BasicAuthUsername != "" || s.BasicAuthPassword != "") {
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
