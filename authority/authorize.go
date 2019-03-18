package authority

import (
	"crypto/x509"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/jose"
)

type idUsed struct {
	UsedAt  int64  `json:"ua,omitempty"`
	Subject string `json:"sub,omitempty"`
}

// Claims extends jose.Claims with step attributes.
type Claims struct {
	jose.Claims
	SANs  []string `json:"sans,omitempty"`
	Email string   `json:"email,omitempty"`
	Nonce string   `json:"nonce,omitempty"`
}

// Authorize authorizes a signature request by validating and authenticating
// a OTT that must be sent w/ the request.
func (a *Authority) Authorize(ott string) ([]provisioner.SignOption, error) {
	var errContext = map[string]interface{}{"ott": ott}

	// Validate payload
	token, err := jose.ParseSigned(ott)
	if err != nil {
		return nil, &apiError{errors.Wrapf(err, "authorize: error parsing token"),
			http.StatusUnauthorized, errContext}
	}

	// Get claims w/out verification. We need to look up the provisioner
	// key in order to verify the claims and we need the issuer from the claims
	// before we can look up the provisioner.
	var claims Claims
	if err = token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, &apiError{err, http.StatusUnauthorized, errContext}
	}

	// Do not accept tokens issued before the start of the ca.
	// This check is meant as a stopgap solution to the current lack of a persistence layer.
	if a.config.AuthorityConfig != nil && !a.config.AuthorityConfig.DisableIssuedAtCheck {
		if claims.IssuedAt > 0 && claims.IssuedAt.Time().Before(a.startTime) {
			return nil, &apiError{errors.New("authorize: token issued before the bootstrap of certificate authority"),
				http.StatusUnauthorized, errContext}
		}
	}

	// This method will also validate the audiences for JWK provisioners.
	p, ok := a.provisioners.LoadByToken(token, &claims.Claims)
	if !ok {
		return nil, &apiError{errors.Errorf("authorize: provisioner not found or invalid audience %s", claims.Audience),
			http.StatusUnauthorized, errContext}
	}

	// Store the token to protect against reuse.
	var reuseKey string
	switch p.GetType() {
	case provisioner.TypeJWK:
		reuseKey = claims.ID
	case provisioner.TypeOIDC:
		reuseKey = claims.Nonce
	}
	if reuseKey != "" {
		if _, ok := a.ottMap.LoadOrStore(reuseKey, &idUsed{
			UsedAt:  time.Now().Unix(),
			Subject: claims.Subject,
		}); ok {
			return nil, &apiError{errors.Errorf("authorize: token already used"), http.StatusUnauthorized, errContext}
		}
	}

	// Call the provisioner Authorize method to get the signing options
	opts, err := p.Authorize(ott)
	if err != nil {
		return nil, &apiError{errors.Wrap(err, "authorize"), http.StatusUnauthorized, errContext}
	}

	return opts, nil
}

// authorizeRenewal tries to locate the step provisioner extension, and checks
// if for the configured provisioner, the renewal is enabled or not. If the
// extra extension cannot be found, authorize the renewal by default.
//
// TODO(mariano): should we authorize by default?
func (a *Authority) authorizeRenewal(crt *x509.Certificate) error {
	errContext := map[string]interface{}{"serialNumber": crt.SerialNumber.String()}
	p, ok := a.provisioners.LoadByCertificate(crt)
	if !ok {
		return &apiError{
			err:     errors.New("provisioner not found"),
			code:    http.StatusUnauthorized,
			context: errContext,
		}
	}
	if err := p.AuthorizeRenewal(crt); err != nil {
		return &apiError{
			err:     err,
			code:    http.StatusUnauthorized,
			context: errContext,
		}
	}
	return nil
}
