package authority

import (
	"crypto/x509"
	"encoding/asn1"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/x509util"
	"gopkg.in/square/go-jose.v2/jwt"
)

type idUsed struct {
	UsedAt  int64  `json:"ua,omitempty"`
	Subject string `json:"sub,omitempty"`
}

// Claims extends jwt.Claims with step attributes.
type Claims struct {
	jwt.Claims
	SANs []string `json:"sans,omitempty"`
}

// matchesAudience returns true if A and B share at least one element.
func matchesAudience(as, bs []string) bool {
	if len(bs) == 0 || len(as) == 0 {
		return false
	}

	for _, b := range bs {
		for _, a := range as {
			if b == a || stripPort(a) == stripPort(b) {
				return true
			}
		}
	}
	return false
}

// stripPort attempts to strip the port from the given url. If parsing the url
// produces errors it will just return the passed argument.
func stripPort(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	u.Host = u.Hostname()
	return u.String()
}

// Authorize authorizes a signature request by validating and authenticating
// a OTT that must be sent w/ the request.
func (a *Authority) Authorize(ott string) ([]interface{}, error) {
	var (
		errContext = map[string]interface{}{"ott": ott}
		claims     = Claims{}
	)

	// Validate payload
	token, err := jwt.ParseSigned(ott)
	if err != nil {
		return nil, &apiError{errors.Wrapf(err, "authorize: error parsing token"),
			http.StatusUnauthorized, errContext}
	}

	// Get claims w/out verification. We need to look up the provisioner
	// key in order to verify the claims and we need the issuer from the claims
	// before we can look up the provisioner.
	if err = token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, &apiError{err, http.StatusUnauthorized, errContext}
	}
	kid := token.Headers[0].KeyID // JWT will only have 1 header.
	if len(kid) == 0 {
		return nil, &apiError{errors.New("authorize: token KeyID cannot be empty"),
			http.StatusUnauthorized, errContext}
	}
	pid := claims.Issuer + ":" + kid
	val, ok := a.provisionerIDIndex.Load(pid)
	if !ok {
		return nil, &apiError{errors.Errorf("authorize: provisioner with id %s not found", pid),
			http.StatusUnauthorized, errContext}
	}
	p, ok := val.(*Provisioner)
	if !ok {
		return nil, &apiError{errors.Errorf("authorize: invalid provisioner type"),
			http.StatusInternalServerError, errContext}
	}

	if err = token.Claims(p.Key, &claims); err != nil {
		return nil, &apiError{err, http.StatusUnauthorized, errContext}
	}

	// According to "rfc7519 JSON Web Token" acceptable skew should be no
	// more than a few minutes.
	if err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer: p.Name,
	}, time.Minute); err != nil {
		return nil, &apiError{errors.Wrapf(err, "authorize: invalid token"),
			http.StatusUnauthorized, errContext}
	}

	// Do not accept tokens issued before the start of the ca.
	// This check is meant as a stopgap solution to the current lack of a persistence layer.
	if a.config.AuthorityConfig != nil && !a.config.AuthorityConfig.DisableIssuedAtCheck {
		if claims.IssuedAt > 0 && claims.IssuedAt.Time().Before(a.startTime) {
			return nil, &apiError{errors.New("token issued before the bootstrap of certificate authority"),
				http.StatusUnauthorized, errContext}
		}
	}

	if !matchesAudience(claims.Audience, a.audiences) {
		return nil, &apiError{errors.New("authorize: token audience invalid"), http.StatusUnauthorized,
			errContext}
	}

	if claims.Subject == "" {
		return nil, &apiError{errors.New("authorize: token subject cannot be empty"),
			http.StatusUnauthorized, errContext}
	}

	// NOTE: This is for backwards compatibility with older versions of cli
	// and certificates. Older versions added the token subject as the only SAN
	// in a CSR by default.
	if len(claims.SANs) == 0 {
		claims.SANs = []string{claims.Subject}
	}
	dnsNames, ips := x509util.SplitSANs(claims.SANs)
	if err != nil {
		return nil, err
	}

	signOps := []interface{}{
		&commonNameClaim{claims.Subject},
		&dnsNamesClaim{dnsNames},
		&ipAddressesClaim{ips},
		p,
	}

	// Store the token to protect against reuse.
	if _, ok := a.ottMap.LoadOrStore(claims.ID, &idUsed{
		UsedAt:  time.Now().Unix(),
		Subject: claims.Subject,
	}); ok {
		return nil, &apiError{errors.Errorf("token already used"), http.StatusUnauthorized,
			errContext}
	}

	return signOps, nil
}

// authorizeRenewal tries to locate the step provisioner extension, and checks
// if for the configured provisioner, the renewal is enabled or not. If the
// extra extension cannot be found, authorize the renewal by default.
//
// TODO(mariano): should we authorize by default?
func (a *Authority) authorizeRenewal(crt *x509.Certificate) error {
	errContext := map[string]interface{}{"serialNumber": crt.SerialNumber.String()}
	for _, e := range crt.Extensions {
		if e.Id.Equal(stepOIDProvisioner) {
			var provisioner stepProvisionerASN1
			if _, err := asn1.Unmarshal(e.Value, &provisioner); err != nil {
				return &apiError{
					err:     errors.Wrap(err, "error decoding step provisioner extension"),
					code:    http.StatusInternalServerError,
					context: errContext,
				}
			}

			// Look for the provisioner, if it cannot be found, renewal will not
			// be authorized.
			pid := string(provisioner.Name) + ":" + string(provisioner.CredentialID)
			val, ok := a.provisionerIDIndex.Load(pid)
			if !ok {
				return &apiError{
					err:     errors.Errorf("not found: provisioner %s", pid),
					code:    http.StatusUnauthorized,
					context: errContext,
				}
			}
			p, ok := val.(*Provisioner)
			if !ok {
				return &apiError{
					err:     errors.Errorf("invalid type: provisioner %s, type %T", pid, val),
					code:    http.StatusInternalServerError,
					context: errContext,
				}
			}
			if p.Claims.IsDisableRenewal() {
				return &apiError{
					err:     errors.Errorf("renew disabled: provisioner %s", pid),
					code:    http.StatusUnauthorized,
					context: errContext,
				}
			}
			return nil
		}
	}

	return nil
}
