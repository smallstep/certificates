package authority

import (
	"net/http"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2/jwt"
)

type idUsed struct {
	UsedAt  int64  `json:"ua,omitempty"`
	Subject string `json:"sub,omitempty"`
}

// matchesOne returns true if A and B share at least one element.
func matchesOne(as, bs []string) bool {
	if len(bs) == 0 || len(as) == 0 {
		return false
	}

	for _, b := range bs {
		for _, a := range as {
			if b == a {
				return true
			}
		}
	}
	return false
}

// Authorize authorizes a signature request by validating and authenticating
// a OTT that must be sent w/ the request.
func (a *Authority) Authorize(ott string) ([]interface{}, error) {
	var (
		errContext = map[string]interface{}{"ott": ott}
		claims     = jwt.Claims{}
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

	if !matchesOne(claims.Audience, a.audiences) {
		return nil, &apiError{errors.New("authorize: token audience invalid"), http.StatusUnauthorized,
			errContext}
	}

	if claims.Subject == "" {
		return nil, &apiError{errors.New("authorize: token subject cannot be empty"),
			http.StatusUnauthorized, errContext}
	}

	signOps := []interface{}{
		&commonNameClaim{claims.Subject},
		&dnsNamesClaim{claims.Subject},
		&ipAddressesClaim{claims.Subject},
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
