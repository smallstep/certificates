package authority

import (
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/ca-component/api"
	"gopkg.in/square/go-jose.v2/jwt"
)

type idUsed struct {
	UsedAt  int64  `json:"ua,omitempty"`
	Subject string `json:"sub,omitempty"`
}

var (
	validTokenAudience = []string{"https://ca/sign", "step-certificate-authority"}
)

func containsAtLeastOneAudience(claim []string, expected []string) bool {
	if len(expected) == 0 {
		return true
	}
	if len(claim) == 0 {
		return false
	}

	for _, exp := range expected {
		for _, cl := range claim {
			if exp == cl {
				return true
			}
		}
	}
	return false
}

// Authorize authorizes a signature request by validating and authenticating
// a OTT that must be sent w/ the request.
func (a *Authority) Authorize(ott string) ([]api.Claim, error) {
	var (
		errContext = map[string]interface{}{"ott": ott}
		claims     = jwt.Claims{}
		// Claims to check in the Sign method
		downstreamClaims []api.Claim
	)

	// Validate payload
	token, err := jwt.ParseSigned(ott)
	if err != nil {
		return nil, &apiError{errors.Wrapf(err, "error parsing OTT to JSONWebToken"),
			http.StatusUnauthorized, errContext}
	}

	kid := token.Headers[0].KeyID // JWT will only have 1 header.
	if len(kid) == 0 {
		return nil, &apiError{errors.New("keyID cannot be empty"),
			http.StatusUnauthorized, errContext}
	}
	val, ok := a.provisionerIDIndex.Load(kid)
	if !ok {
		return nil, &apiError{errors.Errorf("Provisioner with KeyID %s could not be found", kid),
			http.StatusUnauthorized, errContext}
	}
	p, ok := val.(*Provisioner)
	if !ok {
		return nil, &apiError{errors.Errorf("stored value is not a *Provisioner"),
			http.StatusInternalServerError, context{}}
	}

	if err = token.Claims(p.Key, &claims); err != nil {
		return nil, &apiError{err, http.StatusUnauthorized, errContext}
	}

	// According to "rfc7519 JSON Web Token" acceptable skew should be no
	// more than a few minutes.
	if err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer: p.Issuer,
	}, time.Minute); err != nil {
		return nil, &apiError{errors.Wrapf(err, "error validating OTT"),
			http.StatusUnauthorized, errContext}
	}

	if !containsAtLeastOneAudience(claims.Audience, validTokenAudience) {
		return nil, &apiError{errors.New("invalid audience"), http.StatusUnauthorized,
			errContext}
	}

	if claims.Subject == "" {
		return nil, &apiError{errors.New("OTT sub cannot be empty"),
			http.StatusUnauthorized, errContext}
	}
	downstreamClaims = append(downstreamClaims, &commonNameClaim{claims.Subject})
	downstreamClaims = append(downstreamClaims, &dnsNamesClaim{claims.Subject})
	downstreamClaims = append(downstreamClaims, &ipAddressesClaim{claims.Subject})

	// Store the token to protect against reuse.
	if _, ok := a.ottMap.LoadOrStore(claims.ID, &idUsed{
		UsedAt:  time.Now().Unix(),
		Subject: claims.Subject,
	}); ok {
		return nil, &apiError{errors.Errorf("token already used"), http.StatusUnauthorized,
			errContext}
	}

	return downstreamClaims, nil
}
