package api

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"

	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/policy"
	"github.com/smallstep/certificates/authority/provisioner"
)

// NewOrderRequest represents the body for a NewOrder request.
type NewOrderRequest struct {
	Identifiers []acme.Identifier `json:"identifiers"`
	NotBefore   time.Time         `json:"notBefore,omitempty"`
	NotAfter    time.Time         `json:"notAfter,omitempty"`
}

// Validate validates a new-order request body.
func (n *NewOrderRequest) Validate() error {
	if len(n.Identifiers) == 0 {
		return acme.NewError(acme.ErrorMalformedType, "identifiers list cannot be empty")
	}
	for _, id := range n.Identifiers {
		switch id.Type {
		case acme.IP:
			if net.ParseIP(id.Value) == nil {
				return acme.NewError(acme.ErrorMalformedType, "invalid IP address: %s", id.Value)
			}
		case acme.DNS:
			value, _ := trimIfWildcard(id.Value)
			if _, err := x509util.SanitizeName(value); err != nil {
				return acme.NewError(acme.ErrorMalformedType, "invalid DNS name: %s", id.Value)
			}
		case acme.PermanentIdentifier:
			if id.Value == "" {
				return acme.NewError(acme.ErrorMalformedType, "permanent identifier cannot be empty")
			}
		default:
			return acme.NewError(acme.ErrorMalformedType, "identifier type unsupported: %s", id.Type)
		}

		// TODO(hs): add some validations for DNS domains?
		// TODO(hs): combine the errors from this with allow/deny policy, like example error in https://datatracker.ietf.org/doc/html/rfc8555#section-6.7.1
	}
	return nil
}

// FinalizeRequest captures the body for a Finalize order request.
type FinalizeRequest struct {
	CSR string `json:"csr"`
	csr *x509.CertificateRequest
}

// Validate validates a finalize request body.
func (f *FinalizeRequest) Validate() error {
	var err error
	// RFC 8555 isn't 100% conclusive about using raw base64-url encoding for the
	// CSR specifically, instead of "normal" base64-url encoding (incl. padding).
	// By trimming the padding from CSRs submitted by ACME clients that use
	// base64-url encoding instead of raw base64-url encoding, these are also
	// supported. This was reported in https://github.com/smallstep/certificates/issues/939
	// to be the case for a Synology DSM NAS system.
	csrBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(f.CSR, "="))
	if err != nil {
		return acme.WrapError(acme.ErrorMalformedType, err, "error base64url decoding csr")
	}
	f.csr, err = x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return acme.WrapError(acme.ErrorMalformedType, err, "unable to parse csr")
	}
	if err = f.csr.CheckSignature(); err != nil {
		return acme.WrapError(acme.ErrorMalformedType, err, "csr failed signature check")
	}
	return nil
}

var defaultOrderExpiry = time.Hour * 24
var defaultOrderBackdate = time.Minute

// NewOrder ACME api for creating a new order.
func NewOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ca := mustAuthority(ctx)
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	prov, err := provisionerFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	payload, err := payloadFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	var nor NewOrderRequest
	if err := json.Unmarshal(payload.value, &nor); err != nil {
		render.Error(w, acme.WrapError(acme.ErrorMalformedType, err,
			"failed to unmarshal new-order request payload"))
		return
	}

	if err := nor.Validate(); err != nil {
		render.Error(w, err)
		return
	}

	// TODO(hs): gather all errors, so that we can build one response with ACME subproblems
	// include the nor.Validate() error here too, like in the example in the ACME RFC?

	acmeProv, err := acmeProvisionerFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	var eak *acme.ExternalAccountKey
	if acmeProv.RequireEAB {
		if eak, err = db.GetExternalAccountKeyByAccountID(ctx, prov.GetID(), acc.ID); err != nil {
			render.Error(w, acme.WrapErrorISE(err, "error retrieving external account binding key"))
			return
		}
	}

	acmePolicy, err := newACMEPolicyEngine(eak)
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error creating ACME policy engine"))
		return
	}

	for _, identifier := range nor.Identifiers {
		// evaluate the ACME account level policy
		if err = isIdentifierAllowed(acmePolicy, identifier); err != nil {
			render.Error(w, acme.WrapError(acme.ErrorRejectedIdentifierType, err, "not authorized"))
			return
		}
		// evaluate the provisioner level policy
		orderIdentifier := provisioner.ACMEIdentifier{Type: provisioner.ACMEIdentifierType(identifier.Type), Value: identifier.Value}
		if err = prov.AuthorizeOrderIdentifier(ctx, orderIdentifier); err != nil {
			render.Error(w, acme.WrapError(acme.ErrorRejectedIdentifierType, err, "not authorized"))
			return
		}
		// evaluate the authority level policy
		if err = ca.AreSANsAllowed(ctx, []string{identifier.Value}); err != nil {
			render.Error(w, acme.WrapError(acme.ErrorRejectedIdentifierType, err, "not authorized"))
			return
		}
	}

	now := clock.Now()
	// New order.
	o := &acme.Order{
		AccountID:        acc.ID,
		ProvisionerID:    prov.GetID(),
		Status:           acme.StatusPending,
		Identifiers:      nor.Identifiers,
		ExpiresAt:        now.Add(defaultOrderExpiry),
		AuthorizationIDs: make([]string, len(nor.Identifiers)),
		NotBefore:        nor.NotBefore,
		NotAfter:         nor.NotAfter,
	}

	for i, identifier := range o.Identifiers {
		az := &acme.Authorization{
			AccountID:  acc.ID,
			Identifier: identifier,
			ExpiresAt:  o.ExpiresAt,
			Status:     acme.StatusPending,
		}
		if err := newAuthorization(ctx, az); err != nil {
			render.Error(w, err)
			return
		}
		o.AuthorizationIDs[i] = az.ID
	}

	if o.NotBefore.IsZero() {
		o.NotBefore = now
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = o.NotBefore.Add(prov.DefaultTLSCertDuration())
	}
	// If request NotBefore was empty then backdate the order.NotBefore (now)
	// to avoid timing issues.
	if nor.NotBefore.IsZero() {
		o.NotBefore = o.NotBefore.Add(-defaultOrderBackdate)
	}

	if err := db.CreateOrder(ctx, o); err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error creating order"))
		return
	}

	linker.LinkOrder(ctx, o)

	w.Header().Set("Location", linker.GetLink(ctx, acme.OrderLinkType, o.ID))
	render.JSONStatus(w, o, http.StatusCreated)
}

func isIdentifierAllowed(acmePolicy policy.X509Policy, identifier acme.Identifier) error {
	if acmePolicy == nil {
		return nil
	}
	return acmePolicy.AreSANsAllowed([]string{identifier.Value})
}

func newACMEPolicyEngine(eak *acme.ExternalAccountKey) (policy.X509Policy, error) {
	if eak == nil {
		return nil, nil
	}
	return policy.NewX509PolicyEngine(eak.Policy)
}

func trimIfWildcard(value string) (string, bool) {
	if strings.HasPrefix(value, "*.") {
		return strings.TrimPrefix(value, "*."), true
	}
	return value, false
}

func newAuthorization(ctx context.Context, az *acme.Authorization) error {
	value, isWildcard := trimIfWildcard(az.Identifier.Value)
	az.Wildcard = isWildcard
	az.Identifier = acme.Identifier{
		Value: value,
		Type:  az.Identifier.Type,
	}

	chTypes := challengeTypes(az)

	var err error
	az.Token, err = randutil.Alphanumeric(32)
	if err != nil {
		return acme.WrapErrorISE(err, "error generating random alphanumeric ID")
	}

	db := acme.MustDatabaseFromContext(ctx)
	prov := acme.MustProvisionerFromContext(ctx)
	az.Challenges = make([]*acme.Challenge, 0, len(chTypes))
	for _, typ := range chTypes {
		if !prov.IsChallengeEnabled(ctx, provisioner.ACMEChallenge(typ)) {
			continue
		}

		ch := &acme.Challenge{
			AccountID: az.AccountID,
			Value:     az.Identifier.Value,
			Type:      typ,
			Token:     az.Token,
			Status:    acme.StatusPending,
		}
		if err := db.CreateChallenge(ctx, ch); err != nil {
			return acme.WrapErrorISE(err, "error creating challenge")
		}
		az.Challenges = append(az.Challenges, ch)
	}
	if err = db.CreateAuthorization(ctx, az); err != nil {
		return acme.WrapErrorISE(err, "error creating authorization")
	}
	return nil
}

// GetOrder ACME api for retrieving an order.
func GetOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	prov, err := provisionerFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	o, err := db.GetOrder(ctx, chi.URLParam(r, "ordID"))
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving order"))
		return
	}
	if acc.ID != o.AccountID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own order '%s'", acc.ID, o.ID))
		return
	}
	if prov.GetID() != o.ProvisionerID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"provisioner '%s' does not own order '%s'", prov.GetID(), o.ID))
		return
	}
	if err = o.UpdateStatus(ctx, db); err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error updating order status"))
		return
	}

	linker.LinkOrder(ctx, o)

	w.Header().Set("Location", linker.GetLink(ctx, acme.OrderLinkType, o.ID))
	render.JSON(w, o)
}

// FinalizeOrder attempts to finalize an order and create a certificate.
func FinalizeOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	prov, err := provisionerFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	payload, err := payloadFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	var fr FinalizeRequest
	if err := json.Unmarshal(payload.value, &fr); err != nil {
		render.Error(w, acme.WrapError(acme.ErrorMalformedType, err,
			"failed to unmarshal finalize-order request payload"))
		return
	}
	if err := fr.Validate(); err != nil {
		render.Error(w, err)
		return
	}

	o, err := db.GetOrder(ctx, chi.URLParam(r, "ordID"))
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving order"))
		return
	}
	if acc.ID != o.AccountID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own order '%s'", acc.ID, o.ID))
		return
	}
	if prov.GetID() != o.ProvisionerID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"provisioner '%s' does not own order '%s'", prov.GetID(), o.ID))
		return
	}

	ca := mustAuthority(ctx)
	if err = o.Finalize(ctx, db, fr.csr, ca, prov); err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error finalizing order"))
		return
	}

	linker.LinkOrder(ctx, o)

	w.Header().Set("Location", linker.GetLink(ctx, acme.OrderLinkType, o.ID))
	render.JSON(w, o)
}

// challengeTypes determines the types of challenges that should be used
// for the ACME authorization request.
func challengeTypes(az *acme.Authorization) []acme.ChallengeType {
	var chTypes []acme.ChallengeType

	switch az.Identifier.Type {
	case acme.IP:
		chTypes = []acme.ChallengeType{acme.HTTP01, acme.TLSALPN01}
	case acme.DNS:
		chTypes = []acme.ChallengeType{acme.DNS01}
		// HTTP and TLS challenges can only be used for identifiers without wildcards.
		if !az.Wildcard {
			chTypes = append(chTypes, []acme.ChallengeType{acme.HTTP01, acme.TLSALPN01}...)
		}
	case acme.PermanentIdentifier:
		chTypes = []acme.ChallengeType{acme.DEVICEATTEST01}
	default:
		chTypes = []acme.ChallengeType{}
	}

	return chTypes
}
