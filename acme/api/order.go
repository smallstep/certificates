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
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"go.step.sm/crypto/randutil"
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
		if !(id.Type == acme.DNS || id.Type == acme.IP) {
			return acme.NewError(acme.ErrorMalformedType, "identifier type unsupported: %s", id.Type)
		}
		if id.Type == acme.IP && net.ParseIP(id.Value) == nil {
			return acme.NewError(acme.ErrorMalformedType, "invalid IP address: %s", id.Value)
		}
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
	csrBytes, err := base64.RawURLEncoding.DecodeString(f.CSR)
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
func (h *Handler) NewOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, err := accountFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	prov, err := provisionerFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	payload, err := payloadFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	var nor NewOrderRequest
	if err := json.Unmarshal(payload.value, &nor); err != nil {
		api.WriteError(w, acme.WrapError(acme.ErrorMalformedType, err,
			"failed to unmarshal new-order request payload"))
		return
	}

	if err := nor.Validate(); err != nil {
		api.WriteError(w, err)
		return
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
		if err := h.newAuthorization(ctx, az); err != nil {
			api.WriteError(w, err)
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

	if err := h.db.CreateOrder(ctx, o); err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error creating order"))
		return
	}

	h.linker.LinkOrder(ctx, o)

	w.Header().Set("Location", h.linker.GetLink(ctx, OrderLinkType, o.ID))
	api.JSONStatus(w, o, http.StatusCreated)
}

func (h *Handler) newAuthorization(ctx context.Context, az *acme.Authorization) error {
	if strings.HasPrefix(az.Identifier.Value, "*.") {
		az.Wildcard = true
		az.Identifier = acme.Identifier{
			Value: strings.TrimPrefix(az.Identifier.Value, "*."),
			Type:  az.Identifier.Type,
		}
	}

	chTypes := challengeTypes(az)

	var err error
	az.Token, err = randutil.Alphanumeric(32)
	if err != nil {
		return acme.WrapErrorISE(err, "error generating random alphanumeric ID")
	}
	az.Challenges = make([]*acme.Challenge, len(chTypes))
	for i, typ := range chTypes {
		ch := &acme.Challenge{
			AccountID: az.AccountID,
			Value:     az.Identifier.Value,
			Type:      typ,
			Token:     az.Token,
			Status:    acme.StatusPending,
		}
		if err := h.db.CreateChallenge(ctx, ch); err != nil {
			return acme.WrapErrorISE(err, "error creating challenge")
		}
		az.Challenges[i] = ch
	}
	if err = h.db.CreateAuthorization(ctx, az); err != nil {
		return acme.WrapErrorISE(err, "error creating authorization")
	}
	return nil
}

// GetOrder ACME api for retrieving an order.
func (h *Handler) GetOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, err := accountFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	prov, err := provisionerFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	o, err := h.db.GetOrder(ctx, chi.URLParam(r, "ordID"))
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error retrieving order"))
		return
	}
	if acc.ID != o.AccountID {
		api.WriteError(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own order '%s'", acc.ID, o.ID))
		return
	}
	if prov.GetID() != o.ProvisionerID {
		api.WriteError(w, acme.NewError(acme.ErrorUnauthorizedType,
			"provisioner '%s' does not own order '%s'", prov.GetID(), o.ID))
		return
	}
	if err = o.UpdateStatus(ctx, h.db); err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error updating order status"))
		return
	}

	h.linker.LinkOrder(ctx, o)

	w.Header().Set("Location", h.linker.GetLink(ctx, OrderLinkType, o.ID))
	api.JSON(w, o)
}

// FinalizeOrder attemptst to finalize an order and create a certificate.
func (h *Handler) FinalizeOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, err := accountFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	prov, err := provisionerFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	payload, err := payloadFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	var fr FinalizeRequest
	if err := json.Unmarshal(payload.value, &fr); err != nil {
		api.WriteError(w, acme.WrapError(acme.ErrorMalformedType, err,
			"failed to unmarshal finalize-order request payload"))
		return
	}
	if err := fr.Validate(); err != nil {
		api.WriteError(w, err)
		return
	}

	o, err := h.db.GetOrder(ctx, chi.URLParam(r, "ordID"))
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error retrieving order"))
		return
	}
	if acc.ID != o.AccountID {
		api.WriteError(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own order '%s'", acc.ID, o.ID))
		return
	}
	if prov.GetID() != o.ProvisionerID {
		api.WriteError(w, acme.NewError(acme.ErrorUnauthorizedType,
			"provisioner '%s' does not own order '%s'", prov.GetID(), o.ID))
		return
	}
	if err = o.Finalize(ctx, h.db, fr.csr, h.ca, prov); err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error finalizing order"))
		return
	}

	h.linker.LinkOrder(ctx, o)

	w.Header().Set("Location", h.linker.GetLink(ctx, OrderLinkType, o.ID))
	api.JSON(w, o)
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
	default:
		chTypes = []acme.ChallengeType{}
	}

	return chTypes
}
