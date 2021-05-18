package api

import (
	"time"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/mgmt"
)

// Clock that returns time in UTC rounded to seconds.
type Clock struct{}

// Now returns the UTC time rounded to seconds.
func (c *Clock) Now() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

var clock Clock

// Handler is the ACME API request handler.
type Handler struct {
	db   mgmt.DB
	auth *authority.Authority
}

// NewHandler returns a new Authority Config Handler.
func NewHandler(db mgmt.DB, auth *authority.Authority) api.RouterHandler {
	return &Handler{db, auth}
}

// Route traffic and implement the Router interface.
func (h *Handler) Route(r api.Router) {
	// Provisioners
	r.MethodFunc("GET", "/provisioner/{name}", h.GetProvisioner)
	r.MethodFunc("GET", "/provisioners", h.GetProvisioners)
	r.MethodFunc("POST", "/provisioner", h.CreateProvisioner)
	r.MethodFunc("PUT", "/provisioner/{name}", h.UpdateProvisioner)
	r.MethodFunc("DELETE", "/provisioner/{name}", h.DeleteProvisioner)

	// Admins
	r.MethodFunc("GET", "/admin/{id}", h.GetAdmin)
	r.MethodFunc("GET", "/admins", h.GetAdmins)
	r.MethodFunc("POST", "/admin", h.CreateAdmin)
	r.MethodFunc("PATCH", "/admin/{id}", h.UpdateAdmin)
	r.MethodFunc("DELETE", "/admin/{id}", h.DeleteAdmin)

	// AuthConfig
	r.MethodFunc("GET", "/authconfig/{id}", h.GetAuthConfig)
	r.MethodFunc("PUT", "/authconfig/{id}", h.UpdateAuthConfig)
}
