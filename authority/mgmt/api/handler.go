package api

import (
	"time"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/config"
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
	db config.DB
}

// NewHandler returns a new Authority Config Handler.
func NewHandler(db config.DB) api.RouterHandler {
	return &Handler{
		db: ops.DB,
	}
}

// Route traffic and implement the Router interface.
func (h *Handler) Route(r api.Router) {
	// Provisioners
	r.MethodFunc("GET", "/provisioner/{id}", h.GetProvisioner)
	r.MethodFunc("GET", "/provisioners", h.GetProvisioners)
	r.MethodFunc("POST", "/provisioner", h.CreateProvisioner)
	r.MethodFunc("PUT", "/provsiioner/{id}", h.UpdateProvisioner)

	// Admins
	r.MethodFunc("GET", "/admin/{id}", h.GetAdmin)
	r.MethodFunc("GET", "/admins", h.GetAdmins)
	r.MethodFunc("POST", "/admin", h.CreateAdmin)
	r.MethodFunc("PUT", "/admin/{id}", h.UpdateAdmin)

	// AuthConfig
	r.MethodFunc("GET", "/authconfig/{id}", h.GetAuthConfig)
	r.MethodFunc("POST", "/authconfig", h.CreateAuthConfig)
	r.MethodFunc("PUT", "/authconfig/{id}", h.UpdateAuthConfig)
}
