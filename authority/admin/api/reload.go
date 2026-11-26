package api

import (
	"net/http"

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/linkedca"
)

// ReloadAdminResourcesResponse is returned after the instance has refreshed its
// in-memory provisioner and administrator collections from its database.
type ReloadAdminResourcesResponse struct {
	Status string `json:"status"`
}

// ReloadAdminResources refreshes only the instance handling the request. It does
// not restart the CA, reload ca.json, or broadcast a refresh to other instances.
func ReloadAdminResources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if linkedca.MustAdminFromContext(ctx).GetType() != linkedca.Admin_SUPER_ADMIN {
		render.Error(w, r, admin.NewError(admin.ErrorUnauthorizedType,
			"must have super admin access to reload admin resources"))
		return
	}
	if err := mustAuthority(ctx).ReloadAdminResources(ctx); err != nil {
		render.Error(w, r, admin.WrapErrorISE(err, "error reloading admin resources"))
		return
	}
	render.JSON(w, r, &ReloadAdminResourcesResponse{Status: "ok"})
}
