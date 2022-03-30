package api

import (
	"net/http"

	"github.com/go-chi/chi"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/read"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
)

// GetProvisionersResponse is the type for GET /admin/provisioners responses.
type GetProvisionersResponse struct {
	Provisioners provisioner.List `json:"provisioners"`
	NextCursor   string           `json:"nextCursor"`
}

// GetProvisioner returns the requested provisioner, or an error.
func (h *Handler) GetProvisioner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.URL.Query().Get("id")
	name := chi.URLParam(r, "name")

	var (
		p   provisioner.Interface
		err error
	)
	if len(id) > 0 {
		if p, err = h.auth.LoadProvisionerByID(id); err != nil {
			render.Error(w, admin.WrapErrorISE(err, "error loading provisioner %s", id))
			return
		}
	} else {
		if p, err = h.auth.LoadProvisionerByName(name); err != nil {
			render.Error(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
			return
		}
	}

	prov, err := h.adminDB.GetProvisioner(ctx, p.GetID())
	if err != nil {
		render.Error(w, err)
		return
	}
	render.ProtoJSON(w, prov)
}

// GetProvisioners returns the given segment of  provisioners associated with the authority.
func (h *Handler) GetProvisioners(w http.ResponseWriter, r *http.Request) {
	cursor, limit, err := api.ParseCursor(r)
	if err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err,
			"error parsing cursor and limit from query params"))
		return
	}

	p, next, err := h.auth.GetProvisioners(cursor, limit)
	if err != nil {
		render.Error(w, errs.InternalServerErr(err))
		return
	}
	render.JSON(w, &GetProvisionersResponse{
		Provisioners: p,
		NextCursor:   next,
	})
}

// CreateProvisioner creates a new prov.
func (h *Handler) CreateProvisioner(w http.ResponseWriter, r *http.Request) {
	var prov = new(linkedca.Provisioner)
	if err := read.ProtoJSON(r.Body, prov); err != nil {
		render.Error(w, err)
		return
	}

	// TODO: Validate inputs
	if err := authority.ValidateClaims(prov.Claims); err != nil {
		render.Error(w, err)
		return
	}

	if err := h.auth.StoreProvisioner(r.Context(), prov); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error storing provisioner %s", prov.Name))
		return
	}
	render.ProtoJSONStatus(w, prov, http.StatusCreated)
}

// DeleteProvisioner deletes a provisioner.
func (h *Handler) DeleteProvisioner(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	name := chi.URLParam(r, "name")

	var (
		p   provisioner.Interface
		err error
	)
	if len(id) > 0 {
		if p, err = h.auth.LoadProvisionerByID(id); err != nil {
			render.Error(w, admin.WrapErrorISE(err, "error loading provisioner %s", id))
			return
		}
	} else {
		if p, err = h.auth.LoadProvisionerByName(name); err != nil {
			render.Error(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
			return
		}
	}

	if err := h.auth.RemoveProvisioner(r.Context(), p.GetID()); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error removing provisioner %s", p.GetName()))
		return
	}

	render.JSON(w, &DeleteResponse{Status: "ok"})
}

// UpdateProvisioner updates an existing prov.
func (h *Handler) UpdateProvisioner(w http.ResponseWriter, r *http.Request) {
	var nu = new(linkedca.Provisioner)
	if err := read.ProtoJSON(r.Body, nu); err != nil {
		render.Error(w, err)
		return
	}

	name := chi.URLParam(r, "name")
	_old, err := h.auth.LoadProvisionerByName(name)
	if err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error loading provisioner from cached configuration '%s'", name))
		return
	}

	old, err := h.adminDB.GetProvisioner(r.Context(), _old.GetID())
	if err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error loading provisioner from db '%s'", _old.GetID()))
		return
	}

	if nu.Id != old.Id {
		render.Error(w, admin.NewErrorISE("cannot change provisioner ID"))
		return
	}
	if nu.Type != old.Type {
		render.Error(w, admin.NewErrorISE("cannot change provisioner type"))
		return
	}
	if nu.AuthorityId != old.AuthorityId {
		render.Error(w, admin.NewErrorISE("cannot change provisioner authorityID"))
		return
	}
	if !nu.CreatedAt.AsTime().Equal(old.CreatedAt.AsTime()) {
		render.Error(w, admin.NewErrorISE("cannot change provisioner createdAt"))
		return
	}
	if !nu.DeletedAt.AsTime().Equal(old.DeletedAt.AsTime()) {
		render.Error(w, admin.NewErrorISE("cannot change provisioner deletedAt"))
		return
	}

	// TODO: Validate inputs
	if err := authority.ValidateClaims(nu.Claims); err != nil {
		render.Error(w, err)
		return
	}

	if err := h.auth.UpdateProvisioner(r.Context(), nu); err != nil {
		render.Error(w, err)
		return
	}
	render.ProtoJSON(w, nu)
}
