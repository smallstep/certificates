package api

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"

	"go.step.sm/crypto/sshutil"
	"go.step.sm/crypto/x509util"
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
func GetProvisioner(w http.ResponseWriter, r *http.Request) {
	var (
		p   provisioner.Interface
		err error
	)

	ctx := r.Context()
	id := r.URL.Query().Get("id")
	name := chi.URLParam(r, "name")
	auth := mustAuthority(ctx)
	db := admin.MustFromContext(ctx)

	if len(id) > 0 {
		if p, err = auth.LoadProvisionerByID(id); err != nil {
			render.Error(w, admin.WrapErrorISE(err, "error loading provisioner %s", id))
			return
		}
	} else {
		if p, err = auth.LoadProvisionerByName(name); err != nil {
			render.Error(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
			return
		}
	}

	prov, err := db.GetProvisioner(ctx, p.GetID())
	if err != nil {
		render.Error(w, err)
		return
	}
	render.ProtoJSON(w, prov)
}

// GetProvisioners returns the given segment of  provisioners associated with the authority.
func GetProvisioners(w http.ResponseWriter, r *http.Request) {
	cursor, limit, err := api.ParseCursor(r)
	if err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err,
			"error parsing cursor and limit from query params"))
		return
	}

	p, next, err := mustAuthority(r.Context()).GetProvisioners(cursor, limit)
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
func CreateProvisioner(w http.ResponseWriter, r *http.Request) {
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

	// validate the templates and template data
	if err := validateTemplates(prov.X509Template, prov.SshTemplate); err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "invalid template"))
		return
	}

	if err := mustAuthority(r.Context()).StoreProvisioner(r.Context(), prov); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error storing provisioner %s", prov.Name))
		return
	}
	render.ProtoJSONStatus(w, prov, http.StatusCreated)
}

// DeleteProvisioner deletes a provisioner.
func DeleteProvisioner(w http.ResponseWriter, r *http.Request) {
	var (
		p   provisioner.Interface
		err error
	)

	id := r.URL.Query().Get("id")
	name := chi.URLParam(r, "name")
	auth := mustAuthority(r.Context())

	if len(id) > 0 {
		if p, err = auth.LoadProvisionerByID(id); err != nil {
			render.Error(w, admin.WrapErrorISE(err, "error loading provisioner %s", id))
			return
		}
	} else {
		if p, err = auth.LoadProvisionerByName(name); err != nil {
			render.Error(w, admin.WrapErrorISE(err, "error loading provisioner %s", name))
			return
		}
	}

	if err := auth.RemoveProvisioner(r.Context(), p.GetID()); err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error removing provisioner %s", p.GetName()))
		return
	}

	render.JSON(w, &DeleteResponse{Status: "ok"})
}

// UpdateProvisioner updates an existing prov.
func UpdateProvisioner(w http.ResponseWriter, r *http.Request) {
	var nu = new(linkedca.Provisioner)
	if err := read.ProtoJSON(r.Body, nu); err != nil {
		render.Error(w, err)
		return
	}

	ctx := r.Context()
	name := chi.URLParam(r, "name")
	auth := mustAuthority(ctx)
	db := admin.MustFromContext(ctx)

	p, err := auth.LoadProvisionerByName(name)
	if err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error loading provisioner from cached configuration '%s'", name))
		return
	}

	old, err := db.GetProvisioner(r.Context(), p.GetID())
	if err != nil {
		render.Error(w, admin.WrapErrorISE(err, "error loading provisioner from db '%s'", p.GetID()))
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

	// validate the templates and template data
	if err := validateTemplates(nu.X509Template, nu.SshTemplate); err != nil {
		render.Error(w, admin.WrapError(admin.ErrorBadRequestType, err, "invalid template"))
		return
	}

	if err := auth.UpdateProvisioner(r.Context(), nu); err != nil {
		render.Error(w, err)
		return
	}
	render.ProtoJSON(w, nu)
}

// validateTemplates validates the X.509 and SSH templates and template data if set.
func validateTemplates(x509, ssh *linkedca.Template) error {
	if x509 != nil {
		if len(x509.Template) > 0 {
			if err := x509util.ValidateTemplate(x509.Template); err != nil {
				return fmt.Errorf("invalid X.509 template: %w", err)
			}
		}
		if len(x509.Data) > 0 {
			if err := x509util.ValidateTemplateData(x509.Data); err != nil {
				return fmt.Errorf("invalid X.509 template data: %w", err)
			}
		}
	}

	if ssh != nil {
		if len(ssh.Template) > 0 {
			if err := sshutil.ValidateTemplate(ssh.Template); err != nil {
				return fmt.Errorf("invalid SSH template: %w", err)
			}
		}

		if len(ssh.Data) > 0 {
			if err := sshutil.ValidateTemplateData(ssh.Data); err != nil {
				return fmt.Errorf("invalid SSH template data: %w", err)
			}
		}
	}

	return nil
}
