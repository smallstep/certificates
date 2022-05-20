package authority

import (
	"context"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/linkedca"
)

// LoadAdminByID returns an *linkedca.Admin with the given ID.
func (a *Authority) LoadAdminByID(id string) (*linkedca.Admin, bool) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	return a.admins.LoadByID(id)
}

// LoadAdminBySubProv returns an *linkedca.Admin with the given ID.
func (a *Authority) LoadAdminBySubProv(subject, prov string) (*linkedca.Admin, bool) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	return a.admins.LoadBySubProv(subject, prov)
}

// GetAdmins returns a map listing each provisioner and the JWK Key Set
// with their public keys.
func (a *Authority) GetAdmins(cursor string, limit int) ([]*linkedca.Admin, string, error) {
	a.adminMutex.RLock()
	defer a.adminMutex.RUnlock()
	admins, nextCursor := a.admins.Find(cursor, limit)
	return admins, nextCursor, nil
}

// StoreAdmin stores an *linkedca.Admin to the authority.
func (a *Authority) StoreAdmin(ctx context.Context, adm *linkedca.Admin, prov provisioner.Interface) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	if adm.ProvisionerId != prov.GetID() {
		return admin.NewErrorISE("admin.provisionerId does not match provisioner argument")
	}

	if _, ok := a.admins.LoadBySubProv(adm.Subject, prov.GetName()); ok {
		return admin.NewError(admin.ErrorBadRequestType,
			"admin with subject %s and provisioner %s already exists", adm.Subject, prov.GetName())
	}
	// Store to database -- this will set the ID.
	if err := a.adminDB.CreateAdmin(ctx, adm); err != nil {
		return admin.WrapErrorISE(err, "error creating admin")
	}
	if err := a.admins.Store(adm, prov); err != nil {
		if err := a.ReloadAdminResources(ctx); err != nil {
			return admin.WrapErrorISE(err, "error reloading admin resources on failed admin store")
		}
		return admin.WrapErrorISE(err, "error storing admin in authority cache")
	}
	return nil
}

// UpdateAdmin stores an *linkedca.Admin to the authority.
func (a *Authority) UpdateAdmin(ctx context.Context, id string, nu *linkedca.Admin) (*linkedca.Admin, error) {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()
	adm, err := a.admins.Update(id, nu)
	if err != nil {
		return nil, admin.WrapErrorISE(err, "error updating cached admin %s", id)
	}
	if err := a.adminDB.UpdateAdmin(ctx, adm); err != nil {
		if err := a.ReloadAdminResources(ctx); err != nil {
			return nil, admin.WrapErrorISE(err, "error reloading admin resources on failed admin update")
		}
		return nil, admin.WrapErrorISE(err, "error updating admin %s", id)
	}
	return adm, nil
}

// RemoveAdmin removes an *linkedca.Admin from the authority.
func (a *Authority) RemoveAdmin(ctx context.Context, id string) error {
	a.adminMutex.Lock()
	defer a.adminMutex.Unlock()

	return a.removeAdmin(ctx, id)
}

// removeAdmin helper that assumes lock.
func (a *Authority) removeAdmin(ctx context.Context, id string) error {
	if err := a.admins.Remove(id); err != nil {
		return admin.WrapErrorISE(err, "error removing admin %s from authority cache", id)
	}
	if err := a.adminDB.DeleteAdmin(ctx, id); err != nil {
		if err := a.ReloadAdminResources(ctx); err != nil {
			return admin.WrapErrorISE(err, "error reloading admin resources on failed admin remove")
		}
		return admin.WrapErrorISE(err, "error deleting admin %s", id)
	}
	return nil
}
