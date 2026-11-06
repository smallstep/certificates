package authority

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/authority/admin"
	adminDB "github.com/smallstep/certificates/authority/admin/db/nosql"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/linkedca"
	"github.com/smallstep/nosql"
)

func TestReloadAdminResourcesAcrossInstances(t *testing.T) {
	ctx := context.Background()
	db, err := nosql.New("badgerv2", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	d, err := adminDB.New(db, admin.DefaultAuthorityID)
	require.NoError(t, err)
	seed := testAuthority(t)
	t.Cleanup(seed.CloseForReload)
	p, err := seed.LoadProvisionerByName("Max")
	require.NoError(t, err)
	lp, err := ProvisionerToLinkedca(p)
	require.NoError(t, err)
	require.NoError(t, d.CreateProvisioner(ctx, lp))
	require.NoError(t, d.CreateAdmin(ctx, &linkedca.Admin{
		Subject: "step", ProvisionerId: lp.Id, Type: linkedca.Admin_SUPER_ADMIN,
	}))
	newInstance := func() *Authority {
		a := testAuthority(t, WithAdminDB(d), func(a *Authority) error {
			a.config.AuthorityConfig.EnableAdmin = true
			return nil
		})
		t.Cleanup(a.CloseForReload)
		return a
	}
	writer, reader := newInstance(), newInstance()
	lp, err = ProvisionerToLinkedca(&provisioner.ACME{Type: "ACME", Name: "remote-change"})
	require.NoError(t, err)
	require.NoError(t, writer.StoreProvisioner(ctx, lp))
	_, err = reader.LoadProvisionerByName(lp.Name)
	require.Error(t, err, "another instance's cache remains unchanged until refreshed")
	require.NoError(t, reader.ReloadAdminResources(ctx))
	_, err = reader.LoadProvisionerByName(lp.Name)
	require.NoError(t, err)

	lp.Claims = &linkedca.Claims{DisableRenewal: true}
	require.NoError(t, writer.UpdateProvisioner(ctx, lp))
	require.NoError(t, reader.ReloadAdminResources(ctx))
	p, err = reader.LoadProvisionerByID(lp.Id)
	require.NoError(t, err)
	require.NotNil(t, p.(*provisioner.ACME).Claims.DisableRenewal)
	require.True(t, *p.(*provisioner.ACME).Claims.DisableRenewal)

	wp, err := writer.LoadProvisionerByID(lp.Id)
	require.NoError(t, err)
	adm := &linkedca.Admin{Subject: "operator", ProvisionerId: lp.Id, Type: linkedca.Admin_ADMIN}
	require.NoError(t, writer.StoreAdmin(ctx, adm, wp))
	require.NoError(t, reader.ReloadAdminResources(ctx))
	_, ok := reader.LoadAdminByID(adm.Id)
	require.True(t, ok)
	require.NoError(t, writer.RemoveAdmin(ctx, adm.Id))
	require.NoError(t, writer.RemoveProvisioner(ctx, lp.Id))
	require.NoError(t, reader.ReloadAdminResources(ctx))
	_, ok = reader.LoadAdminByID(adm.Id)
	require.False(t, ok)
	_, err = reader.LoadProvisionerByID(lp.Id)
	require.Error(t, err)
}

func TestReloadAdminResourcesFailureAndConcurrentReaders(t *testing.T) {
	a := testAuthority(t)
	t.Cleanup(a.CloseForReload)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for ctx.Err() == nil {
				_, _, _ = a.GetProvisioners("", 100)
				_, _, _ = a.GetAdmins("", 100)
				_, _ = a.LoadProvisionerByName("Max")
			}
		})
	}
	t.Cleanup(func() { cancel(); wg.Wait() })
	for range 10 {
		require.NoError(t, a.ReloadAdminResources(ctx))
	}

	// A failed database read must not publish a partially built collection.
	a.adminMutex.Lock()
	a.config.AuthorityConfig.EnableAdmin = true
	a.adminDB = &admin.MockDB{MockGetProvisioners: func(context.Context) ([]*linkedca.Provisioner, error) {
		return nil, errors.New("database unavailable")
	}}
	beforeProvs, beforeAdmins := a.provisioners, a.admins
	a.adminMutex.Unlock()
	require.Error(t, a.ReloadAdminResources(ctx))
	require.Same(t, beforeProvs, a.provisioners)
	require.Same(t, beforeAdmins, a.admins)
}
