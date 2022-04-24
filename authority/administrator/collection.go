package administrator

import (
	"sort"
	"sync"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/linkedca"
)

// DefaultAdminLimit is the default limit for listing provisioners.
const DefaultAdminLimit = 20

// DefaultAdminMax is the maximum limit for listing provisioners.
const DefaultAdminMax = 100

type adminSlice []*linkedca.Admin

func (p adminSlice) Len() int           { return len(p) }
func (p adminSlice) Less(i, j int) bool { return p[i].Id < p[j].Id }
func (p adminSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// Collection is a memory map of admins.
type Collection struct {
	byID                    *sync.Map
	bySubProv               *sync.Map
	byProv                  *sync.Map
	sorted                  adminSlice
	provisioners            *provisioner.Collection
	superCount              int
	superCountByProvisioner map[string]int
}

// NewCollection initializes a collection of provisioners. The given list of
// audiences are the audiences used by the JWT provisioner.
func NewCollection(provisioners *provisioner.Collection) *Collection {
	return &Collection{
		byID:                    new(sync.Map),
		byProv:                  new(sync.Map),
		bySubProv:               new(sync.Map),
		superCountByProvisioner: map[string]int{},
		provisioners:            provisioners,
	}
}

// LoadByID a admin by the ID.
func (c *Collection) LoadByID(id string) (*linkedca.Admin, bool) {
	return loadAdmin(c.byID, id)
}

type subProv struct {
	subject     string
	provisioner string
}

func newSubProv(subject, prov string) subProv {
	return subProv{subject, prov}
}

// LoadBySubProv loads an admin by subject and provisioner name.
func (c *Collection) LoadBySubProv(sub, provName string) (*linkedca.Admin, bool) {
	return loadAdmin(c.bySubProv, newSubProv(sub, provName))
}

// LoadByProvisioner loads admins by provisioner name.
func (c *Collection) LoadByProvisioner(provName string) ([]*linkedca.Admin, bool) {
	val, ok := c.byProv.Load(provName)
	if !ok {
		return nil, false
	}
	admins, ok := val.([]*linkedca.Admin)
	if !ok {
		return nil, false
	}
	return admins, true
}

// Store adds an admin to the collection and enforces the uniqueness of
// admin IDs and admin subject <-> provisioner name combos.
func (c *Collection) Store(adm *linkedca.Admin, prov provisioner.Interface) error {
	// Input validation.
	if adm.ProvisionerId != prov.GetID() {
		return admin.NewErrorISE("admin.provisionerId does not match provisioner argument")
	}

	// Store admin always in byID. ID must be unique.
	if _, loaded := c.byID.LoadOrStore(adm.Id, adm); loaded {
		return errors.New("cannot add multiple admins with the same id")
	}

	provName := prov.GetName()
	// Store admin always in bySubProv. Subject <-> ProvisionerName must be unique.
	if _, loaded := c.bySubProv.LoadOrStore(newSubProv(adm.Subject, provName), adm); loaded {
		c.byID.Delete(adm.Id)
		return errors.New("cannot add multiple admins with the same subject and provisioner")
	}

	var isSuper = (adm.Type == linkedca.Admin_SUPER_ADMIN)
	if admins, ok := c.LoadByProvisioner(provName); ok {
		c.byProv.Store(provName, append(admins, adm))
		if isSuper {
			c.superCountByProvisioner[provName]++
		}
	} else {
		c.byProv.Store(provName, []*linkedca.Admin{adm})
		if isSuper {
			c.superCountByProvisioner[provName] = 1
		}
	}
	if isSuper {
		c.superCount++
	}

	c.sorted = append(c.sorted, adm)
	sort.Sort(c.sorted)

	return nil
}

// Remove deletes an admin from all associated collections and lists.
func (c *Collection) Remove(id string) error {
	adm, ok := c.LoadByID(id)
	if !ok {
		return admin.NewError(admin.ErrorNotFoundType, "admin %s not found", id)
	}
	if adm.Type == linkedca.Admin_SUPER_ADMIN && c.SuperCount() == 1 {
		return admin.NewError(admin.ErrorBadRequestType, "cannot remove the last super admin")
	}
	prov, ok := c.provisioners.Load(adm.ProvisionerId)
	if !ok {
		return admin.NewError(admin.ErrorNotFoundType,
			"provisioner %s for admin %s not found", adm.ProvisionerId, id)
	}
	provName := prov.GetName()
	adminsByProv, ok := c.LoadByProvisioner(provName)
	if !ok {
		return admin.NewError(admin.ErrorNotFoundType,
			"admins not found for provisioner %s", provName)
	}

	// Find index in sorted list.
	sortedIndex := sort.Search(c.sorted.Len(), func(i int) bool { return c.sorted[i].Id >= adm.Id })
	if c.sorted[sortedIndex].Id != adm.Id {
		return admin.NewError(admin.ErrorNotFoundType,
			"admin %s not found in sorted list", adm.Id)
	}

	var found bool
	for i, a := range adminsByProv {
		if a.Id == adm.Id {
			// Remove admin from list. https://stackoverflow.com/questions/37334119/how-to-delete-an-element-from-a-slice-in-golang
			// Order does not matter.
			adminsByProv[i] = adminsByProv[len(adminsByProv)-1]
			c.byProv.Store(provName, adminsByProv[:len(adminsByProv)-1])
			found = true
		}
	}
	if !found {
		return admin.NewError(admin.ErrorNotFoundType,
			"admin %s not found in adminsByProvisioner list", adm.Id)
	}

	// Remove index in sorted list
	copy(c.sorted[sortedIndex:], c.sorted[sortedIndex+1:]) // Shift a[i+1:] left one index.
	c.sorted[len(c.sorted)-1] = nil                        // Erase last element (write zero value).
	c.sorted = c.sorted[:len(c.sorted)-1]                  // Truncate slice.

	c.byID.Delete(adm.Id)
	c.bySubProv.Delete(newSubProv(adm.Subject, provName))

	if adm.Type == linkedca.Admin_SUPER_ADMIN {
		c.superCount--
		c.superCountByProvisioner[provName]--
	}
	return nil
}

// Update updates the given admin in all related lists and collections.
func (c *Collection) Update(id string, nu *linkedca.Admin) (*linkedca.Admin, error) {
	adm, ok := c.LoadByID(id)
	if !ok {
		return nil, admin.NewError(admin.ErrorNotFoundType, "admin %s not found", adm.Id)
	}
	if adm.Type == nu.Type {
		return adm, nil
	}
	if adm.Type == linkedca.Admin_SUPER_ADMIN && c.SuperCount() == 1 {
		return nil, admin.NewError(admin.ErrorBadRequestType, "cannot change role of last super admin")
	}

	adm.Type = nu.Type
	return adm, nil
}

// SuperCount returns the total number of admins.
func (c *Collection) SuperCount() int {
	return c.superCount
}

// SuperCountByProvisioner returns the total number of admins.
func (c *Collection) SuperCountByProvisioner(provName string) int {
	if cnt, ok := c.superCountByProvisioner[provName]; ok {
		return cnt
	}
	return 0
}

// Find implements pagination on a list of sorted admins.
func (c *Collection) Find(cursor string, limit int) ([]*linkedca.Admin, string) {
	switch {
	case limit <= 0:
		limit = DefaultAdminLimit
	case limit > DefaultAdminMax:
		limit = DefaultAdminMax
	}

	n := c.sorted.Len()
	i := sort.Search(n, func(i int) bool { return c.sorted[i].Id >= cursor })

	slice := []*linkedca.Admin{}
	for ; i < n && len(slice) < limit; i++ {
		slice = append(slice, c.sorted[i])
	}

	if i < n {
		return slice, c.sorted[i].Id
	}
	return slice, ""
}

func loadAdmin(m *sync.Map, key interface{}) (*linkedca.Admin, bool) {
	val, ok := m.Load(key)
	if !ok {
		return nil, false
	}
	adm, ok := val.(*linkedca.Admin)
	if !ok {
		return nil, false
	}
	return adm, true
}
