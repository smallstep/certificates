package admin

import (
	"crypto/sha1"
	"sync"

	"github.com/pkg/errors"
	"go.step.sm/crypto/jose"
)

// DefaultProvisionersLimit is the default limit for listing provisioners.
const DefaultProvisionersLimit = 20

// DefaultProvisionersMax is the maximum limit for listing provisioners.
const DefaultProvisionersMax = 100

/*
type uidProvisioner struct {
	provisioner Interface
	uid         string
}

type provisionerSlice []uidProvisioner

func (p provisionerSlice) Len() int           { return len(p) }
func (p provisionerSlice) Less(i, j int) bool { return p[i].uid < p[j].uid }
func (p provisionerSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
*/

// loadByTokenPayload is a payload used to extract the id used to load the
// provisioner.
type loadByTokenPayload struct {
	jose.Claims
	AuthorizedParty string `json:"azp"` // OIDC client id
	TenantID        string `json:"tid"` // Microsoft Azure tenant id
}

// Collection is a memory map of admins.
type Collection struct {
	byID               *sync.Map
	bySubProv          *sync.Map
	byProv             *sync.Map
	count              int
	countByProvisioner map[string]int
}

// NewCollection initializes a collection of provisioners. The given list of
// audiences are the audiences used by the JWT provisioner.
func NewCollection() *Collection {
	return &Collection{
		byID:               new(sync.Map),
		byProv:             new(sync.Map),
		bySubProv:          new(sync.Map),
		countByProvisioner: map[string]int{},
	}
}

// LoadByID a admin by the ID.
func (c *Collection) LoadByID(id string) (*Admin, bool) {
	return loadAdmin(c.byID, id)
}

func subProvNameHash(sub, provName string) string {
	subHash := sha1.Sum([]byte(sub))
	provNameHash := sha1.Sum([]byte(provName))
	_res := sha1.Sum(append(subHash[:], provNameHash[:]...))
	return string(_res[:])
}

// LoadBySubProv a admin by the subject and provisioner name.
func (c *Collection) LoadBySubProv(sub, provName string) (*Admin, bool) {
	return loadAdmin(c.bySubProv, subProvNameHash(sub, provName))
}

// LoadByProvisioner a admin by the subject and provisioner name.
func (c *Collection) LoadByProvisioner(provName string) ([]*Admin, bool) {
	a, ok := c.byProv.Load(provName)
	if !ok {
		return nil, false
	}
	admins, ok := a.([]*Admin)
	if !ok {
		return nil, false
	}
	return admins, true
}

// Store adds an admin to the collection and enforces the uniqueness of
// admin IDs and amdin subject <-> provisioner name combos.
func (c *Collection) Store(adm *Admin) error {
	provName := adm.ProvisionerName
	// Store admin always in byID. ID must be unique.
	if _, loaded := c.byID.LoadOrStore(adm.ID, adm); loaded {
		return errors.New("cannot add multiple admins with the same id")
	}

	// Store admin alwasy in bySubProv. Subject <-> ProvisionerName must be unique.
	if _, loaded := c.bySubProv.LoadOrStore(subProvNameHash(adm.Subject, provName), adm); loaded {
		c.byID.Delete(adm.ID)
		return errors.New("cannot add multiple admins with the same subject and provisioner")
	}

	if admins, ok := c.LoadByProvisioner(provName); ok {
		c.byProv.Store(provName, append(admins, adm))
		c.countByProvisioner[provName]++
	} else {
		c.byProv.Store(provName, []*Admin{adm})
		c.countByProvisioner[provName] = 1
	}
	c.count++

	return nil
}

// Count returns the total number of admins.
func (c *Collection) Count() int {
	return c.count
}

// CountByProvisioner returns the total number of admins.
func (c *Collection) CountByProvisioner(provName string) int {
	if cnt, ok := c.countByProvisioner[provName]; ok {
		return cnt
	}
	return 0
}

/*
// Find implements pagination on a list of sorted provisioners.
func (c *Collection) Find(cursor string, limit int) (List, string) {
	switch {
	case limit <= 0:
		limit = DefaultProvisionersLimit
	case limit > DefaultProvisionersMax:
		limit = DefaultProvisionersMax
	}

	n := c.sorted.Len()
	cursor = fmt.Sprintf("%040s", cursor)
	i := sort.Search(n, func(i int) bool { return c.sorted[i].uid >= cursor })

	slice := List{}
	for ; i < n && len(slice) < limit; i++ {
		slice = append(slice, c.sorted[i].provisioner)
	}

	if i < n {
		return slice, strings.TrimLeft(c.sorted[i].uid, "0")
	}
	return slice, ""
}
*/

func loadAdmin(m *sync.Map, key string) (*Admin, bool) {
	a, ok := m.Load(key)
	if !ok {
		return nil, false
	}
	adm, ok := a.(*Admin)
	if !ok {
		return nil, false
	}
	return adm, true
}

/*
// provisionerSum returns the SHA1 of the provisioners ID. From this we will
// create the unique and sorted id.
func provisionerSum(p Interface) []byte {
	sum := sha1.Sum([]byte(p.GetID()))
	return sum[:]
}
*/
