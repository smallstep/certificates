package admin

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
)

// DefaultAdminLimit is the default limit for listing provisioners.
const DefaultAdminLimit = 20

// DefaultAdminMax is the maximum limit for listing provisioners.
const DefaultAdminMax = 100

type uidAdmin struct {
	admin *Admin
	uid   string
}

type adminSlice []uidAdmin

func (p adminSlice) Len() int           { return len(p) }
func (p adminSlice) Less(i, j int) bool { return p[i].uid < p[j].uid }
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
	p, ok := c.provisioners.Load(adm.ProvisionerID)
	if !ok {
		return fmt.Errorf("provisioner %s not found", adm.ProvisionerID)
	}
	adm.ProvisionerName = p.GetName()
	adm.ProvisionerType = p.GetType().String()
	// Store admin always in byID. ID must be unique.
	if _, loaded := c.byID.LoadOrStore(adm.ID, adm); loaded {
		return errors.New("cannot add multiple admins with the same id")
	}

	provName := adm.ProvisionerName
	// Store admin alwasy in bySubProv. Subject <-> ProvisionerName must be unique.
	if _, loaded := c.bySubProv.LoadOrStore(subProvNameHash(adm.Subject, provName), adm); loaded {
		c.byID.Delete(adm.ID)
		return errors.New("cannot add multiple admins with the same subject and provisioner")
	}

	if admins, ok := c.LoadByProvisioner(provName); ok {
		c.byProv.Store(provName, append(admins, adm))
		c.superCountByProvisioner[provName]++
	} else {
		c.byProv.Store(provName, []*Admin{adm})
		c.superCountByProvisioner[provName] = 1
	}
	c.superCount++

	// Store sorted admins.
	// Use the first 4 bytes (32bit) of the sum to insert the order
	// Using big endian format to get the strings sorted:
	// 0x00000000, 0x00000001, 0x00000002, ...
	bi := make([]byte, 4)
	_sum := sha1.Sum([]byte(adm.ID))
	sum := _sum[:]
	binary.BigEndian.PutUint32(bi, uint32(c.sorted.Len()))
	sum[0], sum[1], sum[2], sum[3] = bi[0], bi[1], bi[2], bi[3]
	c.sorted = append(c.sorted, uidAdmin{
		admin: adm,
		uid:   hex.EncodeToString(sum),
	})
	sort.Sort(c.sorted)

	return nil
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

// Find implements pagination on a list of sorted provisioners.
func (c *Collection) Find(cursor string, limit int) ([]*Admin, string) {
	switch {
	case limit <= 0:
		limit = DefaultAdminLimit
	case limit > DefaultAdminMax:
		limit = DefaultAdminMax
	}

	n := c.sorted.Len()
	cursor = fmt.Sprintf("%040s", cursor)
	i := sort.Search(n, func(i int) bool { return c.sorted[i].uid >= cursor })

	slice := []*Admin{}
	for ; i < n && len(slice) < limit; i++ {
		slice = append(slice, c.sorted[i].admin)
	}

	if i < n {
		return slice, strings.TrimLeft(c.sorted[i].uid, "0")
	}
	return slice, ""
}

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
