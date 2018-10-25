package authority

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"

	"github.com/pkg/errors"
)

// DefaultProvisionersLimit is the default limit for listing provisioners.
const DefaultProvisionersLimit = 20

// DefaultProvisionersMax is the maximum limit for listing provisioners.
const DefaultProvisionersMax = 100

// GetEncryptedKey returns the JWE key corresponding to the given kid argument.
func (a *Authority) GetEncryptedKey(kid string) (string, error) {
	val, ok := a.encryptedKeyIndex.Load(kid)
	if !ok {
		return "", &apiError{errors.Errorf("encrypted key with kid %s was not found", kid),
			http.StatusNotFound, context{}}
	}

	key, ok := val.(string)
	if !ok {
		return "", &apiError{errors.Errorf("stored value is not a string"),
			http.StatusInternalServerError, context{}}
	}
	return key, nil
}

// GetProvisioners returns a map listing each provisioner and the JWK Key Set
// with their public keys.
func (a *Authority) GetProvisioners() ([]*Provisioner, error) {
	return a.config.AuthorityConfig.Provisioners, nil
}

type uidProvisioner struct {
	provisioner *provisioner.Provisioner
	uid         string
}

func newSortedProvisioners(provisioners []*provisioner.Provisioner) (provisionerSlice, error) {
	if len(provisioners) > math.MaxUint32 {
		return nil, errors.New("too many provisioners")
	}

	var slice provisionerSlice
	bi := make([]byte, 4)
	for i, p := range provisioners {
		sum, err := provisionerSum(p)
		if err != nil {
			return nil, err
		}
		// Use the first 4 bytes (32bit) of the sum to insert the order
		// Using big endian format to get the strings sorted:
		// 0x00000000, 0x00000001, 0x00000002, ...
		binary.BigEndian.PutUint32(bi, uint32(i))
		sum[0], sum[1], sum[2], sum[3] = bi[0], bi[1], bi[2], bi[3]
		bi[0], bi[1], bi[2], bi[3] = 0, 0, 0, 0
		slice = append(slice, uidProvisioner{
			provisioner: p,
			uid:         hex.EncodeToString(sum),
		})
	}
	sort.Sort(slice)
	return slice, nil
}

type provisionerSlice []uidProvisioner

func (p provisionerSlice) Len() int           { return len(p) }
func (p provisionerSlice) Less(i, j int) bool { return p[i].uid < p[j].uid }
func (p provisionerSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func (p provisionerSlice) Find(cursor string, limit int) ([]*provisioner.Provisioner, string) {
	switch {
	case limit <= 0:
		limit = DefaultProvisionersLimit
	case limit > DefaultProvisionersMax:
		limit = DefaultProvisionersMax
	}

	n := len(p)
	cursor = fmt.Sprintf("%040s", cursor)
	i := sort.Search(n, func(i int) bool { return p[i].uid >= cursor })

	var slice []*provisioner.Provisioner
	for ; i < n && len(slice) < limit; i++ {
		slice = append(slice, p[i].provisioner)
	}
	if i < n {
		return slice, strings.TrimLeft(p[i].uid, "0")
	}
	return slice, ""
}

// provisionerSum returns the SHA1 of the json representation of the
// provisioner. From this we will create the unique and sorted id.
func provisionerSum(p *provisioner.Provisioner) ([]byte, error) {
	b, err := json.Marshal(p.Key)
	if err != nil {
		return nil, errors.Wrap(err, "error marshalling provisioner")
	}
	sum := sha1.Sum(b)
	return sum[:], nil
}
