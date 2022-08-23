package provisioner

import (
	"crypto/sha1" //nolint:gosec // not used for cryptographic security
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/smallstep/certificates/authority/admin"
	"go.step.sm/crypto/jose"
)

// DefaultProvisionersLimit is the default limit for listing provisioners.
const DefaultProvisionersLimit = 20

// DefaultProvisionersMax is the maximum limit for listing provisioners.
const DefaultProvisionersMax = 100

type uidProvisioner struct {
	provisioner Interface
	uid         string
}

type provisionerSlice []uidProvisioner

func (p provisionerSlice) Len() int           { return len(p) }
func (p provisionerSlice) Less(i, j int) bool { return p[i].uid < p[j].uid }
func (p provisionerSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// loadByTokenPayload is a payload used to extract the id used to load the
// provisioner.
type loadByTokenPayload struct {
	jose.Claims
	Email           string `json:"email"` // OIDC email
	AuthorizedParty string `json:"azp"`   // OIDC client id
	TenantID        string `json:"tid"`   // Microsoft Azure tenant id
}

// Collection is a memory map of provisioners.
type Collection struct {
	byID      *sync.Map
	byKey     *sync.Map
	byName    *sync.Map
	byTokenID *sync.Map
	sorted    provisionerSlice
	audiences Audiences
}

// NewCollection initializes a collection of provisioners. The given list of
// audiences are the audiences used by the JWT provisioner.
func NewCollection(audiences Audiences) *Collection {
	return &Collection{
		byID:      new(sync.Map),
		byKey:     new(sync.Map),
		byName:    new(sync.Map),
		byTokenID: new(sync.Map),
		audiences: audiences,
	}
}

// Load a provisioner by the ID.
func (c *Collection) Load(id string) (Interface, bool) {
	return loadProvisioner(c.byID, id)
}

// LoadByName a provisioner by name.
func (c *Collection) LoadByName(name string) (Interface, bool) {
	return loadProvisioner(c.byName, name)
}

// LoadByTokenID a provisioner by identifier found in token.
// For different provisioner types this identifier may be found in in different
// attributes of the token.
func (c *Collection) LoadByTokenID(tokenProvisionerID string) (Interface, bool) {
	return loadProvisioner(c.byTokenID, tokenProvisionerID)
}

// LoadByToken parses the token claims and loads the provisioner associated.
func (c *Collection) LoadByToken(token *jose.JSONWebToken, claims *jose.Claims) (Interface, bool) {
	var audiences []string
	// Get all audiences with the given fragment
	fragment := extractFragment(claims.Audience)
	if fragment == "" {
		audiences = c.audiences.All()
	} else {
		audiences = c.audiences.WithFragment(fragment).All()
	}

	// match with server audiences
	if matchesAudience(claims.Audience, audiences) {
		// Use fragment to get provisioner name (GCP, AWS, SSHPOP)
		if fragment != "" {
			return c.LoadByTokenID(fragment)
		}
		// If matches with stored audiences it will be a JWT token (default), and
		// the id would be <issuer>:<kid>.
		// TODO: is this ok?
		return c.LoadByTokenID(claims.Issuer + ":" + token.Headers[0].KeyID)
	}

	// The ID will be just the clientID stored in azp, aud or tid.
	var payload loadByTokenPayload
	if err := token.UnsafeClaimsWithoutVerification(&payload); err != nil {
		return nil, false
	}

	// Kubernetes Service Account tokens.
	if payload.Issuer == k8sSAIssuer {
		if p, ok := c.LoadByTokenID(K8sSAID); ok {
			return p, ok
		}
		// Kubernetes service account provisioner not found
		return nil, false
	}

	// Audience is required for non k8sSA tokens.
	if len(payload.Audience) == 0 {
		return nil, false
	}

	// Try with azp (OIDC)
	if len(payload.AuthorizedParty) > 0 {
		if p, ok := c.LoadByTokenID(payload.AuthorizedParty); ok {
			return p, ok
		}
	}
	// Try with tid (Azure, Azure OIDC)
	if payload.TenantID != "" {
		// Try to load an OIDC provisioner first.
		if payload.Email != "" {
			if p, ok := c.LoadByTokenID(payload.Audience[0]); ok {
				return p, ok
			}
		}
		// Try to load an Azure provisioner.
		if p, ok := c.LoadByTokenID(payload.TenantID); ok {
			return p, ok
		}
	}

	// Fallback to aud
	return c.LoadByTokenID(payload.Audience[0])
}

// LoadByCertificate looks for the provisioner extension and extracts the
// proper id to load the provisioner.
func (c *Collection) LoadByCertificate(cert *x509.Certificate) (Interface, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(StepOIDProvisioner) {
			var provisioner extensionASN1
			if _, err := asn1.Unmarshal(e.Value, &provisioner); err != nil {
				return nil, false
			}
			return c.LoadByName(string(provisioner.Name))
		}
	}

	// Default to noop provisioner if an extension is not found. This allows to
	// accept a renewal of a cert without the provisioner extension.
	return &noop{}, true
}

// LoadEncryptedKey returns an encrypted key by indexed by KeyID. At this moment
// only JWK encrypted keys are indexed by KeyID.
func (c *Collection) LoadEncryptedKey(keyID string) (string, bool) {
	p, ok := loadProvisioner(c.byKey, keyID)
	if !ok {
		return "", false
	}
	_, key, ok := p.GetEncryptedKey()
	return key, ok
}

// Store adds a provisioner to the collection and enforces the uniqueness of
// provisioner IDs.
func (c *Collection) Store(p Interface) error {
	// Store provisioner always in byID. ID must be unique.
	if _, loaded := c.byID.LoadOrStore(p.GetID(), p); loaded {
		return admin.NewError(admin.ErrorBadRequestType,
			"cannot add multiple provisioners with the same id")
	}
	// Store provisioner always by name.
	if _, loaded := c.byName.LoadOrStore(p.GetName(), p); loaded {
		c.byID.Delete(p.GetID())
		return admin.NewError(admin.ErrorBadRequestType,
			"cannot add multiple provisioners with the same name")
	}
	// Store provisioner always by ID presented in token.
	if _, loaded := c.byTokenID.LoadOrStore(p.GetIDForToken(), p); loaded {
		c.byID.Delete(p.GetID())
		c.byName.Delete(p.GetName())
		return admin.NewError(admin.ErrorBadRequestType,
			"cannot add multiple provisioners with the same token identifier")
	}

	// Store provisioner in byKey if EncryptedKey is defined.
	if kid, _, ok := p.GetEncryptedKey(); ok {
		c.byKey.Store(kid, p)
	}

	// Store sorted provisioners.
	// Use the first 4 bytes (32bit) of the sum to insert the order
	// Using big endian format to get the strings sorted:
	// 0x00000000, 0x00000001, 0x00000002, ...
	bi := make([]byte, 4)
	sum := provisionerSum(p)
	binary.BigEndian.PutUint32(bi, uint32(c.sorted.Len()))
	sum[0], sum[1], sum[2], sum[3] = bi[0], bi[1], bi[2], bi[3]
	c.sorted = append(c.sorted, uidProvisioner{
		provisioner: p,
		uid:         hex.EncodeToString(sum),
	})
	sort.Sort(c.sorted)
	return nil
}

// Remove deletes an provisioner from all associated collections and lists.
func (c *Collection) Remove(id string) error {
	prov, ok := c.Load(id)
	if !ok {
		return admin.NewError(admin.ErrorNotFoundType, "provisioner %s not found", id)
	}

	var found bool
	for i, elem := range c.sorted {
		if elem.provisioner.GetID() != id {
			continue
		}
		// Remove index in sorted list
		copy(c.sorted[i:], c.sorted[i+1:])           // Shift a[i+1:] left one index.
		c.sorted[len(c.sorted)-1] = uidProvisioner{} // Erase last element (write zero value).
		c.sorted = c.sorted[:len(c.sorted)-1]        // Truncate slice.
		found = true
		break
	}
	if !found {
		return admin.NewError(admin.ErrorNotFoundType, "provisioner %s not found in sorted list", prov.GetName())
	}

	c.byID.Delete(id)
	c.byName.Delete(prov.GetName())
	c.byTokenID.Delete(prov.GetIDForToken())
	if kid, _, ok := prov.GetEncryptedKey(); ok {
		c.byKey.Delete(kid)
	}

	return nil
}

// Update updates the given provisioner in all related lists and collections.
func (c *Collection) Update(nu Interface) error {
	old, ok := c.Load(nu.GetID())
	if !ok {
		return admin.NewError(admin.ErrorNotFoundType, "provisioner %s not found", nu.GetID())
	}

	if old.GetName() != nu.GetName() {
		if _, ok := c.LoadByName(nu.GetName()); ok {
			return admin.NewError(admin.ErrorBadRequestType,
				"provisioner with name %s already exists", nu.GetName())
		}
	}
	if old.GetIDForToken() != nu.GetIDForToken() {
		if _, ok := c.LoadByTokenID(nu.GetIDForToken()); ok {
			return admin.NewError(admin.ErrorBadRequestType,
				"provisioner with Token ID %s already exists", nu.GetIDForToken())
		}
	}

	if err := c.Remove(old.GetID()); err != nil {
		return err
	}

	return c.Store(nu)
}

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

func loadProvisioner(m *sync.Map, key string) (Interface, bool) {
	i, ok := m.Load(key)
	if !ok {
		return nil, false
	}
	p, ok := i.(Interface)
	if !ok {
		return nil, false
	}
	return p, true
}

// provisionerSum returns the SHA1 of the provisioners ID. From this we will
// create the unique and sorted id.
func provisionerSum(p Interface) []byte {
	//nolint:gosec // not used for cryptographic security
	sum := sha1.Sum([]byte(p.GetID()))
	return sum[:]
}

// matchesAudience returns true if A and B share at least one element.
func matchesAudience(as, bs []string) bool {
	if len(bs) == 0 || len(as) == 0 {
		return false
	}

	for _, b := range bs {
		for _, a := range as {
			if b == a || stripPort(a) == stripPort(b) {
				return true
			}
		}
	}
	return false
}

// stripPort attempts to strip the port from the given url. If parsing the url
// produces errors it will just return the passed argument.
func stripPort(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	u.Host = u.Hostname()
	return u.String()
}

// extractFragment extracts the first fragment of an audience url.
func extractFragment(audience []string) string {
	for _, s := range audience {
		if u, err := url.Parse(s); err == nil && u.Fragment != "" {
			return u.Fragment
		}
	}
	return ""
}
