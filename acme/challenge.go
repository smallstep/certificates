package acme

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/nosql"
)

// Challenge is a subset of the challenge type containing only those attributes
// required for responses in the ACME protocol.
type Challenge struct {
	Type      string  `json:"type"`
	Status    string  `json:"status"`
	Token     string  `json:"token"`
	Validated string  `json:"validated,omitempty"`
	URL       string  `json:"url"`
	Error     *AError `json:"error,omitempty"`
	ID        string  `json:"-"`
	AuthzID   string  `json:"-"`
}

// ToLog enables response logging.
func (c *Challenge) ToLog() (interface{}, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling challenge for logging"))
	}
	return string(b), nil
}

// GetID returns the Challenge ID.
func (c *Challenge) GetID() string {
	return c.ID
}

// GetAuthzID returns the parent Authz ID that owns the Challenge.
func (c *Challenge) GetAuthzID() string {
	return c.AuthzID
}

type httpGetter func(string) (*http.Response, error)
type lookupTxt func(string) ([]string, error)

type validateOptions struct {
	httpGet   httpGetter
	lookupTxt lookupTxt
}

// challenge is the interface ACME challenege types must implement.
type challenge interface {
	save(db nosql.DB, swap challenge) error
	validate(nosql.DB, *jose.JSONWebKey, validateOptions) (challenge, error)
	getType() string
	getError() *AError
	getValue() string
	getStatus() string
	getID() string
	getAuthzID() string
	getToken() string
	clone() *baseChallenge
	getAccountID() string
	getValidated() time.Time
	getCreated() time.Time
	toACME(nosql.DB, *directory, provisioner.Interface) (*Challenge, error)
}

// ChallengeOptions is the type used to created a new Challenge.
type ChallengeOptions struct {
	AccountID  string
	AuthzID    string
	Identifier Identifier
}

// baseChallenge is the base Challenge type that others build from.
type baseChallenge struct {
	ID        string    `json:"id"`
	AccountID string    `json:"accountID"`
	AuthzID   string    `json:"authzID"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	Token     string    `json:"token"`
	Value     string    `json:"value"`
	Validated time.Time `json:"validated"`
	Created   time.Time `json:"created"`
	Error     *AError   `json:"error"`
}

func newBaseChallenge(accountID, authzID string) (*baseChallenge, error) {
	id, err := randID()
	if err != nil {
		return nil, Wrap(err, "error generating random id for ACME challenge")
	}
	token, err := randID()
	if err != nil {
		return nil, Wrap(err, "error generating token for ACME challenge")
	}

	return &baseChallenge{
		ID:        id,
		AccountID: accountID,
		AuthzID:   authzID,
		Status:    StatusPending,
		Token:     token,
		Created:   clock.Now(),
	}, nil
}

// getID returns the id of the baseChallenge.
func (bc *baseChallenge) getID() string {
	return bc.ID
}

// getAuthzID returns the authz ID of the baseChallenge.
func (bc *baseChallenge) getAuthzID() string {
	return bc.AuthzID
}

// getAccountID returns the account id of the baseChallenge.
func (bc *baseChallenge) getAccountID() string {
	return bc.AccountID
}

// getType returns the type of the baseChallenge.
func (bc *baseChallenge) getType() string {
	return bc.Type
}

// getValue returns the type of the baseChallenge.
func (bc *baseChallenge) getValue() string {
	return bc.Value
}

// getStatus returns the status of the baseChallenge.
func (bc *baseChallenge) getStatus() string {
	return bc.Status
}

// getToken returns the token of the baseChallenge.
func (bc *baseChallenge) getToken() string {
	return bc.Token
}

// getValidated returns the validated time of the baseChallenge.
func (bc *baseChallenge) getValidated() time.Time {
	return bc.Validated
}

// getCreated returns the created time of the baseChallenge.
func (bc *baseChallenge) getCreated() time.Time {
	return bc.Created
}

// getCreated returns the created time of the baseChallenge.
func (bc *baseChallenge) getError() *AError {
	return bc.Error
}

// toACME converts the internal Challenge type into the public acmeChallenge
// type for presentation in the ACME protocol.
func (bc *baseChallenge) toACME(db nosql.DB, dir *directory, p provisioner.Interface) (*Challenge, error) {
	ac := &Challenge{
		Type:    bc.getType(),
		Status:  bc.getStatus(),
		Token:   bc.getToken(),
		URL:     dir.getLink(ChallengeLink, URLSafeProvisionerName(p), true, bc.getID()),
		ID:      bc.getID(),
		AuthzID: bc.getAuthzID(),
	}
	if !bc.Validated.IsZero() {
		ac.Validated = bc.Validated.Format(time.RFC3339)
	}
	if bc.Error != nil {
		ac.Error = bc.Error
	}
	return ac, nil
}

// save writes the challenge to disk. For new challenges 'old' should be nil,
// otherwise 'old' should be a pointer to the acme challenge as it was at the
// start of the request. This method will fail if the value currently found
// in the bucket/row does not match the value of 'old'.
func (bc *baseChallenge) save(db nosql.DB, old challenge) error {
	newB, err := json.Marshal(bc)
	if err != nil {
		return ServerInternalErr(errors.Wrap(err,
			"error marshaling new acme challenge"))
	}
	var oldB []byte
	if old == nil {
		oldB = nil
	} else {
		oldB, err = json.Marshal(old)
		if err != nil {
			return ServerInternalErr(errors.Wrap(err,
				"error marshaling old acme challenge"))
		}
	}

	_, swapped, err := db.CmpAndSwap(challengeTable, []byte(bc.ID), oldB, newB)
	switch {
	case err != nil:
		return ServerInternalErr(errors.Wrap(err, "error saving acme challenge"))
	case !swapped:
		return ServerInternalErr(errors.New("error saving acme challenge; " +
			"acme challenge has changed since last read"))
	default:
		return nil
	}
}

func (bc *baseChallenge) clone() *baseChallenge {
	u := *bc
	return &u
}

func (bc *baseChallenge) validate(db nosql.DB, jwk *jose.JSONWebKey, vo validateOptions) (challenge, error) {
	return nil, ServerInternalErr(errors.New("unimplemented"))
}

func (bc *baseChallenge) storeError(db nosql.DB, err *Error) error {
	clone := bc.clone()
	clone.Error = err.ToACME()
	return clone.save(db, bc)
}

// unmarshalChallenge unmarshals a challenge type into the correct sub-type.
func unmarshalChallenge(data []byte) (challenge, error) {
	var getType struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &getType); err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling challenge type"))
	}

	switch getType.Type {
	case "dns-01":
		var bc baseChallenge
		if err := json.Unmarshal(data, &bc); err != nil {
			return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling "+
				"challenge type into dns01Challenge"))
		}
		return &dns01Challenge{&bc}, nil
	case "http-01":
		var bc baseChallenge
		if err := json.Unmarshal(data, &bc); err != nil {
			return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling "+
				"challenge type into http01Challenge"))
		}
		return &http01Challenge{&bc}, nil
	default:
		return nil, ServerInternalErr(errors.Errorf("unexpected challenge type %s", getType.Type))
	}
}

// http01Challenge represents an http-01 acme challenge.
type http01Challenge struct {
	*baseChallenge
}

// newHTTP01Challenge returns a new acme http-01 challenge.
func newHTTP01Challenge(db nosql.DB, ops ChallengeOptions) (challenge, error) {
	bc, err := newBaseChallenge(ops.AccountID, ops.AuthzID)
	if err != nil {
		return nil, err
	}
	bc.Type = "http-01"
	bc.Value = ops.Identifier.Value

	hc := &http01Challenge{bc}
	if err := hc.save(db, nil); err != nil {
		return nil, err
	}
	return hc, nil
}

// Validate attempts to validate the challenge. If the challenge has been
// satisfactorily validated, the 'status' and 'validated' attributes are
// updated.
func (hc *http01Challenge) validate(db nosql.DB, jwk *jose.JSONWebKey, vo validateOptions) (challenge, error) {
	// If already valid or invalid then return without performing validation.
	if hc.getStatus() == StatusValid || hc.getStatus() == StatusInvalid {
		return hc, nil
	}
	url := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", hc.Value, hc.Token)

	resp, err := vo.httpGet(url)
	if err != nil {
		if err = hc.storeError(db, ConnectionErr(errors.Wrapf(err,
			"error doing http GET for url %s", url))); err != nil {
			return nil, err
		}
		return hc, nil
	}
	if resp.StatusCode >= 400 {
		if err = hc.storeError(db,
			ConnectionErr(errors.Errorf("error doing http GET for url %s with status code %d",
				url, resp.StatusCode))); err != nil {
			return nil, err
		}
		return hc, nil
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrapf(err, "error reading "+
			"response body for url %s", url))
	}
	keyAuth := strings.Trim(string(body), "\r\n")

	expected, err := KeyAuthorization(hc.Token, jwk)
	if err != nil {
		return nil, err
	}
	if keyAuth != expected {
		if err = hc.storeError(db,
			RejectedIdentifierErr(errors.Errorf("keyAuthorization does not match; "+
				"expected %s, but got %s", expected, keyAuth))); err != nil {
			return nil, err
		}
		return hc, nil
	}

	// Update and store the challenge.
	upd := &http01Challenge{hc.baseChallenge.clone()}
	upd.Status = StatusValid
	upd.Error = nil
	upd.Validated = clock.Now()

	if err := upd.save(db, hc); err != nil {
		return nil, err
	}
	return upd, nil
}

// dns01Challenge represents an dns-01 acme challenge.
type dns01Challenge struct {
	*baseChallenge
}

// newDNS01Challenge returns a new acme dns-01 challenge.
func newDNS01Challenge(db nosql.DB, ops ChallengeOptions) (challenge, error) {
	bc, err := newBaseChallenge(ops.AccountID, ops.AuthzID)
	if err != nil {
		return nil, err
	}
	bc.Type = "dns-01"
	bc.Value = ops.Identifier.Value

	dc := &dns01Challenge{bc}
	if err := dc.save(db, nil); err != nil {
		return nil, err
	}
	return dc, nil
}

// KeyAuthorization creates the ACME key authorization value from a token
// and a jwk.
func KeyAuthorization(token string, jwk *jose.JSONWebKey) (string, error) {
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", ServerInternalErr(errors.Wrap(err, "error generating JWK thumbprint"))
	}
	encPrint := base64.RawURLEncoding.EncodeToString(thumbprint)
	return fmt.Sprintf("%s.%s", token, encPrint), nil
}

// validate attempts to validate the challenge. If the challenge has been
// satisfactorily validated, the 'status' and 'validated' attributes are
// updated.
func (dc *dns01Challenge) validate(db nosql.DB, jwk *jose.JSONWebKey, vo validateOptions) (challenge, error) {
	// If already valid or invalid then return without performing validation.
	if dc.getStatus() == StatusValid || dc.getStatus() == StatusInvalid {
		return dc, nil
	}

	txtRecords, err := vo.lookupTxt("_acme-challenge." + dc.Value)
	if err != nil {
		if err = dc.storeError(db,
			DNSErr(errors.Wrapf(err, "error looking up TXT "+
				"records for domain %s", dc.Value))); err != nil {
			return nil, err
		}
		return dc, nil
	}

	expectedKeyAuth, err := KeyAuthorization(dc.Token, jwk)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256([]byte(expectedKeyAuth))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	var found bool
	for _, r := range txtRecords {
		if r == expected {
			found = true
			break
		}
	}
	if !found {
		if err = dc.storeError(db,
			RejectedIdentifierErr(errors.Errorf("keyAuthorization "+
				"does not match; expected %s, but got %s", expectedKeyAuth, txtRecords))); err != nil {
			return nil, err
		}
		return dc, nil
	}

	// Update and store the challenge.
	upd := &dns01Challenge{dc.baseChallenge.clone()}
	upd.Status = StatusValid
	upd.Error = nil
	upd.Validated = time.Now().UTC()

	if err := upd.save(db, dc); err != nil {
		return nil, err
	}
	return upd, nil
}

// getChallenge retrieves and unmarshals an ACME challenge type from the database.
func getChallenge(db nosql.DB, id string) (challenge, error) {
	b, err := db.Get(challengeTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, MalformedErr(errors.Wrapf(err, "challenge %s not found", id))
	} else if err != nil {
		return nil, ServerInternalErr(errors.Wrapf(err, "error loading challenge %s", id))
	}
	ch, err := unmarshalChallenge(b)
	if err != nil {
		return nil, err
	}
	return ch, nil
}
