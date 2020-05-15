package acme

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
)

var defaultExpiryDuration = time.Hour * 24

// Authz is a subset of the Authz type containing only those attributes
// required for responses in the ACME protocol.
type Authz struct {
	Identifier Identifier   `json:"identifier"`
	Status     string       `json:"status"`
	Expires    string       `json:"expires"`
	Challenges []*Challenge `json:"challenges"`
	Wildcard   bool         `json:"wildcard"`
	ID         string       `json:"-"`
}

// ToLog enables response logging.
func (a *Authz) ToLog() (interface{}, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling authz for logging"))
	}
	return string(b), nil
}

// GetID returns the Authz ID.
func (a *Authz) GetID() string {
	return a.ID
}

// authz is the interface that the various authz types must implement.
type authz interface {
	save(nosql.DB, authz) error
	clone() *baseAuthz
	getID() string
	getAccountID() string
	getType() string
	getIdentifier() Identifier
	getStatus() string
	getExpiry() time.Time
	getWildcard() bool
	getChallenges() []string
	getCreated() time.Time
	updateStatus(db nosql.DB) (authz, error)
	toACME(context.Context, nosql.DB, *directory) (*Authz, error)
}

// baseAuthz is the base authz type that others build from.
type baseAuthz struct {
	ID         string     `json:"id"`
	AccountID  string     `json:"accountID"`
	Identifier Identifier `json:"identifier"`
	Status     string     `json:"status"`
	Expires    time.Time  `json:"expires"`
	Challenges []string   `json:"challenges"`
	Wildcard   bool       `json:"wildcard"`
	Created    time.Time  `json:"created"`
	Error      *Error     `json:"error"`
}

func newBaseAuthz(accID string, identifier Identifier) (*baseAuthz, error) {
	id, err := randID()
	if err != nil {
		return nil, err
	}

	now := clock.Now()
	ba := &baseAuthz{
		ID:         id,
		AccountID:  accID,
		Status:     StatusPending,
		Created:    now,
		Expires:    now.Add(defaultExpiryDuration),
		Identifier: identifier,
	}

	if strings.HasPrefix(identifier.Value, "*.") {
		ba.Wildcard = true
		ba.Identifier = Identifier{
			Value: strings.TrimPrefix(identifier.Value, "*."),
			Type:  identifier.Type,
		}
	}

	return ba, nil
}

// getID returns the ID of the authz.
func (ba *baseAuthz) getID() string {
	return ba.ID
}

// getAccountID returns the Account ID that created the authz.
func (ba *baseAuthz) getAccountID() string {
	return ba.AccountID
}

// getType returns the type of the authz.
func (ba *baseAuthz) getType() string {
	return ba.Identifier.Type
}

// getIdentifier returns the identifier for the authz.
func (ba *baseAuthz) getIdentifier() Identifier {
	return ba.Identifier
}

// getStatus returns the status of the authz.
func (ba *baseAuthz) getStatus() string {
	return ba.Status
}

// getWildcard returns true if the authz identifier has a '*', false otherwise.
func (ba *baseAuthz) getWildcard() bool {
	return ba.Wildcard
}

// getChallenges returns the authz challenge IDs.
func (ba *baseAuthz) getChallenges() []string {
	return ba.Challenges
}

// getExpiry returns the expiration time of the authz.
func (ba *baseAuthz) getExpiry() time.Time {
	return ba.Expires
}

// getCreated returns the created time of the authz.
func (ba *baseAuthz) getCreated() time.Time {
	return ba.Created
}

// toACME converts the internal Authz type into the public acmeAuthz type for
// presentation in the ACME protocol.
func (ba *baseAuthz) toACME(ctx context.Context, db nosql.DB, dir *directory) (*Authz, error) {
	var chs = make([]*Challenge, len(ba.Challenges))
	for i, chID := range ba.Challenges {
		ch, err := getChallenge(db, chID)
		if err != nil {
			return nil, err
		}
		chs[i], err = ch.toACME(ctx, db, dir)
		if err != nil {
			return nil, err
		}
	}
	return &Authz{
		Identifier: ba.Identifier,
		Status:     ba.getStatus(),
		Challenges: chs,
		Wildcard:   ba.getWildcard(),
		Expires:    ba.Expires.Format(time.RFC3339),
		ID:         ba.ID,
	}, nil
}

func (ba *baseAuthz) save(db nosql.DB, old authz) error {
	var (
		err        error
		oldB, newB []byte
	)
	if old == nil {
		oldB = nil
	} else {
		if oldB, err = json.Marshal(old); err != nil {
			return ServerInternalErr(errors.Wrap(err, "error marshaling old authz"))
		}
	}
	if newB, err = json.Marshal(ba); err != nil {
		return ServerInternalErr(errors.Wrap(err, "error marshaling new authz"))
	}
	_, swapped, err := db.CmpAndSwap(authzTable, []byte(ba.ID), oldB, newB)
	switch {
	case err != nil:
		return ServerInternalErr(errors.Wrapf(err, "error storing authz"))
	case !swapped:
		return ServerInternalErr(errors.Errorf("error storing authz; " +
			"value has changed since last read"))
	default:
		return nil
	}
}

func (ba *baseAuthz) clone() *baseAuthz {
	u := *ba
	return &u
}

func (ba *baseAuthz) parent() authz {
	return &dnsAuthz{ba}
}

// updateStatus attempts to update the status on a baseAuthz and stores the
// updating object if necessary.
func (ba *baseAuthz) updateStatus(db nosql.DB) (authz, error) {
	newAuthz := ba.clone()

	now := time.Now().UTC()
	switch ba.Status {
	case StatusInvalid:
		return ba.parent(), nil
	case StatusValid:
		return ba.parent(), nil
	case StatusPending:
		// check expiry
		if now.After(ba.Expires) {
			newAuthz.Status = StatusInvalid
			newAuthz.Error = MalformedErr(errors.New("authz has expired"))
			break
		}

		var isValid = false
		for _, chID := range ba.Challenges {
			ch, err := getChallenge(db, chID)
			if err != nil {
				return ba, err
			}
			if ch.getStatus() == StatusValid {
				isValid = true
				break
			}
		}

		if !isValid {
			return ba.parent(), nil
		}
		newAuthz.Status = StatusValid
		newAuthz.Error = nil
	default:
		return nil, ServerInternalErr(errors.Errorf("unrecognized authz status: %s", ba.Status))
	}

	if err := newAuthz.save(db, ba); err != nil {
		return ba, err
	}
	return newAuthz.parent(), nil
}

// unmarshalAuthz unmarshals an authz type into the correct sub-type.
func unmarshalAuthz(data []byte) (authz, error) {
	var getType struct {
		Identifier Identifier `json:"identifier"`
	}
	if err := json.Unmarshal(data, &getType); err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling authz type"))
	}

	switch getType.Identifier.Type {
	case "dns":
		var ba baseAuthz
		if err := json.Unmarshal(data, &ba); err != nil {
			return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling authz type into dnsAuthz"))
		}
		return &dnsAuthz{&ba}, nil
	default:
		return nil, ServerInternalErr(errors.Errorf("unexpected authz type %s",
			getType.Identifier.Type))
	}
}

// dnsAuthz represents a dns acme authorization.
type dnsAuthz struct {
	*baseAuthz
}

// newAuthz returns a new acme authorization object based on the identifier
// type.
func newAuthz(db nosql.DB, accID string, identifier Identifier) (a authz, err error) {
	switch identifier.Type {
	case "dns":
		a, err = newDNSAuthz(db, accID, identifier)
	default:
		err = MalformedErr(errors.Errorf("unexpected authz type %s",
			identifier.Type))
	}
	return
}

// newDNSAuthz returns a new dns acme authorization object.
func newDNSAuthz(db nosql.DB, accID string, identifier Identifier) (authz, error) {
	ba, err := newBaseAuthz(accID, identifier)
	if err != nil {
		return nil, err
	}

	ba.Challenges = []string{}
	if !ba.Wildcard {
		// http and alpn challenges are only permitted if the DNS is not a wildcard dns.
		ch1, err := newHTTP01Challenge(db, ChallengeOptions{
			AccountID:  accID,
			AuthzID:    ba.ID,
			Identifier: ba.Identifier})
		if err != nil {
			return nil, Wrap(err, "error creating http challenge")
		}
		ba.Challenges = append(ba.Challenges, ch1.getID())

		ch2, err := newTLSALPN01Challenge(db, ChallengeOptions{
			AccountID:  accID,
			AuthzID:    ba.ID,
			Identifier: ba.Identifier,
		})
		if err != nil {
			return nil, Wrap(err, "error creating alpn challenge")
		}
		ba.Challenges = append(ba.Challenges, ch2.getID())
	}
	ch3, err := newDNS01Challenge(db, ChallengeOptions{
		AccountID:  accID,
		AuthzID:    ba.ID,
		Identifier: identifier})
	if err != nil {
		return nil, Wrap(err, "error creating dns challenge")
	}
	ba.Challenges = append(ba.Challenges, ch3.getID())

	da := &dnsAuthz{ba}
	if err := da.save(db, nil); err != nil {
		return nil, err
	}

	return da, nil
}

// getAuthz retrieves and unmarshals an ACME authz type from the database.
func getAuthz(db nosql.DB, id string) (authz, error) {
	b, err := db.Get(authzTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, MalformedErr(errors.Wrapf(err, "authz %s not found", id))
	} else if err != nil {
		return nil, ServerInternalErr(errors.Wrapf(err, "error loading authz %s", id))
	}
	az, err := unmarshalAuthz(b)
	if err != nil {
		return nil, err
	}
	return az, nil
}
