package acme

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
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
	Type       string  `json:"type"`
	Status     string  `json:"status"`
	Token      string  `json:"token"`
	Validated  string  `json:"validated,omitempty"`
	URL        string  `json:"url"`
	Error      *AError `json:"error,omitempty"`
	RetryAfter string  `json:"retry_after,omitempty"`
	ID         string  `json:"-"`
	AuthzID    string  `json:"-"`
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
type tlsDialer func(network, addr string, config *tls.Config) (*tls.Conn, error)

type validateOptions struct {
	httpGet   httpGetter
	lookupTxt lookupTxt
	tlsDial   tlsDialer
}

// challenge is the interface ACME challenege types must implement.
type challenge interface {
	save(db nosql.DB, swap challenge) error
	validate(*jose.JSONWebKey, validateOptions) (challenge, error)
	getType() string
	getError() *AError
	getValue() string
	getStatus() string
	getID() string
	getAuthzID() string
	getToken() string
	getRetry() *Retry
	clone() *baseChallenge
	getAccountID() string
	getValidated() time.Time
	getCreated() time.Time
	toACME(*directory, provisioner.Interface) (*Challenge, error)
}

// ChallengeOptions is the type used to created a new Challenge.
type ChallengeOptions struct {
	AccountID     string
	AuthzID       string
	ProvisionerID string
	Identifier    Identifier
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
	Created   time.Time `json:"created"`
	Validated time.Time `json:"validated"`
	Error     *AError   `json:"error"`
	Retry     *Retry    `json:"retry"`
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

// getRetry returns the retry state of the baseChallenge
func (bc *baseChallenge) getRetry() *Retry {
	return bc.Retry
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
func (bc *baseChallenge) toACME(dir *directory, p provisioner.Interface) (*Challenge, error) {
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
	if bc.Retry != nil && bc.Status == StatusProcessing {
		ac.RetryAfter = bc.Retry.NextAttempt
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
	r := *bc.Retry
	u.Retry = &r
	return &u
}

func (bc *baseChallenge) validate(jwk *jose.JSONWebKey, vo validateOptions) (challenge, error) {
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
	case "tls-alpn-01":
		var bc baseChallenge
		if err := json.Unmarshal(data, &bc); err != nil {
			return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling "+
				"challenge type into tlsALPN01Challenge"))
		}
		return &tlsALPN01Challenge{&bc}, nil
	default:
		return nil, ServerInternalErr(errors.Errorf("unexpected challenge type %s", getType.Type))
	}
}

// Challenge retry information is internally relevant and needs to be stored in the DB, but should not be part
// of the public challenge API apart from the Retry-After header.
type Retry struct {
	Owner         int    `json:"owner"`
	ProvisionerID string `json:"provisionerid"`
	NumAttempts   int    `json:"numattempts"`
	MaxAttempts   int    `json:"maxattempts"`
	NextAttempt   string `json:"nextattempt"`
}

func (r *Retry) Active() bool {
	return r.NumAttempts < r.MaxAttempts
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
func (hc *http01Challenge) validate(jwk *jose.JSONWebKey, vo validateOptions) (challenge, error) {
	// If already valid or invalid then return without performing validation.
	switch hc.getStatus() {
	case StatusPending:
		panic("pending challenges must first be moved to the processing state")
	case StatusProcessing:
		break
	case StatusValid, StatusInvalid:
		return hc, nil
	default:
		panic("unknown challenge state: " + hc.getStatus())
	}

	up := &http01Challenge{hc.baseChallenge.clone()}

	url := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", hc.Value, hc.Token)
	resp, err := vo.httpGet(url)
	if err != nil {
		e := errors.Wrapf(err, "error doing http GET for url %s", url)
		up.Error = ConnectionErr(e).ToACME()
		return up, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		e := errors.Errorf("error doing http GET for url %s with status code %d", url, resp.StatusCode)
		up.Error = ConnectionErr(e).ToACME()
		return up, nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		e := errors.Wrapf(err, "error reading response body for url %s", url)
		up.Error = ServerInternalErr(e).ToACME()
		return up, nil
	}

	keyAuth := strings.Trim(string(body), "\r\n")
	expected, err := KeyAuthorization(hc.Token, jwk)
	if err != nil {
		return nil, err
	}
	if keyAuth != expected {
		// add base challenge fail validation
		e := errors.Errorf("keyAuthorization does not match; expected %s, but got %s", expected, keyAuth)
		up.Error = RejectedIdentifierErr(e).ToACME()
		up.Status = StatusInvalid
		return up, nil
	}

	up.Status = StatusValid
	up.Validated = clock.Now()
	up.Error = nil
	up.Retry = nil
	return up, nil
}

type tlsALPN01Challenge struct {
	*baseChallenge
}

// newTLSALPN01Challenge returns a new acme tls-alpn-01 challenge.
func newTLSALPN01Challenge(db nosql.DB, ops ChallengeOptions) (challenge, error) {
	bc, err := newBaseChallenge(ops.AccountID, ops.AuthzID)
	if err != nil {
		return nil, err
	}
	bc.Type = "tls-alpn-01"
	bc.Value = ops.Identifier.Value

	tc := &tlsALPN01Challenge{bc}
	if err := tc.save(db, nil); err != nil {
		return nil, err
	}
	return tc, nil
}

func (tc *tlsALPN01Challenge) validate(jwk *jose.JSONWebKey, vo validateOptions) (challenge, error) {
	// If already valid or invalid then return without performing validation.
	switch tc.getStatus() {
	case StatusPending:
		panic("pending challenges must first be moved to the processing state")
	case StatusProcessing:
		break
	case StatusValid, StatusInvalid:
		return tc, nil
	default:
		panic("unknown challenge state: " + tc.getStatus())
	}

	up := &tlsALPN01Challenge{tc.baseChallenge.clone()}

	config := &tls.Config{
		NextProtos:         []string{"acme-tls/1"},
		ServerName:         tc.Value,
		InsecureSkipVerify: true, // we expect a self-signed challenge certificate
	}
	hostPort := net.JoinHostPort(tc.Value, "443")
	conn, err := vo.tlsDial("tcp", hostPort, config)
	if err != nil {
		e := errors.Wrapf(err, "error doing TLS dial for %s", hostPort)
		up.Error = ConnectionErr(e).ToACME()
		return up, nil
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	certs := cs.PeerCertificates

	if len(certs) == 0 {
		e := errors.Errorf("%s challenge for %s resulted in no certificates", tc.Type, tc.Value)
		up.Error = RejectedIdentifierErr(e).ToACME()
		return up, nil
	}
	if !cs.NegotiatedProtocolIsMutual || cs.NegotiatedProtocol != "acme-tls/1" {
		e := errors.Errorf("cannot negotiate ALPN acme-tls/1 protocol for tls-alpn-01 challenge")
		up.Error = RejectedIdentifierErr(e).ToACME()
		return up, nil
	}

	leafCert := certs[0]
	if len(leafCert.DNSNames) != 1 || !strings.EqualFold(leafCert.DNSNames[0], tc.Value) {
		e := errors.Errorf("incorrect certificate for tls-alpn-01 challenge: "+
			"leaf certificate must contain a single DNS name, %v", tc.Value)
		up.Error = RejectedIdentifierErr(e).ToACME()
		return up, nil
	}

	idPeAcmeIdentifier := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}
	idPeAcmeIdentifierV1Obsolete := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 30, 1}
	foundIDPeAcmeIdentifierV1Obsolete := false

	keyAuth, err := KeyAuthorization(tc.Token, jwk)
	if err != nil {
		return nil, err
	}
	hashedKeyAuth := sha256.Sum256([]byte(keyAuth))

	for _, ext := range leafCert.Extensions {
		if idPeAcmeIdentifier.Equal(ext.Id) {
			if !ext.Critical {
				e := errors.Errorf("incorrect certificate for tls-alpn-01 challenge: " +
					"acmeValidationV1 extension not critical")
				up.Error = IncorrectResponseErr(e).ToACME()
				return up, nil
			}

			var extValue []byte
			rest, err := asn1.Unmarshal(ext.Value, &extValue)

			if err != nil || len(rest) > 0 || len(hashedKeyAuth) != len(extValue) {
				e := errors.Errorf("incorrect certificate for tls-alpn-01 challenge: " +
					"malformed acmeValidationV1 extension value")
				up.Error = IncorrectResponseErr(e).ToACME()
				return up, nil
			}

			if subtle.ConstantTimeCompare(hashedKeyAuth[:], extValue) != 1 {
				e := errors.Errorf("incorrect certificate for tls-alpn-01 challenge: "+
					"expected acmeValidationV1 extension value %s for this challenge but got %s",
					hex.EncodeToString(hashedKeyAuth[:]), hex.EncodeToString(extValue))
				up.Error = IncorrectResponseErr(e).ToACME()
				// There is an appropriate value, but it doesn't match.
				up.Status = StatusInvalid
				return up, nil
			}

			up.Validated = clock.Now()
			up.Status = StatusValid
			up.Error = nil
			up.Retry = nil
			return up, nil
		}

		if idPeAcmeIdentifierV1Obsolete.Equal(ext.Id) {
			foundIDPeAcmeIdentifierV1Obsolete = true
		}
	}

	if foundIDPeAcmeIdentifierV1Obsolete {
		e := errors.Errorf("incorrect certificate for tls-alpn-01 challenge: " +
			"obsolete id-pe-acmeIdentifier in acmeValidationV1 extension")
		up.Error = IncorrectResponseErr(e).ToACME()
		return up, nil
	}

	e := errors.Errorf("incorrect certificate for tls-alpn-01 challenge: " +
		"missing acmeValidationV1 extension")
	up.Error = IncorrectResponseErr(e).ToACME()
	return tc, nil
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

// validate attempts to validate the challenge. If the challenge has been
// satisfactorily validated, the 'status' and 'validated' attributes are
// updated.
func (dc *dns01Challenge) validate(jwk *jose.JSONWebKey, vo validateOptions) (challenge, error) {
	// If already valid or invalid then return without performing validation.
	switch dc.getStatus() {
	case StatusPending:
		panic("pending challenges must first be moved to the processing state")
	case StatusProcessing:
		break
	case StatusValid, StatusInvalid:
		return dc, nil
	default:
		panic("unknown challenge state: " + dc.getStatus())
	}

	up := &dns01Challenge{dc.baseChallenge.clone()}

	// Normalize domain for wildcard DNS names
	// This is done to avoid making TXT lookups for domains like
	// _acme-challenge.*.example.com
	// Instead perform txt lookup for _acme-challenge.example.com
	domain := strings.TrimPrefix(dc.Value, "*.")
	record := "_acme-challenge." + domain

	txtRecords, err := vo.lookupTxt(record)
	if err != nil {
		e := errors.Wrapf(err, "error looking up TXT records for domain %s", domain)
		up.Error = DNSErr(e).ToACME()
		return dc, nil
	}

	expectedKeyAuth, err := KeyAuthorization(dc.Token, jwk)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256([]byte(expectedKeyAuth))
	expected := base64.RawURLEncoding.EncodeToString(h[:])

	if len(txtRecords) == 0 {
		e := errors.Errorf("no TXT record found at '%s'", record)
		up.Error = DNSErr(e).ToACME()
		return up, nil
	}

	for _, r := range txtRecords {
		if r == expected {
			up.Validated = time.Now().UTC()
			up.Status = StatusValid
			up.Error = nil
			up.Retry = nil
			return up, nil
		}
	}

	up.Status = StatusInvalid
	e := errors.Errorf("keyAuthorization does not match; expected %s, but got %s",
		expectedKeyAuth, txtRecords)
	up.Error = IncorrectResponseErr(e).ToACME()
	return up, nil
}

// KeyAuthorization creates the ACME key authorization value from a token
// and a jwk.
func KeyAuthorization(token string, jwk *jose.JSONWebKey) (string, *Error) {
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", ServerInternalErr(errors.Wrap(err, "error generating JWK thumbprint"))
	}
	encPrint := base64.RawURLEncoding.EncodeToString(thumbprint)
	return fmt.Sprintf("%s.%s", token, encPrint), nil
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
