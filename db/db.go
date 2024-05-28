package db

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
	"golang.org/x/crypto/ssh"
)

var (
	certsTable             = []byte("x509_certs")
	certsDataTable         = []byte("x509_certs_data")
	revokedCertsTable      = []byte("revoked_x509_certs")
	crlTable               = []byte("x509_crl")
	revokedSSHCertsTable   = []byte("revoked_ssh_certs")
	usedOTTTable           = []byte("used_ott")
	sshCertsTable          = []byte("ssh_certs")
	sshHostsTable          = []byte("ssh_hosts")
	sshUsersTable          = []byte("ssh_users")
	sshHostPrincipalsTable = []byte("ssh_host_principals")
)

// TODO: at the moment we store a single CRL in the database, in a dedicated table.
// is this acceptable? probably not....
var crlKey = []byte("crl")

// ErrAlreadyExists can be returned if the DB attempts to set a key that has
// been previously set.
var ErrAlreadyExists = errors.New("already exists")

// Config represents the JSON attributes used for configuring a step-ca DB.
type Config struct {
	Type       string `json:"type"`
	DataSource string `json:"dataSource"`
	ValueDir   string `json:"valueDir,omitempty"`
	Database   string `json:"database,omitempty"`

	// BadgerFileLoadingMode can be set to 'FileIO' (instead of the default
	// 'MemoryMap') to avoid memory-mapping log files. This can be useful
	// in environments with low RAM
	BadgerFileLoadingMode string `json:"badgerFileLoadingMode"`
}

// AuthDB is an interface over an Authority DB client that implements a nosql.DB interface.
type AuthDB interface {
	IsRevoked(sn string) (bool, error)
	IsSSHRevoked(sn string) (bool, error)
	Revoke(rci *RevokedCertificateInfo) error
	RevokeSSH(rci *RevokedCertificateInfo) error
	GetCertificate(serialNumber string) (*x509.Certificate, error)
	UseToken(id, tok string) (bool, error)
	IsSSHHost(name string) (bool, error)
	GetSSHHostPrincipals() ([]string, error)
	Shutdown() error
}

type dbKey struct{}

// NewContext adds the given authority database to the context.
func NewContext(ctx context.Context, db AuthDB) context.Context {
	return context.WithValue(ctx, dbKey{}, db)
}

// FromContext returns the current authority database from the given context.
func FromContext(ctx context.Context) (db AuthDB, ok bool) {
	db, ok = ctx.Value(dbKey{}).(AuthDB)
	return
}

// MustFromContext returns the current database from the given context. It
// will panic if it's not in the context.
func MustFromContext(ctx context.Context) AuthDB {
	var (
		db AuthDB
		ok bool
	)
	if db, ok = FromContext(ctx); !ok {
		panic("authority database is not in the context")
	}
	return db
}

// CertificateStorer is an extension of AuthDB that allows to store
// certificates.
type CertificateStorer interface {
	StoreCertificate(crt *x509.Certificate) error
	StoreSSHCertificate(crt *ssh.Certificate) error
}

// CertificateRevocationListDB is an interface to indicate whether the DB supports CRL generation
type CertificateRevocationListDB interface {
	GetRevokedCertificates() (*[]RevokedCertificateInfo, error)
	GetCRL() (*CertificateRevocationListInfo, error)
	StoreCRL(*CertificateRevocationListInfo) error
}

// DB is a wrapper over the nosql.DB interface.
type DB struct {
	nosql.DB
	isUp bool
}

// New returns a new database client that implements the AuthDB interface.
func New(c *Config) (AuthDB, error) {
	if c == nil {
		return newSimpleDB(c)
	}

	opts := []nosql.Option{nosql.WithDatabase(c.Database),
		nosql.WithValueDir(c.ValueDir)}
	if c.BadgerFileLoadingMode != "" {
		opts = append(opts, nosql.WithBadgerFileLoadingMode(c.BadgerFileLoadingMode))
	}

	db, err := nosql.New(c.Type, c.DataSource, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "Error opening database of Type %s", c.Type)
	}

	tables := [][]byte{
		revokedCertsTable, certsTable, usedOTTTable,
		sshCertsTable, sshHostsTable, sshHostPrincipalsTable, sshUsersTable,
		revokedSSHCertsTable, certsDataTable, crlTable,
	}
	for _, b := range tables {
		if err := db.CreateTable(b); err != nil {
			return nil, errors.Wrapf(err, "error creating table %s",
				string(b))
		}
	}

	return &DB{db, true}, nil
}

// RevokedCertificateInfo contains information regarding the certificate
// revocation action.
type RevokedCertificateInfo struct {
	Serial        string
	ProvisionerID string
	ReasonCode    int
	Reason        string
	RevokedAt     time.Time
	ExpiresAt     time.Time
	TokenID       string
	MTLS          bool
	ACME          bool
}

// CertificateRevocationListInfo contains a CRL in DER format and associated
// metadata to allow a decision on whether to regenerate the CRL or not easier
type CertificateRevocationListInfo struct {
	Number    int64
	ExpiresAt time.Time
	Duration  time.Duration
	DER       []byte
}

// IsRevoked returns whether or not a certificate with the given identifier
// has been revoked.
// In the case of an X509 Certificate the `id` should be the Serial Number of
// the Certificate.
func (db *DB) IsRevoked(sn string) (bool, error) {
	// If the DB is nil then act as pass through.
	if db == nil {
		return false, nil
	}

	// If the error is `Not Found` then the certificate has not been revoked.
	// Any other error should be propagated to the caller.
	if _, err := db.Get(revokedCertsTable, []byte(sn)); err != nil {
		if nosql.IsErrNotFound(err) {
			return false, nil
		}
		return false, errors.Wrap(err, "error checking revocation bucket")
	}

	// This certificate has been revoked.
	return true, nil
}

// IsSSHRevoked returns whether or not a certificate with the given identifier
// has been revoked.
// In the case of an X509 Certificate the `id` should be the Serial Number of
// the Certificate.
func (db *DB) IsSSHRevoked(sn string) (bool, error) {
	// If the DB is nil then act as pass through.
	if db == nil {
		return false, nil
	}

	// If the error is `Not Found` then the certificate has not been revoked.
	// Any other error should be propagated to the caller.
	if _, err := db.Get(revokedSSHCertsTable, []byte(sn)); err != nil {
		if nosql.IsErrNotFound(err) {
			return false, nil
		}
		return false, errors.Wrap(err, "error checking revocation bucket")
	}

	// This certificate has been revoked.
	return true, nil
}

// Revoke adds a certificate to the revocation table.
func (db *DB) Revoke(rci *RevokedCertificateInfo) error {
	rcib, err := json.Marshal(rci)
	if err != nil {
		return errors.Wrap(err, "error marshaling revoked certificate info")
	}

	_, swapped, err := db.CmpAndSwap(revokedCertsTable, []byte(rci.Serial), nil, rcib)
	switch {
	case err != nil:
		return errors.Wrap(err, "error AuthDB CmpAndSwap")
	case !swapped:
		return ErrAlreadyExists
	default:
		return nil
	}
}

// RevokeSSH adds a SSH certificate to the revocation table.
func (db *DB) RevokeSSH(rci *RevokedCertificateInfo) error {
	rcib, err := json.Marshal(rci)
	if err != nil {
		return errors.Wrap(err, "error marshaling revoked certificate info")
	}

	_, swapped, err := db.CmpAndSwap(revokedSSHCertsTable, []byte(rci.Serial), nil, rcib)
	switch {
	case err != nil:
		return errors.Wrap(err, "error AuthDB CmpAndSwap")
	case !swapped:
		return ErrAlreadyExists
	default:
		return nil
	}
}

// GetRevokedCertificates gets a list of all revoked certificates.
func (db *DB) GetRevokedCertificates() (*[]RevokedCertificateInfo, error) {
	entries, err := db.List(revokedCertsTable)
	if err != nil {
		return nil, err
	}
	var revokedCerts []RevokedCertificateInfo
	for _, e := range entries {
		var data RevokedCertificateInfo
		if err := json.Unmarshal(e.Value, &data); err != nil {
			return nil, err
		}
		revokedCerts = append(revokedCerts, data)
	}
	return &revokedCerts, nil
}

// StoreCRL stores a CRL in the DB
func (db *DB) StoreCRL(crlInfo *CertificateRevocationListInfo) error {
	crlInfoBytes, err := json.Marshal(crlInfo)
	if err != nil {
		return errors.Wrap(err, "json Marshal error")
	}

	if err := db.Set(crlTable, crlKey, crlInfoBytes); err != nil {
		return errors.Wrap(err, "database Set error")
	}
	return nil
}

// GetCRL gets the existing CRL from the database
func (db *DB) GetCRL() (*CertificateRevocationListInfo, error) {
	crlInfoBytes, err := db.Get(crlTable, crlKey)
	if err != nil {
		return nil, errors.Wrap(err, "database Get error")
	}

	var crlInfo CertificateRevocationListInfo
	err = json.Unmarshal(crlInfoBytes, &crlInfo)
	if err != nil {
		return nil, errors.Wrap(err, "json Unmarshal error")
	}
	return &crlInfo, err
}

// GetCertificate retrieves a certificate by the serial number.
func (db *DB) GetCertificate(serialNumber string) (*x509.Certificate, error) {
	asn1Data, err := db.Get(certsTable, []byte(serialNumber))
	if err != nil {
		return nil, errors.Wrap(err, "database Get error")
	}
	cert, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing certificate with serial number %s", serialNumber)
	}
	return cert, nil
}

// GetCertificateData returns the data stored for a provisioner
func (db *DB) GetCertificateData(serialNumber string) (*CertificateData, error) {
	b, err := db.Get(certsDataTable, []byte(serialNumber))
	if err != nil {
		return nil, errors.Wrap(err, "database Get error")
	}
	var data CertificateData
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling json")
	}
	return &data, nil
}

// StoreCertificate stores a certificate PEM.
func (db *DB) StoreCertificate(crt *x509.Certificate) error {
	if err := db.Set(certsTable, []byte(crt.SerialNumber.String()), crt.Raw); err != nil {
		return errors.Wrap(err, "database Set error")
	}
	return nil
}

// CertificateData is the JSON representation of the data stored in
// x509_certs_data table.
type CertificateData struct {
	Provisioner *ProvisionerData    `json:"provisioner,omitempty"`
	RaInfo      *provisioner.RAInfo `json:"ra,omitempty"`
}

// ProvisionerData is the JSON representation of the provisioner stored in the
// x509_certs_data table.
type ProvisionerData struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type raProvisioner interface {
	RAInfo() *provisioner.RAInfo
}

// StoreCertificateChain stores the leaf certificate and the provisioner that
// authorized the certificate.
func (db *DB) StoreCertificateChain(p provisioner.Interface, chain ...*x509.Certificate) error {
	leaf := chain[0]
	serialNumber := []byte(leaf.SerialNumber.String())
	data := &CertificateData{}
	if p != nil {
		data.Provisioner = &ProvisionerData{
			ID:   p.GetID(),
			Name: p.GetName(),
			Type: p.GetType().String(),
		}
		if rap, ok := p.(raProvisioner); ok {
			data.RaInfo = rap.RAInfo()
		}
	}
	b, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "error marshaling json")
	}
	// Add certificate and certificate data in one transaction.
	tx := new(database.Tx)
	tx.Set(certsTable, serialNumber, leaf.Raw)
	tx.Set(certsDataTable, serialNumber, b)
	if err := db.Update(tx); err != nil {
		return errors.Wrap(err, "database Update error")
	}
	return nil
}

// StoreRenewedCertificate stores the leaf certificate and the provisioner that
// authorized the old certificate if available.
func (db *DB) StoreRenewedCertificate(oldCert *x509.Certificate, chain ...*x509.Certificate) error {
	var certificateData []byte
	if data, err := db.GetCertificateData(oldCert.SerialNumber.String()); err == nil {
		if b, err := json.Marshal(data); err == nil {
			certificateData = b
		}
	}

	leaf := chain[0]
	serialNumber := []byte(leaf.SerialNumber.String())

	// Add certificate and certificate data in one transaction.
	tx := new(database.Tx)
	tx.Set(certsTable, serialNumber, leaf.Raw)
	if certificateData != nil {
		tx.Set(certsDataTable, serialNumber, certificateData)
	}
	if err := db.Update(tx); err != nil {
		return errors.Wrap(err, "database Update error")
	}
	return nil
}

// UseToken returns true if we were able to successfully store the token for
// for the first time, false otherwise.
func (db *DB) UseToken(id, tok string) (bool, error) {
	_, swapped, err := db.CmpAndSwap(usedOTTTable, []byte(id), nil, []byte(tok))
	if err != nil {
		return false, errors.Wrapf(err, "error storing used token %s/%s",
			string(usedOTTTable), id)
	}
	return swapped, nil
}

// IsSSHHost returns if a principal is present in the ssh hosts table.
func (db *DB) IsSSHHost(principal string) (bool, error) {
	if _, err := db.Get(sshHostsTable, []byte(strings.ToLower(principal))); err != nil {
		if database.IsErrNotFound(err) {
			return false, nil
		}
		return false, errors.Wrap(err, "database Get error")
	}
	return true, nil
}

type sshHostPrincipalData struct {
	Serial string
	Expiry uint64
}

// StoreSSHCertificate stores an SSH certificate.
func (db *DB) StoreSSHCertificate(crt *ssh.Certificate) error {
	serial := strconv.FormatUint(crt.Serial, 10)
	tx := new(database.Tx)
	tx.Set(sshCertsTable, []byte(serial), crt.Marshal())
	if crt.CertType == ssh.HostCert {
		for _, p := range crt.ValidPrincipals {
			hostPrincipalData, err := json.Marshal(sshHostPrincipalData{
				Serial: serial,
				Expiry: crt.ValidBefore,
			})
			if err != nil {
				return err
			}
			tx.Set(sshHostsTable, []byte(strings.ToLower(p)), []byte(serial))
			tx.Set(sshHostPrincipalsTable, []byte(strings.ToLower(p)), hostPrincipalData)
		}
	} else {
		for _, p := range crt.ValidPrincipals {
			tx.Set(sshUsersTable, []byte(strings.ToLower(p)), []byte(serial))
		}
	}
	if err := db.Update(tx); err != nil {
		return errors.Wrap(err, "database Update error")
	}
	return nil
}

// GetSSHHostPrincipals gets a list of all valid host principals.
func (db *DB) GetSSHHostPrincipals() ([]string, error) {
	entries, err := db.List(sshHostPrincipalsTable)
	if err != nil {
		return nil, err
	}
	var principals []string
	for _, e := range entries {
		var data sshHostPrincipalData
		if err := json.Unmarshal(e.Value, &data); err != nil {
			return nil, err
		}
		if time.Unix(int64(data.Expiry), 0).After(time.Now()) {
			principals = append(principals, string(e.Key))
		}
	}
	return principals, nil
}

// Shutdown sends a shutdown message to the database.
func (db *DB) Shutdown() error {
	if db.isUp {
		if err := db.Close(); err != nil {
			return errors.Wrap(err, "database shutdown error")
		}
		db.isUp = false
	}
	return nil
}

// MockAuthDB mocks the AuthDB interface. //
type MockAuthDB struct {
	Err                     error
	Ret1                    interface{}
	MIsRevoked              func(string) (bool, error)
	MIsSSHRevoked           func(string) (bool, error)
	MRevoke                 func(rci *RevokedCertificateInfo) error
	MRevokeSSH              func(rci *RevokedCertificateInfo) error
	MGetCertificate         func(serialNumber string) (*x509.Certificate, error)
	MGetCertificateData     func(serialNumber string) (*CertificateData, error)
	MStoreCertificate       func(crt *x509.Certificate) error
	MUseToken               func(id, tok string) (bool, error)
	MIsSSHHost              func(principal string) (bool, error)
	MStoreSSHCertificate    func(crt *ssh.Certificate) error
	MGetSSHHostPrincipals   func() ([]string, error)
	MShutdown               func() error
	MGetRevokedCertificates func() (*[]RevokedCertificateInfo, error)
	MGetCRL                 func() (*CertificateRevocationListInfo, error)
	MStoreCRL               func(*CertificateRevocationListInfo) error
}

func (m *MockAuthDB) GetRevokedCertificates() (*[]RevokedCertificateInfo, error) {
	if m.MGetRevokedCertificates != nil {
		return m.MGetRevokedCertificates()
	}
	return m.Ret1.(*[]RevokedCertificateInfo), m.Err
}

func (m *MockAuthDB) GetCRL() (*CertificateRevocationListInfo, error) {
	if m.MGetCRL != nil {
		return m.MGetCRL()
	}
	return m.Ret1.(*CertificateRevocationListInfo), m.Err
}

func (m *MockAuthDB) StoreCRL(info *CertificateRevocationListInfo) error {
	if m.MStoreCRL != nil {
		return m.MStoreCRL(info)
	}
	return m.Err
}

// IsRevoked mock.
func (m *MockAuthDB) IsRevoked(sn string) (bool, error) {
	if m.MIsRevoked != nil {
		return m.MIsRevoked(sn)
	}
	return m.Ret1.(bool), m.Err
}

// IsSSHRevoked mock.
func (m *MockAuthDB) IsSSHRevoked(sn string) (bool, error) {
	if m.MIsSSHRevoked != nil {
		return m.MIsSSHRevoked(sn)
	}
	return m.Ret1.(bool), m.Err
}

// UseToken mock.
func (m *MockAuthDB) UseToken(id, tok string) (bool, error) {
	if m.MUseToken != nil {
		return m.MUseToken(id, tok)
	}
	if m.Ret1 == nil {
		return false, m.Err
	}
	return m.Ret1.(bool), m.Err
}

// Revoke mock.
func (m *MockAuthDB) Revoke(rci *RevokedCertificateInfo) error {
	if m.MRevoke != nil {
		return m.MRevoke(rci)
	}
	return m.Err
}

// RevokeSSH mock.
func (m *MockAuthDB) RevokeSSH(rci *RevokedCertificateInfo) error {
	if m.MRevokeSSH != nil {
		return m.MRevokeSSH(rci)
	}
	return m.Err
}

// GetCertificate mock.
func (m *MockAuthDB) GetCertificate(serialNumber string) (*x509.Certificate, error) {
	if m.MGetCertificate != nil {
		return m.MGetCertificate(serialNumber)
	}
	return m.Ret1.(*x509.Certificate), m.Err
}

// GetCertificateData mock.
func (m *MockAuthDB) GetCertificateData(serialNumber string) (*CertificateData, error) {
	if m.MGetCertificateData != nil {
		return m.MGetCertificateData(serialNumber)
	}
	if cd, ok := m.Ret1.(*CertificateData); ok {
		return cd, m.Err
	}
	return nil, m.Err
}

// StoreCertificate mock.
func (m *MockAuthDB) StoreCertificate(crt *x509.Certificate) error {
	if m.MStoreCertificate != nil {
		return m.MStoreCertificate(crt)
	}
	return m.Err
}

// IsSSHHost mock.
func (m *MockAuthDB) IsSSHHost(principal string) (bool, error) {
	if m.MIsSSHHost != nil {
		return m.MIsSSHHost(principal)
	}
	return m.Ret1.(bool), m.Err
}

// StoreSSHCertificate mock.
func (m *MockAuthDB) StoreSSHCertificate(crt *ssh.Certificate) error {
	if m.MStoreSSHCertificate != nil {
		return m.MStoreSSHCertificate(crt)
	}
	return m.Err
}

// GetSSHHostPrincipals mock.
func (m *MockAuthDB) GetSSHHostPrincipals() ([]string, error) {
	if m.MGetSSHHostPrincipals != nil {
		return m.MGetSSHHostPrincipals()
	}
	return m.Ret1.([]string), m.Err
}

// Shutdown mock.
func (m *MockAuthDB) Shutdown() error {
	if m.MShutdown != nil {
		return m.MShutdown()
	}
	return m.Err
}

// MockNoSQLDB //
type MockNoSQLDB struct {
	Err          error
	Ret1, Ret2   interface{}
	MGet         func(bucket, key []byte) ([]byte, error)
	MSet         func(bucket, key, value []byte) error
	MOpen        func(dataSourceName string, opt ...database.Option) error
	MClose       func() error
	MCreateTable func(bucket []byte) error
	MDeleteTable func(bucket []byte) error
	MDel         func(bucket, key []byte) error
	MList        func(bucket []byte) ([]*database.Entry, error)
	MUpdate      func(tx *database.Tx) error
	MCmpAndSwap  func(bucket, key, old, newval []byte) ([]byte, bool, error)
}

// CmpAndSwap mock
func (m *MockNoSQLDB) CmpAndSwap(bucket, key, old, newval []byte) ([]byte, bool, error) {
	if m.MCmpAndSwap != nil {
		return m.MCmpAndSwap(bucket, key, old, newval)
	}
	if m.Ret1 == nil {
		return nil, false, m.Err
	}
	return m.Ret1.([]byte), m.Ret2.(bool), m.Err
}

// Get mock
func (m *MockNoSQLDB) Get(bucket, key []byte) ([]byte, error) {
	if m.MGet != nil {
		return m.MGet(bucket, key)
	}
	if m.Ret1 == nil {
		return nil, m.Err
	}
	return m.Ret1.([]byte), m.Err
}

// Set mock
func (m *MockNoSQLDB) Set(bucket, key, value []byte) error {
	if m.MSet != nil {
		return m.MSet(bucket, key, value)
	}
	return m.Err
}

// Open mock
func (m *MockNoSQLDB) Open(dataSourceName string, opt ...database.Option) error {
	if m.MOpen != nil {
		return m.MOpen(dataSourceName, opt...)
	}
	return m.Err
}

// Close mock
func (m *MockNoSQLDB) Close() error {
	if m.MClose != nil {
		return m.MClose()
	}
	return m.Err
}

// CreateTable mock
func (m *MockNoSQLDB) CreateTable(bucket []byte) error {
	if m.MCreateTable != nil {
		return m.MCreateTable(bucket)
	}
	return m.Err
}

// DeleteTable mock
func (m *MockNoSQLDB) DeleteTable(bucket []byte) error {
	if m.MDeleteTable != nil {
		return m.MDeleteTable(bucket)
	}
	return m.Err
}

// Del mock
func (m *MockNoSQLDB) Del(bucket, key []byte) error {
	if m.MDel != nil {
		return m.MDel(bucket, key)
	}
	return m.Err
}

// List mock
func (m *MockNoSQLDB) List(bucket []byte) ([]*database.Entry, error) {
	if m.MList != nil {
		return m.MList(bucket)
	}
	return m.Ret1.([]*database.Entry), m.Err
}

// Update mock
func (m *MockNoSQLDB) Update(tx *database.Tx) error {
	if m.MUpdate != nil {
		return m.MUpdate(tx)
	}
	return m.Err
}
