package db

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/db/sql"
	sqlDatabase "github.com/smallstep/certificates/db/sql/sql"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
	"golang.org/x/crypto/ssh"
)

var (
	certsTable             = []byte("x509_certs")
	revokedCertsTable      = []byte("revoked_x509_certs")
	revokedSSHCertsTable   = []byte("revoked_ssh_certs")
	certSANsTable          = []byte("x509_sans")
	certExtensionsTable    = []byte("x509_extensions")
	usedOTTTable           = []byte("used_ott")
	sshCertsTable          = []byte("ssh_certs")
	sshHostsTable          = []byte("ssh_hosts")
	sshUsersTable          = []byte("ssh_users")
	sshHostPrincipalsTable = []byte("ssh_host_principals")
)

// ErrAlreadyExists can be returned if the DB attempts to set a key that has
// been previously set.
var ErrAlreadyExists = errors.New("already exists")

// Config represents the JSON attributes used for configuring a step-ca DB.
type Config struct {
	Type       string `json:"type"`
	DataSource string `json:"dataSource"`
	ValueDir   string `json:"valueDir,omitempty"`
	Database   string `json:"database,omitempty"`
	EnableSQL  bool   `json:"enableSQL,omitempty"`

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
	GetCertificate(ctx context.Context, serialNumber string) (*x509.Certificate, error)
	StoreCertificate(crt *x509.Certificate) error
	UseToken(id, tok string) (bool, error)
	IsSSHHost(name string) (bool, error)
	StoreSSHCertificate(crt *ssh.Certificate) error
	GetSSHHostPrincipals() ([]string, error)
	Shutdown() error
}

// DB is a wrapper over the nosql.DB interface.
type NoSQLDB struct {
	nosql.DB
	isUp bool
}

// DB is a wrapper over the SQLDB interface.
type SQLDB struct {
	sql.DB
	isUp bool
}

// New returns a new database client that implements the AuthDB interface.
func New(c *Config) (AuthDB, error) {
	if c == nil {
		return newSimpleDB(c)
	}

	if c.EnableSQL {
		opts := []sqlDatabase.SQLOption{sqlDatabase.WithDatabase(c.Database)}
		// Initialize step-ca with SQL DB
		db, err := sql.New(c.Type, c.DataSource, opts...)
		if err != nil {
			return nil, errors.Wrapf(err, "Error opening database of Type %s with source %s", c.Type, c.DataSource)
		}
		tables := [][]byte{
			revokedCertsTable, usedOTTTable,
			sshCertsTable, sshHostsTable, sshHostPrincipalsTable, sshUsersTable,
			revokedSSHCertsTable,
		}
		for _, b := range tables {
			if err := db.CreateTable(b); err != nil {
				return nil, errors.Wrapf(err, "error creating table %s",
					string(b))
			}
		}
		// Separate schema for Certs Table so that queries on these tables can be done in the future.
		if err := db.CreateX509CertificateTable(certsTable); err != nil {
			return nil, errors.Wrapf(err, "error creating table %s",
				string(certsTable))
		}
		if err := db.CreateX509CertificateSansTable(certSANsTable, []byte("CertSans"), certsTable); err != nil {
			return nil, errors.Wrapf(err, "error creating table %s",
				string(certSANsTable))
		}
		if err := db.CreateX509CertificateExtensionsTable(certExtensionsTable, []byte("CertExtensions"), certsTable); err != nil {
			return nil, errors.Wrapf(err, "error creating table %s",
				string(certSANsTable))
		}

		return &SQLDB{db, true}, nil

	}
	opts := []nosql.Option{nosql.WithDatabase(c.Database),
		nosql.WithValueDir(c.ValueDir)}
	if len(c.BadgerFileLoadingMode) > 0 {
		opts = append(opts, nosql.WithBadgerFileLoadingMode(c.BadgerFileLoadingMode))
	}
	db, err := nosql.New(c.Type, c.DataSource, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "Error opening database of Type %s with source %s", c.Type, c.DataSource)
	}
	tables := [][]byte{
		revokedCertsTable, certsTable, usedOTTTable,
		sshCertsTable, sshHostsTable, sshHostPrincipalsTable, sshUsersTable,
		revokedSSHCertsTable,
	}
	for _, b := range tables {
		if err := db.CreateTable(b); err != nil {
			return nil, errors.Wrapf(err, "error creating table %s",
				string(b))
		}
	}
	return &NoSQLDB{db, true}, nil

}

// RevokedCertificateInfo contains information regarding the certificate
// revocation action.
type RevokedCertificateInfo struct {
	Serial        string
	ProvisionerID string
	ReasonCode    int
	Reason        string
	RevokedAt     time.Time
	TokenID       string
	MTLS          bool
}

// IsRevoked returns whether or not a certificate with the given identifier
// has been revoked.
// In the case of an X509 Certificate the `id` should be the Serial Number of
// the Certificate.
func (db *NoSQLDB) IsRevoked(sn string) (bool, error) {
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
func (db *NoSQLDB) IsSSHRevoked(sn string) (bool, error) {
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
func (db *NoSQLDB) Revoke(rci *RevokedCertificateInfo) error {
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
func (db *NoSQLDB) RevokeSSH(rci *RevokedCertificateInfo) error {
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

// GetCertificate retrieves a certificate by the serial number.
func (db *NoSQLDB) GetCertificate(ctx context.Context, serialNumber string) (*x509.Certificate, error) {
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

// StoreCertificate stores a certificate PEM.
func (db *NoSQLDB) StoreCertificate(crt *x509.Certificate) error {
	if err := db.Set(certsTable, []byte(crt.SerialNumber.String()), crt.Raw); err != nil {
		return errors.Wrap(err, "database Set error")
	}
	return nil
}

// UseToken returns true if we were able to successfully store the token for
// for the first time, false otherwise.
func (db *NoSQLDB) UseToken(id, tok string) (bool, error) {
	_, swapped, err := db.CmpAndSwap(usedOTTTable, []byte(id), nil, []byte(tok))
	if err != nil {
		return false, errors.Wrapf(err, "error storing used token %s/%s",
			string(usedOTTTable), id)
	}
	return swapped, nil
}

// IsSSHHost returns if a principal is present in the ssh hosts table.
func (db *NoSQLDB) IsSSHHost(principal string) (bool, error) {
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
func (db *NoSQLDB) StoreSSHCertificate(crt *ssh.Certificate) error {
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
func (db *NoSQLDB) GetSSHHostPrincipals() ([]string, error) {
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
func (db *NoSQLDB) Shutdown() error {
	if db.isUp {
		if err := db.Close(); err != nil {
			return errors.Wrap(err, "database shutdown error")
		}
		db.isUp = false
	}
	return nil
}

// IsRevoked returns whether or not a certificate with the given identifier
// has been revoked.
// In the case of an X509 Certificate the `id` should be the Serial Number of
// the Certificate.
func (db *SQLDB) IsRevoked(sn string) (bool, error) {
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
func (db *SQLDB) IsSSHRevoked(sn string) (bool, error) {
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
func (db *SQLDB) Revoke(rci *RevokedCertificateInfo) error {
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
func (db *SQLDB) RevokeSSH(rci *RevokedCertificateInfo) error {
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

// GetCertificate retrieves a certificate by the serial number.
func (db *SQLDB) GetCertificate(ctx context.Context, serialNumber string) (*x509.Certificate, error) {
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

var (
	stepOIDRoot        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64}
	stepOIDProvisioner = append(asn1.ObjectIdentifier(nil), append(stepOIDRoot, 1)...)
)

type stepProvisionerASN1 struct {
	Type          int
	Name          []byte
	CredentialID  []byte
	KeyValuePairs []string `asn1:"optional,omitempty"`
}

// StoreCertificate stores a certificate PEM.
func (db *SQLDB) StoreCertificate(crt *x509.Certificate) error {
	var provisioner stepProvisionerASN1
	for _, e := range crt.Extensions {
		if e.Id.Equal(stepOIDProvisioner) {
			if _, err := asn1.Unmarshal(e.Value, &provisioner); err != nil {
				return errors.Wrap(err, "Cert did not unmarshal.")
			}
		}
	}
	if provisioner.Name == nil {
		provisioner.Name = []byte("NA")
	}

	if err := db.SetX509Certificate(certsTable, []byte(crt.SerialNumber.String()), crt.Raw, certExtensionsTable, certSANsTable, string(provisioner.Name)); err != nil {
		return errors.Wrap(err, "database Set error")
	}
	return nil
}

// UseToken returns true if we were able to successfully store the token for
// for the first time, false otherwise.
func (db *SQLDB) UseToken(id, tok string) (bool, error) {
	_, swapped, err := db.CmpAndSwap(usedOTTTable, []byte(id), nil, []byte(tok))
	if err != nil {
		return false, errors.Wrapf(err, "error storing used token %s/%s",
			string(usedOTTTable), id)
	}
	return swapped, nil
}

// IsSSHHost returns if a principal is present in the ssh hosts table.
func (db *SQLDB) IsSSHHost(principal string) (bool, error) {
	if _, err := db.Get(sshHostsTable, []byte(strings.ToLower(principal))); err != nil {
		if database.IsErrNotFound(err) {
			return false, nil
		}
		return false, errors.Wrap(err, "database Get error")
	}
	return true, nil
}

// StoreSSHCertificate stores an SSH certificate.
func (db *SQLDB) StoreSSHCertificate(crt *ssh.Certificate) error {
	serial := strconv.FormatUint(crt.Serial, 10)
	tx := new(sqlDatabase.Tx)
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
func (db *SQLDB) GetSSHHostPrincipals() ([]string, error) {
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
func (db *SQLDB) Shutdown() error {
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
	Err                   error
	Ret1                  interface{}
	MIsRevoked            func(string) (bool, error)
	MIsSSHRevoked         func(string) (bool, error)
	MRevoke               func(rci *RevokedCertificateInfo) error
	MRevokeSSH            func(rci *RevokedCertificateInfo) error
	MGetCertificate       func(serialNumber string) (*x509.Certificate, error)
	MStoreCertificate     func(crt *x509.Certificate) error
	MUseToken             func(id, tok string) (bool, error)
	MIsSSHHost            func(principal string) (bool, error)
	MStoreSSHCertificate  func(crt *ssh.Certificate) error
	MGetSSHHostPrincipals func() ([]string, error)
	MShutdown             func() error
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

// MockNoSQLDB //
type MockSQLDB struct {
	Err                                   error
	Ret1, Ret2                            interface{}
	MGet                                  func(bucket, key []byte) ([]byte, error)
	MSet                                  func(bucket, key, value []byte) error
	MCreateX509CertificateTable           func(bucket []byte) error
	MCreateX509CertificateSansTable       func(bucket, constraint, reference []byte) error
	MCreateX509CertificateExtensionsTable func(bucket, constraint, reference []byte) error
	MOpen                                 func(dataSourceName string, opt ...sqlDatabase.SQLOption) error
	MSetX509Certificate                   func(bucket, key, value []byte, extensionBucket []byte, dnsNameBucket []byte, provisionerName string) error
	MListPage                             func(bucket []byte, limit int, offset int) ([]*database.Entry, error)
	MCmpAndSwapACMECertificate            func(bucket []byte, key []byte, cert *x509.Certificate, oldValue, newValue, extensionBucket, dnsNameBucket []byte, provisionerName string) ([]byte, bool, error)
	MClose                                func() error
	MCreateTable                          func(bucket []byte) error
	MDeleteTable                          func(bucket []byte) error
	MDel                                  func(bucket, key []byte) error
	MList                                 func(bucket []byte) ([]*database.Entry, error)
	MUpdate                               func(tx *sqlDatabase.Tx) error
	MCount                                func(bucket []byte) (int, error)
	MCmpAndSwap                           func(bucket, key, old, newval []byte) ([]byte, bool, error)
}

// MCmpAndSwapACMECertificate mock
func (m *MockSQLDB) CmpAndSwapACMECertificate(bucket []byte, key []byte, cert *x509.Certificate, oldValue, newValue, extensionBucket, dnsNameBucket []byte, provisionerName string) ([]byte, bool, error) {
	if m.MCmpAndSwap != nil {
		return m.MCmpAndSwapACMECertificate(bucket, key, cert, oldValue, newValue, extensionBucket, dnsNameBucket, provisionerName)
	}
	if m.Ret1 == nil {
		return nil, false, m.Err
	}
	return m.Ret1.([]byte), m.Ret2.(bool), m.Err
}

// CmpAndSwap mock
func (m *MockSQLDB) CmpAndSwap(bucket, key, old, newval []byte) ([]byte, bool, error) {
	if m.MCmpAndSwap != nil {
		return m.MCmpAndSwap(bucket, key, old, newval)
	}
	if m.Ret1 == nil {
		return nil, false, m.Err
	}
	return m.Ret1.([]byte), m.Ret2.(bool), m.Err
}

// Get mock
func (m *MockSQLDB) Get(bucket, key []byte) ([]byte, error) {
	if m.MGet != nil {
		return m.MGet(bucket, key)
	}
	if m.Ret1 == nil {
		return nil, m.Err
	}
	return m.Ret1.([]byte), m.Err
}

// MSetX509Certificate mock
func (m *MockSQLDB) SetX509Certificate(bucket, key, value []byte, extensionBucket []byte, dnsNameBucket []byte, provisionerName string) error {
	if m.MSetX509Certificate != nil {
		return m.MSetX509Certificate(certsTable, []byte("SERIALNUMBER"), []byte("RAW CERT"), certExtensionsTable, certSANsTable, provisionerName)
	}
	return m.Err
}

// Set mock
func (m *MockSQLDB) Set(bucket, key, value []byte) error {
	if m.MSet != nil {
		return m.MSet(bucket, key, value)
	}
	return m.Err
}

// Set mock
func (m *MockSQLDB) Count(bucket []byte) (int, error) {
	if m.MSet != nil {
		return m.MCount(bucket)
	}
	return 1, nil
}

// Open mock
func (m *MockSQLDB) Open(dataSourceName string, opt ...sqlDatabase.SQLOption) error {
	if m.MOpen != nil {
		return m.MOpen(dataSourceName, opt...)
	}
	return m.Err
}

// Close mock
func (m *MockSQLDB) Close() error {
	if m.MClose != nil {
		return m.MClose()
	}
	return m.Err
}

// CreateX509CertificateSansTable mock
func (m *MockSQLDB) CreateX509CertificateSansTable(bucket, constraint, reference []byte) error {
	if m.MCreateX509CertificateSansTable != nil {
		return m.MCreateX509CertificateSansTable(bucket, constraint, reference)
	}
	return m.Err
}

// CreateX509CertificateExtensionsTable mock
func (m *MockSQLDB) CreateX509CertificateExtensionsTable(bucket, constraint, reference []byte) error {
	if m.MCreateX509CertificateExtensionsTable != nil {
		return m.MCreateX509CertificateExtensionsTable(bucket, constraint, reference)
	}
	return m.Err
}

// CreateX509CertificateTable mock
func (m *MockSQLDB) CreateX509CertificateTable(bucket []byte) error {
	if m.MCreateX509CertificateTable != nil {
		return m.MCreateX509CertificateTable(bucket)
	}
	return m.Err
}

// CreateTable mock
func (m *MockSQLDB) CreateTable(bucket []byte) error {
	if m.MCreateTable != nil {
		return m.MCreateTable(bucket)
	}
	return m.Err
}

// DeleteTable mock
func (m *MockSQLDB) DeleteTable(bucket []byte) error {
	if m.MDeleteTable != nil {
		return m.MDeleteTable(bucket)
	}
	return m.Err
}

// Del mock
func (m *MockSQLDB) Del(bucket, key []byte) error {
	if m.MDel != nil {
		return m.MDel(bucket, key)
	}
	return m.Err
}

// List mock
func (m *MockSQLDB) List(bucket []byte) ([]*database.Entry, error) {
	if m.MList != nil {
		return m.MList(bucket)
	}
	return m.Ret1.([]*database.Entry), m.Err
}

// Update mock
func (m *MockSQLDB) Update(tx *sqlDatabase.Tx) error {
	if m.MUpdate != nil {
		return m.MUpdate(tx)
	}
	return m.Err
}

// ListPage mock
func (m *MockSQLDB) ListPage(bucket []byte, limit int, offset int) ([]*database.Entry, error) {
	if m.MListPage != nil {
		return m.MListPage(bucket, limit, offset)
	}
	return m.Ret1.([]*database.Entry), m.Err
}
