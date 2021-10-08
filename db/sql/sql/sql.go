package sql

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/smallstep/nosql/database"
)

var (
	// ErrNotFound is the type returned on DB implementations if an item does not
	// exist.
	ErrNotFound = errors.New("not found")
	// ErrOpNotSupported is the type returned on DB implementations if an operation
	// is not supported.
	ErrOpNotSupported = errors.New("operation not supported")
)

// IsErrNotFound returns true if the cause of the given error is ErrNotFound.
func IsErrNotFound(err error) bool {
	return err == ErrNotFound || cause(err) == ErrNotFound
}

// IsErrOpNotSupported returns true if the cause of the given error is ErrOpNotSupported.
func IsErrOpNotSupported(err error) bool {
	return err == ErrOpNotSupported || cause(err) == ErrNotFound
}

// cause (from github.com/pkg/errors) returns the underlying cause of the
// error, if possible. An error value has a cause if it implements the
// following interface:
//
//     type causer interface {
//            Cause() error
//     }
//
// If the error does not implement Cause, the original error will
// be returned. If the error is nil, nil will be returned without further
// investigation.
func cause(err error) error {
	type causer interface {
		Cause() error
	}

	for err != nil {
		cause, ok := err.(causer)
		if !ok {
			break
		}
		err = cause.Cause()
	}
	return err
}

// Options are configuration options for the database.
type SQLOptions struct {
	Database string
}

// Option is the modifier type over Options.
type SQLOption func(o *SQLOptions) error

// WithDatabase is a modifier that sets the Database attribute of SQLOption.
func WithDatabase(db string) SQLOption {
	return func(o *SQLOptions) error {
		o.Database = db
		return nil
	}
}

// DB is a interface to be implemented by the databases.
type DB interface {
	// Open opens the database available with the given options.
	Open(dataSourceName string, opt ...SQLOption) error
	// Close closes the current database.
	Close() error
	// Get returns the value stored in the given table/bucket and key.
	Get(bucket, key []byte) (ret []byte, err error)
	// Set sets the given value in the given table/bucket and key.
	Set(bucket, key, value []byte) error
	// SetX509Certificate sets the given value in the x509 certificate table/bucket and key.
	SetX509Certificate(bucket, key, value []byte, extensionBucket []byte, dnsNameBucket []byte, provisionerName string) error
	// CmpAndSwap swaps the value at the given bucket and key if the current
	// value is equivalent to the oldValue input. Returns 'true' if the
	// swap was successful and 'false' otherwise.
	CmpAndSwap(bucket, key, oldValue, newValue []byte) ([]byte, bool, error)

	// CmpAndSwapACMECertificate swaps the value at the given bucket and key if the current
	// value is equivalent to the oldValue input. Returns 'true' if the
	// swap was successful and 'false' otherwise.
	CmpAndSwapACMECertificate(bucket []byte, key []byte, cert *x509.Certificate, oldValue, newValue, extensionBucket, dnsNameBucket []byte, provisionerName string) ([]byte, bool, error)
	// Del deletes the data in the given table/bucket and key.
	Del(bucket, key []byte) error
	// Count returns a number of entries in some table
	Count(bucket []byte) (int, error)
	// List returns a list of all the entries in a given table/bucket.
	List(bucket []byte) ([]*database.Entry, error)
	// ListPage returns a page worth of entries, whatever page size is specified. Better for performance on large DBs.
	ListPage(bucket []byte, limit int, offset int) ([]*database.Entry, error)
	// Update performs a transaction with multiple read-write commands.
	Update(tx *Tx) error
	// CreateTable creates a table or a bucket in the database.
	CreateTable(bucket []byte) error
	// CreateX509CertificateTable creates a x509cert table or a bucket in the database.
	CreateX509CertificateTable(bucket []byte) error
	// CreateX509CertificateSansTable creates a x509cert table to associate SANS with their certs. This is how we search by SAN.
	CreateX509CertificateSansTable(bucket, constraint, reference []byte) error
	// CreateX509CertificateExtensionsTable creates a x509cert table to associate Extensions with their certs. This is how we search by Extension.
	CreateX509CertificateExtensionsTable(bucket, constraint, reference []byte) error
	// DeleteTable deletes a table or a bucket in the database.
	DeleteTable(bucket []byte) error
}

// Badger FileLoadingMode constants.
const (
	BadgerMemoryMap = "mmap"
	BadgerFileIO    = "fileio"
)

// TxCmd is the type used to represent database command and operations.
type TxCmd int

const (
	// CreateTable on a TxEntry will represent the creation of a table or
	// bucket on the database.
	CreateTable TxCmd = iota
	// DeleteTable on a TxEntry will represent the deletion of a table or
	// bucket on the database.
	DeleteTable
	// Get on a TxEntry will represent a command to retrieve data from the
	// database.
	Get
	// Set on a TxEntry will represent a command to write data on the
	// database.
	Set
	// Set on a TxEntry will represent a command to write an x509 certificate on the
	// database.
	SetX509Certificate
	// Delete on a TxEntry represent a command to delete data on the database.
	Delete
	// CmpAndSwap on a TxEntry will represent a compare and swap operation on
	// the database. It will compare the value read and change it if it's
	// different. The TxEntry will contain the value read.
	CmpAndSwap
	// CmpOrRollback on a TxEntry will represent a read transaction that will
	// compare the values will the ones passed, and if they don't match the
	// transaction will fail
	CmpOrRollback
)

// String implements the fmt.Stringer interface on TxCmd.
func (o TxCmd) String() string {
	switch o {
	case CreateTable:
		return "create-table"
	case DeleteTable:
		return "delete-table"
	case Get:
		return "read"
	case Set:
		return "write"
	case SetX509Certificate:
		return "write-x509certificate"
	case Delete:
		return "delete"
	case CmpAndSwap:
		return "compare-and-swap"
	case CmpOrRollback:
		return "compare-and-rollback"
	default:
		return fmt.Sprintf("unknown(%d)", o)
	}
}

// Tx represents a transaction and it's list of multiple TxEntry. Each TxEntry
// represents a read or write operation on the database.
type Tx struct {
	Operations []*TxEntry
}

// CreateTable adds a new create query to the transaction.
func (tx *Tx) CreateTable(bucket []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Cmd:    CreateTable,
	})
}

// DeleteTable adds a new create query to the transaction.
func (tx *Tx) DeleteTable(bucket []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Cmd:    DeleteTable,
	})
}

// Get adds a new read query to the transaction.
func (tx *Tx) Get(bucket, key []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Key:    key,
		Cmd:    Get,
	})
}

// SetX509Certificate adds a new write query to the transaction.
func (tx *Tx) SetX509Certificate(bucket, key, value []byte, extensionBucket []byte, dnsNameBucket []byte, provisionerName string) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Key:    key,
		Value:  value,
		Cmd:    Set,
	})
}

func (tx *Tx) Set(bucket, key, value []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Key:    key,
		Value:  value,
		Cmd:    Set,
	})
}

// Del adds a new delete query to the transaction.
func (tx *Tx) Del(bucket, key []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Key:    key,
		Cmd:    Delete,
	})
}

// CmpAndSwapACMECertificate.
func (tx *Tx) CmpAndSwapACMECertificate(bucket []byte, key []byte, cert *x509.Certificate, oldValue, newValue, extensionBucket, dnsNameBucket []byte, provisionerName string) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Key:    key,
		Cmd:    Delete,
	})
}

// Cas adds a new compare-and-swap query to the transaction.
func (tx *Tx) Cas(bucket, key, value []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Key:    key,
		Value:  value,
		Cmd:    CmpAndSwap,
	})
}

// Cmp adds a new compare-or-rollback query to the transaction.
func (tx *Tx) Cmp(bucket, key, value []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Key:    key,
		Value:  value,
		Cmd:    CmpOrRollback,
	})
}

// TxEntry is the base elements for the transactions, a TxEntry is a read or
// write operation on the database.
type TxEntry struct {
	Bucket   []byte
	Key      []byte
	Value    []byte
	CmpValue []byte
	// Where the result of Get or CmpAndSwap txns is stored.
	Result  []byte
	Cmd     TxCmd
	Swapped bool
}
