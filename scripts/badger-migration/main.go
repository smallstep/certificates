package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	badgerv1 "github.com/dgraph-io/badger"
	badgerv2 "github.com/dgraph-io/badger/v2"

	"github.com/smallstep/certificates/internal/cast"
	"github.com/smallstep/nosql"
)

var (
	authorityTables = []string{
		"x509_certs",
		"x509_certs_data",
		"revoked_x509_certs",
		"x509_crl",
		"revoked_ssh_certs",
		"used_ott",
		"ssh_certs",
		"ssh_hosts",
		"ssh_users",
		"ssh_host_principals",
	}
	acmeTables = []string{
		"acme_accounts",
		"acme_keyID_accountID_index",
		"acme_authzs",
		"acme_challenges",
		"nonces",
		"acme_orders",
		"acme_account_orders_index",
		"acme_certs",
		"acme_serial_certs_index",
		"acme_external_account_keys",
		"acme_external_account_keyID_reference_index",
		"acme_external_account_keyID_provisionerID_index",
	}
	adminTables = []string{
		"admins",
		"provisioners",
		"authority_policies",
	}
)

type DB interface {
	CreateTable([]byte) error
	Set(bucket, key, value []byte) error
}

type dryRunDB struct{}

func (*dryRunDB) CreateTable([]byte) error { return nil }

func (*dryRunDB) Set(bucket, key, value []byte) error { return nil }

func usage(fs *flag.FlagSet) {
	name := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "%s is a tool to migrate data from BadgerDB to MySQL or PostgreSQL.\n", name)
	fmt.Fprintln(os.Stderr, "\nUsage:")
	fmt.Fprintf(os.Stderr, "  %s [-v1|-v2] -dir=<path> [-value-dir=<path>] -type=type -database=<source>\n", name)
	fmt.Fprintln(os.Stderr, "\nExamples:")
	fmt.Fprintf(os.Stderr, "  %s -v1 -dir /var/lib/step-ca/db -type=mysql -database \"user@unix/step_ca\"\n", name)
	fmt.Fprintf(os.Stderr, "  %s -v1 -dir /var/lib/step-ca/db -type=mysql -database \"user:password@tcp(localhost:3306)/step_ca\"\n", name)
	fmt.Fprintf(os.Stderr, "  %s -v2 -dir /var/lib/step-ca/db -type=postgresql -database \"user=postgres dbname=step_ca\"\n", name)
	fmt.Fprintf(os.Stderr, "  %s -v2 -dir /var/lib/step-ca/db -dry-run\"\n", name)
	fmt.Fprintln(os.Stderr, "\nOptions:")
	fs.PrintDefaults()
}

func main() {
	var v1, v2, dryRun bool
	var dir, valueDir string
	var typ, database string
	var key string

	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	fs.BoolVar(&v1, "v1", false, "use badger v1 as the source database")
	fs.BoolVar(&v2, "v2", false, "use badger v2 as the source database")
	fs.StringVar(&dir, "dir", "", "badger database directory")
	fs.StringVar(&valueDir, "value-dir", "", "badger database value directory")
	fs.StringVar(&typ, "type", "", "the destination database type to use")
	fs.StringVar(&database, "database", "", "the destination driver-specific data source name")
	fs.StringVar(&key, "key", "", "the key used to resume the migration")
	fs.BoolVar(&dryRun, "dry-run", false, "runs the migration scripts without writing anything")
	fs.Usage = func() { usage(fs) }
	fs.Parse(os.Args[1:])

	switch {
	case v1 == v2:
		fatal("flag -v1 or -v2 are required")
	case dir == "":
		fatal("flag -dir is required")
	case typ != "postgresql" && typ != "mysql" && !dryRun:
		fatal(`flag -type must be "postgresql" or "mysql"`)
	case database == "" && !dryRun:
		fatal("flag --database required")
	}

	var (
		err     error
		v1DB    *badgerv1.DB
		v2DB    *badgerv2.DB
		lastKey []byte
	)

	if key != "" {
		if lastKey, err = base64.StdEncoding.DecodeString(key); err != nil {
			fatal("error decoding key: %v", err)
		}
	}

	if v1 {
		if v1DB, err = badgerV1Open(dir, valueDir); err != nil {
			fatal("error opening badger v1 database: %v", err)
		}
	} else {
		if v2DB, err = badgerV2Open(dir, valueDir); err != nil {
			fatal("error opening badger v2 database: %v", err)
		}
	}

	var db DB
	if dryRun {
		db = &dryRunDB{}
	} else {
		db, err = nosql.New(typ, database)
		if err != nil {
			fatal("error opening %s database: %v", typ, err)
		}
	}

	allTables := append([]string{}, authorityTables...)
	allTables = append(allTables, acmeTables...)
	allTables = append(allTables, adminTables...)

	// Convert prefix names to badger key prefixes
	badgerKeys := make([][]byte, len(allTables))
	for i, name := range allTables {
		badgerKeys[i], err = badgerEncode([]byte(name))
		if err != nil {
			fatal("error encoding table %s: %v", name, err)
		}
	}

	for i, prefix := range badgerKeys {
		table := allTables[i]

		// With a key flag, resume from that table and prefix
		if lastKey != nil {
			bucket, _ := parseBadgerEncode(lastKey)
			if table != string(bucket) {
				fmt.Printf("skipping table %s\n", table)
				continue
			}
			// Continue with a new prefix
			prefix = lastKey
			lastKey = nil
		}

		var n int64
		fmt.Printf("migrating %s ...", table)
		if err := db.CreateTable([]byte(table)); err != nil {
			fatal("error creating table %s: %v", table, err)
		}

		if v1 {
			if badgerKey, err := badgerV1Iterate(v1DB, prefix, func(bucket, key, value []byte) error {
				n++
				return db.Set(bucket, key, value)
			}); err != nil {
				fmt.Println()
				fatal("error inserting into %s: %v\nLast key: %s", table, err, base64.StdEncoding.EncodeToString(badgerKey))
			}
		} else {
			if badgerKey, err := badgerV2Iterate(v2DB, prefix, func(bucket, key, value []byte) error {
				n++
				return db.Set(bucket, key, value)
			}); err != nil {
				fmt.Println()
				fatal("error inserting into %s: %v\nLast key: %s", table, err, base64.StdEncoding.EncodeToString(badgerKey))
			}
		}

		fmt.Printf(" %d rows\n", n)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
	os.Exit(1)
}

func badgerV1Open(dir, valueDir string) (*badgerv1.DB, error) {
	opts := badgerv1.DefaultOptions(dir)
	if valueDir != "" {
		opts.ValueDir = valueDir
	}
	return badgerv1.Open(opts)
}

func badgerV2Open(dir, valueDir string) (*badgerv2.DB, error) {
	opts := badgerv2.DefaultOptions(dir)
	if valueDir != "" {
		opts.ValueDir = valueDir
	}
	return badgerv2.Open(opts)
}

type Iterator interface {
	Seek([]byte)
	ValidForPrefix([]byte) bool
	Next()
}

type Item interface {
	KeyCopy([]byte) []byte
	ValueCopy([]byte) ([]byte, error)
}

func badgerV1Iterate(db *badgerv1.DB, prefix []byte, fn func(bucket, key, value []byte) error) (badgerKey []byte, err error) {
	err = db.View(func(txn *badgerv1.Txn) error {
		it := txn.NewIterator(badgerv1.DefaultIteratorOptions)
		defer it.Close()
		badgerKey, err = badgerIterate(it, prefix, fn)
		return err
	})
	return
}

func badgerV2Iterate(db *badgerv2.DB, prefix []byte, fn func(bucket, key, value []byte) error) (badgerKey []byte, err error) {
	err = db.View(func(txn *badgerv2.Txn) error {
		it := txn.NewIterator(badgerv2.DefaultIteratorOptions)
		defer it.Close()
		badgerKey, err = badgerIterate(it, prefix, fn)
		return err
	})
	return
}

func badgerIterate(it Iterator, prefix []byte, fn func(bucket, key, value []byte) error) ([]byte, error) {
	var badgerKey []byte
	for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
		var item Item
		switch itt := it.(type) {
		case *badgerv1.Iterator:
			item = itt.Item()
		case *badgerv2.Iterator:
			item = itt.Item()
		default:
			return badgerKey, fmt.Errorf("unexpected iterator type %T", it)
		}

		badgerKey = item.KeyCopy(nil)
		if isBadgerTable(badgerKey) {
			continue
		}

		bucket, key, err := fromBadgerKey(badgerKey)
		if err != nil {
			return badgerKey, fmt.Errorf("error converting from badger key %s", badgerKey)
		}
		value, err := item.ValueCopy(nil)
		if err != nil {
			return badgerKey, fmt.Errorf("error retrieving contents from database value: %w", err)
		}

		if err := fn(bucket, key, value); err != nil {
			return badgerKey, fmt.Errorf("error exporting %s[%s]=%x", bucket, key, value)
		}
	}

	return badgerKey, nil
}

// badgerEncode encodes a byte slice into a section of a BadgerKey. See
// documentation for toBadgerKey.
func badgerEncode(val []byte) ([]byte, error) {
	l := len(val)
	switch {
	case l == 0:
		return nil, errors.New("input cannot be empty")
	case l > 65535:
		return nil, errors.New("length of input cannot be greater than 65535")
	default:
		lb := new(bytes.Buffer)
		if err := binary.Write(lb, binary.LittleEndian, uint16(l)); err != nil {
			return nil, fmt.Errorf("error doing binary Write: %w", err)
		}
		return append(lb.Bytes(), val...), nil
	}
}

// parseBadgerEncode decodes the badger key and returns the bucket and the rest.
func parseBadgerEncode(bk []byte) (value, rest []byte) {
	var (
		keyLen uint16
		start  = uint16(2)
		length = cast.Uint16(len(bk))
	)
	if cast.Uint16(len(bk)) < start {
		return nil, bk
	}
	// First 2 bytes stores the length of the value.
	if err := binary.Read(bytes.NewReader(bk[:2]), binary.LittleEndian, &keyLen); err != nil {
		return nil, bk
	}
	end := start + keyLen
	switch {
	case length < end:
		return nil, bk
	case length == end:
		return bk[start:end], nil
	default:
		return bk[start:end], bk[end:]
	}
}

// isBadgerTable returns True if the slice is a badgerTable token, false
// otherwise. badgerTable means that the slice contains only the [size|value] of
// one section of a badgerKey and no remainder. A badgerKey is [bucket|key],
// while a badgerTable is only the bucket section.
func isBadgerTable(bk []byte) bool {
	if k, rest := parseBadgerEncode(bk); len(k) > 0 && len(rest) == 0 {
		return true
	}
	return false
}

// fromBadgerKey returns the bucket and key encoded in a BadgerKey. See
// documentation for toBadgerKey.
func fromBadgerKey(bk []byte) ([]byte, []byte, error) {
	bucket, rest := parseBadgerEncode(bk)
	if len(bucket) == 0 || len(rest) == 0 {
		return nil, nil, fmt.Errorf("invalid badger key: %v", bk)
	}

	key, rest2 := parseBadgerEncode(rest)
	if len(key) == 0 || len(rest2) != 0 {
		return nil, nil, fmt.Errorf("invalid badger key: %v", bk)
	}

	return bucket, key, nil
}
