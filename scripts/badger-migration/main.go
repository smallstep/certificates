package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	badgerv1 "github.com/dgraph-io/badger"
	badgerv2 "github.com/dgraph-io/badger/v2"

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
)

func usage(fs *flag.FlagSet) {
	name := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "%s is a tool to migrate data from BadgerDB to MySQL or PostgreSQL.\n", name)
	fmt.Fprintln(os.Stderr, "\nUsage:")
	fmt.Fprintf(os.Stderr, "  %s [-v1|-v2] -dir=<path> [-value-dir=<path>] -type=type -database=<source>\n", name)
	fmt.Fprintln(os.Stderr, "\nExamples:")
	fmt.Fprintf(os.Stderr, "  %s -v1 -dir /var/lib/step-ca/db -type=mysql -database \"user@unix/step_ca\"\n", name)
	fmt.Fprintf(os.Stderr, "  %s -v2 -dir /var/lib/step-ca/db -type=mysql -database \"user:password@tcp(localhost:3306)/step_ca\"\n", name)
	fmt.Fprintf(os.Stderr, "  %s -v2 -dir /var/lib/step-ca/db -type=postgresql -database \"user=postgres dbname=step_ca\"\n", name)
	fmt.Fprintln(os.Stderr, "\nOptions:")
	fs.PrintDefaults()
}

func main() {
	var v1, v2 bool
	var dir, valueDir string
	var typ, database string

	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	fs.BoolVar(&v1, "v1", false, "use badger v1 as the source database")
	fs.BoolVar(&v2, "v2", true, "use badger v2 as the source database")
	fs.StringVar(&dir, "dir", "", "badger database directory")
	fs.StringVar(&valueDir, "value-dir", "", "badger database value directory")
	fs.StringVar(&typ, "type", "", "the destination database type to use")
	fs.StringVar(&database, "database", "", "the destination driver-specific data source name")
	fs.Usage = func() { usage(fs) }
	fs.Parse(os.Args[1:])

	switch {
	case v1 == v2:
		fatal("flag --v1 or --v2 are required")
	case dir == "":
		fatal("flag --dir is required")
	case typ != "postgresql" && typ != "mysql":
		fatal(`flag --type must be "postgresql" or "mysql"`)
	case database == "":
		fatal("flag --database required")
	}

	var (
		err  error
		v1DB *badgerv1.DB
		v2DB *badgerv2.DB
	)

	if v1 {
		if v1DB, err = badgerV1Open(dir, valueDir); err != nil {
			fatal("error opening badger v1 database: %v", err)
		}
	} else {
		if v2DB, err = badgerV2Open(dir, valueDir); err != nil {
			fatal("error opening badger v2 database: %v", err)
		}
	}

	db, err := nosql.New(typ, database)
	if err != nil {
		fatal("error opening %s database: %v", typ, err)
	}

	allTables := append([]string{}, authorityTables...)
	allTables = append(allTables, acmeTables...)

	for _, table := range allTables {
		var n int64
		fmt.Printf("migrating %s ...\n", table)
		if err := db.CreateTable([]byte(table)); err != nil {
			fatal("error creating table %s: %v", table, err)
		}

		if v1 {
			if err := badgerV1Iterate(v1DB, []byte(table), func(bucket, key, value []byte) error {
				n++
				return db.Set(bucket, key, value)
			}); err != nil {
				fatal("error inserting into %s: %v", table, err)
			}
		} else {
			if err := badgerV2Iterate(v2DB, []byte(table), func(bucket, key, value []byte) error {
				n++
				return db.Set(bucket, key, value)
			}); err != nil {
				fatal("error inserting into %s: %v", table, err)
			}
		}

		log.Printf("%d rows\n", n)
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

func badgerV1Iterate(db *badgerv1.DB, table []byte, fn func(table, key, value []byte) error) error {
	return db.View(func(txn *badgerv1.Txn) error {
		var tableExists bool

		it := txn.NewIterator(badgerv1.DefaultIteratorOptions)
		defer it.Close()

		prefix, err := badgerEncode(table)
		if err != nil {
			return err
		}

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			tableExists = true
			item := it.Item()
			bk := item.KeyCopy(nil)
			if isBadgerTable(bk) {
				continue
			}

			bucket, key, err := fromBadgerKey(bk)
			if err != nil {
				return fmt.Errorf("error converting from badger key %s", bk)
			}
			if !bytes.Equal(table, bucket) {
				return fmt.Errorf("bucket names do not match; want %s, but got %s", table, bucket)
			}

			v, err := item.ValueCopy(nil)
			if err != nil {
				return fmt.Errorf("error retrieving contents from database value: %w", err)
			}
			value := cloneBytes(v)

			if err := fn(bucket, key, value); err != nil {
				return fmt.Errorf("error exporting %s[%s]=%v", table, key, value)
			}
		}

		if !tableExists {
			fmt.Printf("bucket %s not found\n", table)
		}

		return nil
	})
}

func badgerV2Iterate(db *badgerv2.DB, table []byte, fn func(table, key, value []byte) error) error {
	return db.View(func(txn *badgerv2.Txn) error {
		var tableExists bool

		it := txn.NewIterator(badgerv2.DefaultIteratorOptions)
		defer it.Close()

		prefix, err := badgerEncode(table)
		if err != nil {
			return err
		}
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			tableExists = true
			item := it.Item()
			bk := item.KeyCopy(nil)
			if isBadgerTable(bk) {
				continue
			}

			bucket, key, err := fromBadgerKey(bk)
			if err != nil {
				return fmt.Errorf("error converting from badgerKey %s: %w", bk, err)
			}
			if !bytes.Equal(table, bucket) {
				return fmt.Errorf("bucket names do not match; want %s, but got %s", table, bucket)
			}

			v, err := item.ValueCopy(nil)
			if err != nil {
				return fmt.Errorf("error retrieving contents from database value: %w", err)
			}
			value := cloneBytes(v)

			if err := fn(bucket, key, value); err != nil {
				return fmt.Errorf("error exporting %s[%s]=%v", table, key, value)
			}
		}
		if !tableExists {
			log.Printf("bucket %s not found", table)
		}
		return nil
	})
}

// badgerEncode encodes a byte slice into a section of a BadgerKey.
// See documentation for toBadgerKey.
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

// isBadgerTable returns True if the slice is a badgerTable token, false otherwise.
// badgerTable means that the slice contains only the [size|value] of one section
// of a badgerKey and no remainder. A badgerKey is [buket|key], while a badgerTable
// is only the bucket section.
func isBadgerTable(bk []byte) bool {
	if k, rest := parseBadgerEncode(bk); len(k) > 0 && len(rest) == 0 {
		return true
	}
	return false
}

// fromBadgerKey returns the bucket and key encoded in a BadgerKey.
// See documentation for toBadgerKey.
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

// cloneBytes returns a copy of a given slice.
func cloneBytes(v []byte) []byte {
	var clone = make([]byte, len(v))
	copy(clone, v)
	return clone
}

func parseBadgerEncode(bk []byte) (value, rest []byte) {
	var (
		keyLen uint16
		start  = uint16(2)
		length = uint16(len(bk))
	)
	if uint16(len(bk)) < start {
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
