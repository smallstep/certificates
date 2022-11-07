package db

import (
	"bytes"
	"crypto/x509"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

func TestIsRevoked(t *testing.T) {
	tests := map[string]struct {
		key       string
		db        *DB
		isRevoked bool
		err       error
	}{
		"false/nil db": {
			key: "sn",
		},
		"false/ErrNotFound": {
			key: "sn",
			db:  &DB{&MockNoSQLDB{Err: database.ErrNotFound, Ret1: nil}, true},
		},
		"error/checking bucket": {
			key: "sn",
			db:  &DB{&MockNoSQLDB{Err: errors.New("force"), Ret1: nil}, true},
			err: errors.New("error checking revocation bucket: force"),
		},
		"true": {
			key:       "sn",
			db:        &DB{&MockNoSQLDB{Ret1: []byte("value")}, true},
			isRevoked: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			isRevoked, err := tc.db.IsRevoked(tc.key)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, tc.err.Error(), err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
				assert.Fatal(t, isRevoked == tc.isRevoked)
			}
		})
	}
}

func TestRevoke(t *testing.T) {
	tests := map[string]struct {
		rci *RevokedCertificateInfo
		db  *DB
		err error
	}{
		"error/force isRevoked": {
			rci: &RevokedCertificateInfo{Serial: "sn"},
			db: &DB{&MockNoSQLDB{
				MCmpAndSwap: func(bucket, sn, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, true},
			err: errors.New("error AuthDB CmpAndSwap: force"),
		},
		"error/was already revoked": {
			rci: &RevokedCertificateInfo{Serial: "sn"},
			db: &DB{&MockNoSQLDB{
				MCmpAndSwap: func(bucket, sn, old, newval []byte) ([]byte, bool, error) {
					return []byte("foo"), false, nil
				},
			}, true},
			err: ErrAlreadyExists,
		},
		"ok": {
			rci: &RevokedCertificateInfo{Serial: "sn"},
			db: &DB{&MockNoSQLDB{
				MCmpAndSwap: func(bucket, sn, old, newval []byte) ([]byte, bool, error) {
					return []byte("foo"), true, nil
				},
			}, true},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := tc.db.Revoke(tc.rci); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, tc.err.Error(), err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestUseToken(t *testing.T) {
	type result struct {
		err error
		ok  bool
	}
	tests := map[string]struct {
		id, tok string
		db      *DB
		want    result
	}{
		"fail/force-CmpAndSwap-error": {
			id:  "id",
			tok: "token",
			db: &DB{&MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, true},
			want: result{
				ok:  false,
				err: errors.New("error storing used token used_ott/id"),
			},
		},
		"fail/CmpAndSwap-already-exists": {
			id:  "id",
			tok: "token",
			db: &DB{&MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return []byte("foo"), false, nil
				},
			}, true},
			want: result{
				ok: false,
			},
		},
		"ok/cmpAndSwap-success": {
			id:  "id",
			tok: "token",
			db: &DB{&MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return []byte("bar"), true, nil
				},
			}, true},
			want: result{
				ok: true,
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			switch ok, err := tc.db.UseToken(tc.id, tc.tok); {
			case err != nil:
				if assert.NotNil(t, tc.want.err) {
					assert.HasPrefix(t, err.Error(), tc.want.err.Error())
				}
				assert.False(t, ok)
			case ok:
				assert.True(t, tc.want.ok)
			default:
				assert.False(t, tc.want.ok)
			}
		})
	}
}

// wrappedProvisioner implements raProvisioner and attProvisioner.
type wrappedProvisioner struct {
	provisioner.Interface
	raInfo *provisioner.RAInfo
}

func (p *wrappedProvisioner) RAInfo() *provisioner.RAInfo {
	return p.raInfo
}

func TestDB_StoreCertificateChain(t *testing.T) {
	p := &provisioner.JWK{
		ID:   "some-id",
		Name: "admin",
		Type: "JWK",
	}
	rap := &wrappedProvisioner{
		Interface: p,
		raInfo: &provisioner.RAInfo{
			ProvisionerID:   "ra-id",
			ProvisionerType: "JWK",
			ProvisionerName: "ra",
		},
	}
	chain := []*x509.Certificate{
		{Raw: []byte("the certificate"), SerialNumber: big.NewInt(1234)},
	}
	type fields struct {
		DB   nosql.DB
		isUp bool
	}
	type args struct {
		p     provisioner.Interface
		chain []*x509.Certificate
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{&MockNoSQLDB{
			MUpdate: func(tx *database.Tx) error {
				if len(tx.Operations) != 2 {
					t.Fatal("unexpected number of operations")
				}
				assert.Equals(t, []byte("x509_certs"), tx.Operations[0].Bucket)
				assert.Equals(t, []byte("1234"), tx.Operations[0].Key)
				assert.Equals(t, []byte("the certificate"), tx.Operations[0].Value)
				assert.Equals(t, []byte("x509_certs_data"), tx.Operations[1].Bucket)
				assert.Equals(t, []byte("1234"), tx.Operations[1].Key)
				assert.Equals(t, []byte(`{"provisioner":{"id":"some-id","name":"admin","type":"JWK"}}`), tx.Operations[1].Value)
				return nil
			},
		}, true}, args{p, chain}, false},
		{"ok ra provisioner", fields{&MockNoSQLDB{
			MUpdate: func(tx *database.Tx) error {
				if len(tx.Operations) != 2 {
					t.Fatal("unexpected number of operations")
				}
				assert.Equals(t, []byte("x509_certs"), tx.Operations[0].Bucket)
				assert.Equals(t, []byte("1234"), tx.Operations[0].Key)
				assert.Equals(t, []byte("the certificate"), tx.Operations[0].Value)
				assert.Equals(t, []byte("x509_certs_data"), tx.Operations[1].Bucket)
				assert.Equals(t, []byte("1234"), tx.Operations[1].Key)
				assert.Equals(t, []byte(`{"provisioner":{"id":"some-id","name":"admin","type":"JWK"},"ra":{"provisionerId":"ra-id","provisionerType":"JWK","provisionerName":"ra"}}`), tx.Operations[1].Value)
				assert.Equals(t, `{"provisioner":{"id":"some-id","name":"admin","type":"JWK"},"ra":{"provisionerId":"ra-id","provisionerType":"JWK","provisionerName":"ra"}}`, string(tx.Operations[1].Value))
				return nil
			},
		}, true}, args{rap, chain}, false},
		{"ok no provisioner", fields{&MockNoSQLDB{
			MUpdate: func(tx *database.Tx) error {
				if len(tx.Operations) != 2 {
					t.Fatal("unexpected number of operations")
				}
				assert.Equals(t, []byte("x509_certs"), tx.Operations[0].Bucket)
				assert.Equals(t, []byte("1234"), tx.Operations[0].Key)
				assert.Equals(t, []byte("the certificate"), tx.Operations[0].Value)
				assert.Equals(t, []byte("x509_certs_data"), tx.Operations[1].Bucket)
				assert.Equals(t, []byte("1234"), tx.Operations[1].Key)
				assert.Equals(t, []byte(`{}`), tx.Operations[1].Value)
				return nil
			},
		}, true}, args{nil, chain}, false},
		{"fail store certificate", fields{&MockNoSQLDB{
			MUpdate: func(tx *database.Tx) error {
				return errors.New("test error")
			},
		}, true}, args{p, chain}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DB{
				DB:   tt.fields.DB,
				isUp: tt.fields.isUp,
			}
			if err := d.StoreCertificateChain(tt.args.p, tt.args.chain...); (err != nil) != tt.wantErr {
				t.Errorf("DB.StoreCertificateChain() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDB_GetCertificateData(t *testing.T) {
	type fields struct {
		DB   nosql.DB
		isUp bool
	}
	type args struct {
		serialNumber string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *CertificateData
		wantErr bool
	}{
		{"ok", fields{&MockNoSQLDB{
			MGet: func(bucket, key []byte) ([]byte, error) {
				assert.Equals(t, bucket, []byte("x509_certs_data"))
				assert.Equals(t, key, []byte("1234"))
				return []byte(`{"provisioner":{"id":"some-id","name":"admin","type":"JWK"}}`), nil
			},
		}, true}, args{"1234"}, &CertificateData{
			Provisioner: &ProvisionerData{
				ID: "some-id", Name: "admin", Type: "JWK",
			},
		}, false},
		{"fail not found", fields{&MockNoSQLDB{
			MGet: func(bucket, key []byte) ([]byte, error) {
				return nil, database.ErrNotFound
			},
		}, true}, args{"1234"}, nil, true},
		{"fail db", fields{&MockNoSQLDB{
			MGet: func(bucket, key []byte) ([]byte, error) {
				return nil, errors.New("an error")
			},
		}, true}, args{"1234"}, nil, true},
		{"fail unmarshal", fields{&MockNoSQLDB{
			MGet: func(bucket, key []byte) ([]byte, error) {
				return []byte(`{"bad-json"}`), nil
			},
		}, true}, args{"1234"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &DB{
				DB:   tt.fields.DB,
				isUp: tt.fields.isUp,
			}
			got, err := db.GetCertificateData(tt.args.serialNumber)
			if (err != nil) != tt.wantErr {
				t.Errorf("DB.GetCertificateData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DB.GetCertificateData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDB_StoreRenewedCertificate(t *testing.T) {
	oldCert := &x509.Certificate{SerialNumber: big.NewInt(1)}
	chain := []*x509.Certificate{
		&x509.Certificate{SerialNumber: big.NewInt(2), Raw: []byte("raw")},
		&x509.Certificate{SerialNumber: big.NewInt(0)},
	}

	testErr := errors.New("test error")
	certsData := []byte(`{"provisioner":{"id":"p","name":"name","type":"JWK"},"ra":{"provisionerId":"rap","provisionerType":"JWK","provisionerName":"rapname"}}`)
	matchOperation := func(op *database.TxEntry, bucket, key, value []byte) bool {
		return bytes.Equal(op.Bucket, bucket) && bytes.Equal(op.Key, key) && bytes.Equal(op.Value, value)
	}

	type fields struct {
		DB   nosql.DB
		isUp bool
	}
	type args struct {
		oldCert *x509.Certificate
		chain   []*x509.Certificate
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{&MockNoSQLDB{
			MGet: func(bucket, key []byte) ([]byte, error) {
				if bytes.Equal(bucket, certsDataTable) && bytes.Equal(key, []byte("1")) {
					return certsData, nil
				}
				t.Error("ok failed: unexpected get")
				return nil, testErr
			},
			MUpdate: func(tx *database.Tx) error {
				if len(tx.Operations) != 2 {
					t.Error("ok failed: unexpected number of operations")
					return testErr
				}
				op0, op1 := tx.Operations[0], tx.Operations[1]
				if !matchOperation(op0, certsTable, []byte("2"), []byte("raw")) {
					t.Errorf("ok failed: unexpected entry 0, %s[%s]=%s", op0.Bucket, op0.Key, op0.Value)
					return testErr
				}
				if !matchOperation(op1, certsDataTable, []byte("2"), certsData) {
					t.Errorf("ok failed: unexpected entry 1, %s[%s]=%s", op1.Bucket, op1.Key, op1.Value)
					return testErr
				}
				return nil
			},
		}, true}, args{oldCert, chain}, false},
		{"ok no data", fields{&MockNoSQLDB{
			MGet: func(bucket, key []byte) ([]byte, error) {
				return nil, database.ErrNotFound
			},
			MUpdate: func(tx *database.Tx) error {
				if len(tx.Operations) != 1 {
					t.Error("ok failed: unexpected number of operations")
					return testErr
				}
				op0 := tx.Operations[0]
				if !matchOperation(op0, certsTable, []byte("2"), []byte("raw")) {
					t.Errorf("ok failed: unexpected entry 0, %s[%s]=%s", op0.Bucket, op0.Key, op0.Value)
					return testErr
				}
				return nil
			},
		}, true}, args{oldCert, chain}, false},
		{"ok fail marshal", fields{&MockNoSQLDB{
			MGet: func(bucket, key []byte) ([]byte, error) {
				return []byte(`{"bad":"json"`), nil
			},
			MUpdate: func(tx *database.Tx) error {
				if len(tx.Operations) != 1 {
					t.Error("ok failed: unexpected number of operations")
					return testErr
				}
				op0 := tx.Operations[0]
				if !matchOperation(op0, certsTable, []byte("2"), []byte("raw")) {
					t.Errorf("ok failed: unexpected entry 0, %s[%s]=%s", op0.Bucket, op0.Key, op0.Value)
					return testErr
				}
				return nil
			},
		}, true}, args{oldCert, chain}, false},
		{"fail", fields{&MockNoSQLDB{
			MGet: func(bucket, key []byte) ([]byte, error) {
				return certsData, nil
			},
			MUpdate: func(tx *database.Tx) error {
				return testErr
			},
		}, true}, args{oldCert, chain}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &DB{
				DB:   tt.fields.DB,
				isUp: tt.fields.isUp,
			}
			if err := db.StoreRenewedCertificate(tt.args.oldCert, tt.args.chain...); (err != nil) != tt.wantErr {
				t.Errorf("DB.StoreRenewedCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
