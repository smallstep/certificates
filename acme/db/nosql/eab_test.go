package nosql

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	certdb "github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	nosqldb "github.com/smallstep/nosql/database"
)

func TestDB_getDBExternalAccountKey(t *testing.T) {
	keyID := "keyID"
	provID := "provID"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		dbeak   *dbExternalAccountKey
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:            keyID,
				ProvisionerID: provID,
				Reference:     "ref",
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)
						return b, nil
					},
				},
				err:   nil,
				dbeak: dbeak,
			}
		},
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)
						return nil, nosqldb.ErrNotFound
					},
				},
				err: acme.ErrNotFound,
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)
						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading external account key keyID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)

						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling external account key keyID into dbExternalAccountKey"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if dbeak, err := d.getDBExternalAccountKey(context.Background(), keyID); err != nil {
				var ae *acme.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, ae.Type, tc.acmeErr.Type)
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
						assert.Equals(t, ae.Status, tc.acmeErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, dbeak.ID, tc.dbeak.ID)
				assert.Equals(t, dbeak.HmacKey, tc.dbeak.HmacKey)
				assert.Equals(t, dbeak.ProvisionerID, tc.dbeak.ProvisionerID)
				assert.Equals(t, dbeak.Reference, tc.dbeak.Reference)
				assert.Equals(t, dbeak.CreatedAt, tc.dbeak.CreatedAt)
				assert.Equals(t, dbeak.AccountID, tc.dbeak.AccountID)
				assert.Equals(t, dbeak.BoundAt, tc.dbeak.BoundAt)
			}
		})
	}
}

func TestDB_GetExternalAccountKey(t *testing.T) {
	keyID := "keyID"
	provID := "provID"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		eak     *acme.ExternalAccountKey
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:            keyID,
				ProvisionerID: provID,
				Reference:     "ref",
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)
						return b, nil
					},
				},
				eak: &acme.ExternalAccountKey{
					ID:            keyID,
					ProvisionerID: provID,
					Reference:     "ref",
					AccountID:     "",
					HmacKey:       []byte{1, 3, 3, 7},
					CreatedAt:     now,
				},
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading external account key keyID: force"),
			}
		},
		"fail/non-matching-provisioner": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:            keyID,
				ProvisionerID: "aDifferentProvID",
				Reference:     "ref",
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)
						return b, nil
					},
				},
				eak: &acme.ExternalAccountKey{
					ID:            keyID,
					ProvisionerID: provID,
					Reference:     "ref",
					AccountID:     "",
					HmacKey:       []byte{1, 3, 3, 7},
					CreatedAt:     now,
				},
				acmeErr: acme.NewError(acme.ErrorUnauthorizedType, "provisioner does not match provisioner for which the EAB key was created"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if eak, err := d.GetExternalAccountKey(context.Background(), provID, keyID); err != nil {
				var ae *acme.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, ae.Type, tc.acmeErr.Type)
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
						assert.Equals(t, ae.Status, tc.acmeErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, eak.ID, tc.eak.ID)
				assert.Equals(t, eak.HmacKey, tc.eak.HmacKey)
				assert.Equals(t, eak.ProvisionerID, tc.eak.ProvisionerID)
				assert.Equals(t, eak.Reference, tc.eak.Reference)
				assert.Equals(t, eak.CreatedAt, tc.eak.CreatedAt)
				assert.Equals(t, eak.AccountID, tc.eak.AccountID)
				assert.Equals(t, eak.BoundAt, tc.eak.BoundAt)
			}
		})
	}
}

func TestDB_GetExternalAccountKeyByReference(t *testing.T) {
	keyID := "keyID"
	provID := "provID"
	ref := "ref"
	type test struct {
		db      nosql.DB
		err     error
		ref     string
		acmeErr *acme.Error
		eak     *acme.ExternalAccountKey
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:            keyID,
				ProvisionerID: provID,
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			dbref := &dbExternalAccountKeyReference{
				Reference:            ref,
				ExternalAccountKeyID: keyID,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			dbrefBytes, err := json.Marshal(dbref)
			assert.FatalError(t, err)
			return test{
				ref: ref,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, string(key), provID+"."+ref)
							return dbrefBytes, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return b, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
				},
				eak: &acme.ExternalAccountKey{
					ID:            keyID,
					ProvisionerID: provID,
					Reference:     ref,
					AccountID:     "",
					HmacKey:       []byte{1, 3, 3, 7},
					CreatedAt:     now,
				},
				err: nil,
			}
		},
		"ok/no-reference": func(t *testing.T) test {
			return test{
				ref: "",
				eak: nil,
				err: nil,
			}
		},
		"fail/reference-not-found": func(t *testing.T) test {
			return test{
				ref: ref,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyIDsByReferenceTable))
						assert.Equals(t, string(key), provID+"."+ref)
						return nil, nosqldb.ErrNotFound
					},
				},
				err: errors.New("not found"),
			}
		},
		"fail/reference-load-error": func(t *testing.T) test {
			return test{
				ref: ref,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyIDsByReferenceTable))
						assert.Equals(t, string(key), provID+"."+ref)
						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading ACME EAB key for reference ref: force"),
			}
		},
		"fail/reference-unmarshal-error": func(t *testing.T) test {
			return test{
				ref: ref,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyIDsByReferenceTable))
						assert.Equals(t, string(key), provID+"."+ref)
						return []byte{0}, nil
					},
				},
				err: errors.New("error unmarshaling ACME EAB key for reference ref"),
			}
		},
		"fail/db.GetExternalAccountKey-error": func(t *testing.T) test {
			dbref := &dbExternalAccountKeyReference{
				Reference:            ref,
				ExternalAccountKeyID: keyID,
			}
			dbrefBytes, err := json.Marshal(dbref)
			assert.FatalError(t, err)
			return test{
				ref: ref,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, string(key), provID+"."+ref)
							return dbrefBytes, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return nil, errors.New("force")
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force")
						}
					},
				},
				err: errors.New("error loading external account key keyID: force"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if eak, err := d.GetExternalAccountKeyByReference(context.Background(), provID, tc.ref); err != nil {
				var ae *acme.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, ae.Type, tc.acmeErr.Type)
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
						assert.Equals(t, ae.Status, tc.acmeErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) && tc.eak != nil {
				assert.Equals(t, eak.ID, tc.eak.ID)
				assert.Equals(t, eak.AccountID, tc.eak.AccountID)
				assert.Equals(t, eak.BoundAt, tc.eak.BoundAt)
				assert.Equals(t, eak.CreatedAt, tc.eak.CreatedAt)
				assert.Equals(t, eak.HmacKey, tc.eak.HmacKey)
				assert.Equals(t, eak.ProvisionerID, tc.eak.ProvisionerID)
				assert.Equals(t, eak.Reference, tc.eak.Reference)
			}
		})
	}
}

func TestDB_GetExternalAccountKeys(t *testing.T) {
	keyID1 := "keyID1"
	keyID2 := "keyID2"
	keyID3 := "keyID3"
	provID := "provID"
	ref := "ref"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
		eaks    []*acme.ExternalAccountKey
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbeak1 := &dbExternalAccountKey{
				ID:            keyID1,
				ProvisionerID: provID,
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			b1, err := json.Marshal(dbeak1)
			assert.FatalError(t, err)
			dbeak2 := &dbExternalAccountKey{
				ID:            keyID2,
				ProvisionerID: provID,
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			b2, err := json.Marshal(dbeak2)
			assert.FatalError(t, err)
			dbeak3 := &dbExternalAccountKey{
				ID:            keyID3,
				ProvisionerID: "aDifferentProvID",
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			b3, err := json.Marshal(dbeak3)
			assert.FatalError(t, err)
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeyIDsByProvisionerIDTable):
							keys := []string{"", keyID1, keyID2} // includes an empty keyID
							b, err := json.Marshal(keys)
							assert.FatalError(t, err)
							return b, nil
						case string(externalAccountKeyTable):
							switch string(key) {
							case keyID1:
								return b1, nil
							case keyID2:
								return b2, nil
							default:
								assert.FatalError(t, errors.Errorf("unexpected key %s", string(key)))
								return nil, errors.New("force default")
							}
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force default")
						}
					},
					// TODO: remove the MList
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						switch string(bucket) {
						case string(externalAccountKeyTable):
							return []*nosqldb.Entry{
								{
									Bucket: bucket,
									Key:    []byte(keyID1),
									Value:  b1,
								},
								{
									Bucket: bucket,
									Key:    []byte(keyID2),
									Value:  b2,
								},
								{
									Bucket: bucket,
									Key:    []byte(keyID3),
									Value:  b3,
								},
							}, nil
						case string(externalAccountKeyIDsByProvisionerIDTable):
							keys := []string{keyID1, keyID2}
							b, err := json.Marshal(keys)
							assert.FatalError(t, err)
							return []*nosqldb.Entry{
								{
									Bucket: bucket,
									Key:    []byte(provID),
									Value:  b,
								},
							}, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force default")
						}
					},
				},
				eaks: []*acme.ExternalAccountKey{
					{
						ID:            keyID1,
						ProvisionerID: provID,
						Reference:     ref,
						AccountID:     "",
						HmacKey:       []byte{1, 3, 3, 7},
						CreatedAt:     now,
					},
					{
						ID:            keyID2,
						ProvisionerID: provID,
						Reference:     ref,
						AccountID:     "",
						HmacKey:       []byte{1, 3, 3, 7},
						CreatedAt:     now,
					},
				},
			}
		},
		"fail/db.Get-externalAccountKeysByProvisionerIDTable": func(t *testing.T) test {
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyIDsByProvisionerIDTable))
						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading ACME EAB Key IDs for provisioner provID: force"),
			}
		},
		"fail/db.Get-externalAccountKeysByProvisionerIDTable-unmarshal": func(t *testing.T) test {
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyIDsByProvisionerIDTable))
						b, _ := json.Marshal(1)
						return b, nil
					},
				},
				err: errors.New("error unmarshaling ACME EAB Key IDs for provisioner provID: json: cannot unmarshal number into Go value of type []string"),
			}
		},
		"fail/db.getDBExternalAccountKey": func(t *testing.T) test {
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeyIDsByProvisionerIDTable):
							keys := []string{keyID1, keyID2}
							b, err := json.Marshal(keys)
							assert.FatalError(t, err)
							return b, nil
						case string(externalAccountKeyTable):
							return nil, errors.New("force")
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force bucket")
						}
					},
				},
				err: errors.New("error retrieving ACME EAB Key for provisioner provID and keyID keyID1: error loading external account key keyID1: force"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			cursor, limit := "", 0
			if eaks, nextCursor, err := d.GetExternalAccountKeys(context.Background(), provID, cursor, limit); err != nil {
				assert.Equals(t, "", nextCursor)
				var ae *acme.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, ae.Type, tc.acmeErr.Type)
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
						assert.Equals(t, ae.Status, tc.acmeErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.Equals(t, tc.err.Error(), err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, len(eaks), len(tc.eaks))
				assert.Equals(t, "", nextCursor)
				for i, eak := range eaks {
					assert.Equals(t, eak.ID, tc.eaks[i].ID)
					assert.Equals(t, eak.HmacKey, tc.eaks[i].HmacKey)
					assert.Equals(t, eak.ProvisionerID, tc.eaks[i].ProvisionerID)
					assert.Equals(t, eak.Reference, tc.eaks[i].Reference)
					assert.Equals(t, eak.CreatedAt, tc.eaks[i].CreatedAt)
					assert.Equals(t, eak.AccountID, tc.eaks[i].AccountID)
					assert.Equals(t, eak.BoundAt, tc.eaks[i].BoundAt)
				}
			}
		})
	}
}

func TestDB_DeleteExternalAccountKey(t *testing.T) {
	keyID := "keyID"
	provID := "provID"
	ref := "ref"
	type test struct {
		db      nosql.DB
		err     error
		acmeErr *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:            keyID,
				ProvisionerID: provID,
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			dbref := &dbExternalAccountKeyReference{
				Reference:            ref,
				ExternalAccountKeyID: keyID,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			dbrefBytes, err := json.Marshal(dbref)
			assert.FatalError(t, err)
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, string(key), provID+"."+ref)
							return dbrefBytes, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return b, nil
						case string(externalAccountKeyIDsByProvisionerIDTable):
							assert.Equals(t, provID, string(key))
							b, err := json.Marshal([]string{keyID})
							assert.FatalError(t, err)
							return b, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force default")
						}
					},
					MDel: func(bucket, key []byte) error {
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, string(key), provID+"."+ref)
							return nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return errors.New("force default")
						}
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						fmt.Println(string(bucket))
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, provID+"."+ref, string(key))
							return nil, true, nil
						case string(externalAccountKeyIDsByProvisionerIDTable):
							assert.Equals(t, provID, string(key))
							return nil, true, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, false, errors.New("force default")
						}
					},
				},
			}
		},
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyTable))
						assert.Equals(t, string(key), keyID)
						return nil, nosqldb.ErrNotFound
					},
				},
				err: errors.New("error loading ACME EAB Key with Key ID keyID: not found"),
			}
		},
		"fail/non-matching-provisioner": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:            keyID,
				ProvisionerID: "aDifferentProvID",
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyTable))
						assert.Equals(t, string(key), keyID)
						return b, nil
					},
				},
				err: errors.New("provisioner does not match provisioner for which the EAB key was created"),
			}
		},
		"fail/delete-reference": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:            keyID,
				ProvisionerID: provID,
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			dbref := &dbExternalAccountKeyReference{
				Reference:            ref,
				ExternalAccountKeyID: keyID,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			dbrefBytes, err := json.Marshal(dbref)
			assert.FatalError(t, err)
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, string(key), ref)
							return dbrefBytes, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return b, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force default")
						}
					},
					MDel: func(bucket, key []byte) error {
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, string(key), provID+"."+ref)
							return errors.New("force")
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return errors.New("force default")
						}
					},
				},
				err: errors.New("error deleting ACME EAB Key reference with Key ID keyID and reference ref: force"),
			}
		},
		"fail/delete-eak": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:            keyID,
				ProvisionerID: provID,
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			dbref := &dbExternalAccountKeyReference{
				Reference:            ref,
				ExternalAccountKeyID: keyID,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			dbrefBytes, err := json.Marshal(dbref)
			assert.FatalError(t, err)
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, string(key), ref)
							return dbrefBytes, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return b, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force default")
						}
					},
					MDel: func(bucket, key []byte) error {
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, string(key), provID+"."+ref)
							return nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return errors.New("force")
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return errors.New("force default")
						}
					},
				},
				err: errors.New("error deleting ACME EAB Key with Key ID keyID: force"),
			}
		},
		"fail/delete-eakID": func(t *testing.T) test {
			now := clock.Now()
			dbeak := &dbExternalAccountKey{
				ID:            keyID,
				ProvisionerID: provID,
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			dbref := &dbExternalAccountKeyReference{
				Reference:            ref,
				ExternalAccountKeyID: keyID,
			}
			b, err := json.Marshal(dbeak)
			assert.FatalError(t, err)
			dbrefBytes, err := json.Marshal(dbref)
			assert.FatalError(t, err)
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, string(key), ref)
							return dbrefBytes, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return b, nil
						case string(externalAccountKeyIDsByProvisionerIDTable):
							return b, errors.New("force")
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, errors.New("force default")
						}
					},
					MDel: func(bucket, key []byte) error {
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, string(key), provID+"."+ref)
							return nil
						case string(externalAccountKeyTable):
							assert.Equals(t, string(key), keyID)
							return nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return errors.New("force default")
						}
					},
				},
				err: errors.New("error removing ACME EAB Key ID keyID: error loading eakIDs for provisioner provID: force"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if err := d.DeleteExternalAccountKey(context.Background(), provID, keyID); err != nil {
				var ae *acme.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.acmeErr) {
						assert.Equals(t, ae.Type, tc.acmeErr.Type)
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
						assert.Equals(t, ae.Status, tc.acmeErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.acmeErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.acmeErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.Equals(t, err.Error(), tc.err.Error())
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestDB_CreateExternalAccountKey(t *testing.T) {
	keyID := "keyID"
	provID := "provID"
	ref := "ref"
	type test struct {
		db  nosql.DB
		err error
		_id *string
		eak *acme.ExternalAccountKey
	}
	var tests = map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			var (
				id    string
				idPtr = &id
			)
			now := clock.Now()
			eak := &acme.ExternalAccountKey{
				ID:            keyID,
				ProvisionerID: provID,
				Reference:     "ref",
				AccountID:     "",
				CreatedAt:     now,
			}
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyIDsByProvisionerIDTable))
						assert.Equals(t, provID, string(key))
						b, _ := json.Marshal([]string{})
						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						switch string(bucket) {
						case string(externalAccountKeyIDsByProvisionerIDTable):
							assert.Equals(t, provID, string(key))
							return nu, true, nil
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, provID+"."+ref, string(key))
							assert.Equals(t, nil, old)
							return nu, true, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, nil, old)

							id = string(key)

							dbeak := new(dbExternalAccountKey)
							assert.FatalError(t, json.Unmarshal(nu, dbeak))
							assert.Equals(t, string(key), dbeak.ID)
							assert.Equals(t, eak.ProvisionerID, dbeak.ProvisionerID)
							assert.Equals(t, eak.Reference, dbeak.Reference)
							assert.Equals(t, 32, len(dbeak.HmacKey))
							assert.False(t, dbeak.CreatedAt.IsZero())
							assert.Equals(t, dbeak.AccountID, eak.AccountID)
							assert.True(t, dbeak.BoundAt.IsZero())
							return nu, true, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, false, errors.New("force default")
						}
					},
				},
				eak: eak,
				_id: idPtr,
			}
		},
		"fail/externalAccountKeyID-cmpAndSwap-error": func(t *testing.T) test {
			return test{
				db: &certdb.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, string(key), ref)
							assert.Equals(t, old, nil)
							return nu, true, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, old, nil)
							return nu, true, errors.New("force")
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, false, errors.New("force default")
						}
					},
				},
				err: errors.New("error saving acme external_account_key: force"),
			}
		},
		"fail/addEAKID-error": func(t *testing.T) test {
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyIDsByProvisionerIDTable))
						assert.Equals(t, provID, string(key))
						return nil, errors.New("force")
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						switch string(bucket) {
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, string(key), ref)
							assert.Equals(t, old, nil)
							return nu, true, nil
						case string(externalAccountKeyTable):
							assert.Equals(t, old, nil)
							return nu, true, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, false, errors.New("force default")
						}
					},
				},
				err: errors.New("error loading eakIDs for provisioner provID: force"),
			}
		},
		"fail/externalAccountKeyReference-cmpAndSwap-error": func(t *testing.T) test {
			return test{
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, string(bucket), string(externalAccountKeyIDsByProvisionerIDTable))
						assert.Equals(t, provID, string(key))
						b, _ := json.Marshal([]string{})
						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						switch string(bucket) {
						case string(externalAccountKeyIDsByProvisionerIDTable):
							assert.Equals(t, provID, string(key))
							return nu, true, nil
						case string(externalAccountKeyIDsByReferenceTable):
							assert.Equals(t, provID+"."+ref, string(key))
							assert.Equals(t, old, nil)
							return nu, true, errors.New("force")
						case string(externalAccountKeyTable):
							assert.Equals(t, old, nil)
							return nu, true, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected bucket %s", string(bucket)))
							return nil, false, errors.New("force default")
						}
					},
				},
				err: errors.New("error saving acme external_account_key_reference: force"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			eak, err := d.CreateExternalAccountKey(context.Background(), provID, ref)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.Equals(t, err.Error(), tc.err.Error())
				}
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, *tc._id, eak.ID)
				assert.Equals(t, provID, eak.ProvisionerID)
				assert.Equals(t, ref, eak.Reference)
				assert.Equals(t, "", eak.AccountID)
				assert.False(t, eak.CreatedAt.IsZero())
				assert.False(t, eak.AlreadyBound())
				assert.True(t, eak.BoundAt.IsZero())
			}
		})
	}
}

func TestDB_UpdateExternalAccountKey(t *testing.T) {
	keyID := "keyID"
	provID := "provID"
	ref := "ref"
	now := clock.Now()
	dbeak := &dbExternalAccountKey{
		ID:            keyID,
		ProvisionerID: provID,
		Reference:     ref,
		AccountID:     "",
		HmacKey:       []byte{1, 3, 3, 7},
		CreatedAt:     now,
	}
	b, err := json.Marshal(dbeak)
	assert.FatalError(t, err)
	type test struct {
		db  nosql.DB
		eak *acme.ExternalAccountKey
		err error
	}
	var tests = map[string]func(t *testing.T) test{

		"ok": func(t *testing.T) test {
			eak := &acme.ExternalAccountKey{
				ID:            keyID,
				ProvisionerID: provID,
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			return test{
				eak: eak,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, old, b)

						dbNew := new(dbExternalAccountKey)
						assert.FatalError(t, json.Unmarshal(nu, dbNew))
						assert.Equals(t, dbNew.ID, dbeak.ID)
						assert.Equals(t, dbNew.ProvisionerID, dbeak.ProvisionerID)
						assert.Equals(t, dbNew.Reference, dbeak.Reference)
						assert.Equals(t, dbNew.AccountID, dbeak.AccountID)
						assert.Equals(t, dbNew.CreatedAt, dbeak.CreatedAt)
						assert.Equals(t, dbNew.BoundAt, dbeak.BoundAt)
						assert.Equals(t, dbNew.HmacKey, dbeak.HmacKey)
						return nu, true, nil
					},
				},
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				eak: &acme.ExternalAccountKey{
					ID: keyID,
				},
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading external account key keyID: force"),
			}
		},
		"fail/provisioner-mismatch": func(t *testing.T) test {
			newDBEAK := &dbExternalAccountKey{
				ID:            keyID,
				ProvisionerID: "aDifferentProvID",
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			b, err := json.Marshal(newDBEAK)
			assert.FatalError(t, err)
			return test{
				eak: &acme.ExternalAccountKey{
					ID: keyID,
				},
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)

						return b, nil
					},
				},
				err: errors.New("provisioner does not match provisioner for which the EAB key was created"),
			}
		},
		"fail/provisioner-change": func(t *testing.T) test {
			newDBEAK := &dbExternalAccountKey{
				ID:            keyID,
				ProvisionerID: provID,
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			b, err := json.Marshal(newDBEAK)
			assert.FatalError(t, err)
			return test{
				eak: &acme.ExternalAccountKey{
					ID:            keyID,
					ProvisionerID: "aDifferentProvisionerID",
				},
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)
						return b, nil
					},
				},
				err: errors.New("cannot change provisioner for an existing ACME EAB Key"),
			}
		},
		"fail/reference-change": func(t *testing.T) test {
			newDBEAK := &dbExternalAccountKey{
				ID:            keyID,
				ProvisionerID: provID,
				Reference:     ref,
				AccountID:     "",
				HmacKey:       []byte{1, 3, 3, 7},
				CreatedAt:     now,
			}
			b, err := json.Marshal(newDBEAK)
			assert.FatalError(t, err)
			return test{
				eak: &acme.ExternalAccountKey{
					ID:            keyID,
					ProvisionerID: provID,
					Reference:     "aDifferentReference",
				},
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyTable)
						assert.Equals(t, string(key), keyID)
						return b, nil
					},
				},
				err: errors.New("cannot change reference for an existing ACME EAB Key"),
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if err := d.UpdateExternalAccountKey(context.Background(), provID, tc.eak); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, dbeak.ID, tc.eak.ID)
				assert.Equals(t, dbeak.ProvisionerID, tc.eak.ProvisionerID)
				assert.Equals(t, dbeak.Reference, tc.eak.Reference)
				assert.Equals(t, dbeak.AccountID, tc.eak.AccountID)
				assert.Equals(t, dbeak.CreatedAt, tc.eak.CreatedAt)
				assert.Equals(t, dbeak.BoundAt, tc.eak.BoundAt)
				assert.Equals(t, dbeak.HmacKey, tc.eak.HmacKey)
			}
		})
	}
}

func TestDB_addEAKID(t *testing.T) {
	provID := "provID"
	eakID := "eakID"
	type test struct {
		ctx           context.Context
		provisionerID string
		eakID         string
		db            nosql.DB
		err           error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/empty-eakID": func(t *testing.T) test {
			return test{
				ctx:           context.Background(),
				provisionerID: provID,
				eakID:         "",
				err:           errors.New("can't add empty eakID for provisioner provID"),
			}
		},
		"fail/db.Get": func(t *testing.T) test {
			return test{
				ctx:           context.Background(),
				provisionerID: provID,
				eakID:         eakID,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading eakIDs for provisioner provID: force"),
			}
		},
		"fail/unmarshal": func(t *testing.T) test {
			return test{
				ctx:           context.Background(),
				provisionerID: provID,
				eakID:         eakID,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						b, _ := json.Marshal(1)
						return b, nil
					},
				},
				err: errors.New("error unmarshaling eakIDs for provisioner provID: json: cannot unmarshal number into Go value of type []string"),
			}
		},
		"fail/eakID-already-exists": func(t *testing.T) test {
			return test{
				ctx:           context.Background(),
				provisionerID: provID,
				eakID:         eakID,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						b, _ := json.Marshal([]string{eakID})
						return b, nil
					},
				},
				err: errors.New("eakID eakID already exists for provisioner provID"),
			}
		},
		"fail/db.save": func(t *testing.T) test {
			return test{
				ctx:           context.Background(),
				provisionerID: provID,
				eakID:         eakID,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						b, _ := json.Marshal([]string{"id1"})
						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						oldB, _ := json.Marshal([]string{"id1"})
						assert.Equals(t, old, oldB)
						newB, _ := json.Marshal([]string{"id1", eakID})
						assert.Equals(t, nu, newB)
						return newB, true, errors.New("force")
					},
				},
				err: errors.New("error saving eakIDs index for provisioner provID: error saving acme externalAccountKeyIDsByProvisionerID: force"),
			}
		},
		"ok/db.Get-not-found": func(t *testing.T) test {
			return test{
				ctx:           context.Background(),
				provisionerID: provID,
				eakID:         eakID,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						return nil, nosqldb.ErrNotFound
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						assert.Equals(t, old, nil)
						b, _ := json.Marshal([]string{eakID})
						assert.Equals(t, nu, b)
						return b, true, nil
					},
				},
				err: nil,
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				ctx:           context.Background(),
				provisionerID: provID,
				eakID:         eakID,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						b, _ := json.Marshal([]string{"id1", "id2"})
						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						oldB, _ := json.Marshal([]string{"id1", "id2"})
						assert.Equals(t, old, oldB)
						newB, _ := json.Marshal([]string{"id1", "id2", eakID})
						assert.Equals(t, nu, newB)
						return newB, true, nil
					},
				},
				err: nil,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := &DB{
				db: tc.db,
			}
			wantErr := tc.err != nil
			err := db.addEAKID(tc.ctx, tc.provisionerID, tc.eakID)
			if (err != nil) != wantErr {
				t.Errorf("DB.addEAKID() error = %v, wantErr %v", err, wantErr)
			}
			if err != nil {
				assert.Equals(t, tc.err.Error(), err.Error())
			}
		})
	}
}

func TestDB_deleteEAKID(t *testing.T) {
	provID := "provID"
	eakID := "eakID"
	type test struct {
		ctx           context.Context
		provisionerID string
		eakID         string
		db            nosql.DB
		err           error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.Get": func(t *testing.T) test {
			return test{
				ctx:           context.Background(),
				provisionerID: provID,
				eakID:         eakID,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading eakIDs for provisioner provID: force"),
			}
		},
		"fail/unmarshal": func(t *testing.T) test {
			return test{
				ctx:           context.Background(),
				provisionerID: provID,
				eakID:         eakID,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						b, _ := json.Marshal(1)
						return b, nil
					},
				},
				err: errors.New("error unmarshaling eakIDs for provisioner provID: json: cannot unmarshal number into Go value of type []string"),
			}
		},
		"fail/db.save": func(t *testing.T) test {
			return test{
				ctx:           context.Background(),
				provisionerID: provID,
				eakID:         eakID,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						b, _ := json.Marshal([]string{"id1", eakID})
						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						oldB, _ := json.Marshal([]string{"id1", eakID})
						assert.Equals(t, old, oldB)
						newB, _ := json.Marshal([]string{"id1"})
						assert.Equals(t, nu, newB)
						return newB, true, errors.New("force")
					},
				},
				err: errors.New("error saving eakIDs index for provisioner provID: error saving acme externalAccountKeyIDsByProvisionerID: force"),
			}
		},
		"ok/db.Get-not-found": func(t *testing.T) test {
			return test{
				ctx:           context.Background(),
				provisionerID: provID,
				eakID:         eakID,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						return nil, nosqldb.ErrNotFound
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						assert.Equals(t, old, nil)
						b, _ := json.Marshal([]string{})
						assert.Equals(t, nu, b)
						return b, true, nil
					},
				},
				err: nil,
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				ctx:           context.Background(),
				provisionerID: provID,
				eakID:         eakID,
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						b, _ := json.Marshal([]string{"id1", eakID, "id2"})
						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						oldB, _ := json.Marshal([]string{"id1", eakID, "id2"})
						assert.Equals(t, old, oldB)
						newB, _ := json.Marshal([]string{"id1", "id2"})
						assert.Equals(t, nu, newB)
						return newB, true, nil
					},
				},
				err: nil,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			db := &DB{
				db: tc.db,
			}
			wantErr := tc.err != nil
			err := db.deleteEAKID(tc.ctx, tc.provisionerID, tc.eakID)
			if (err != nil) != wantErr {
				t.Errorf("DB.deleteEAKID() error = %v, wantErr %v", err, wantErr)
			}
			if err != nil {
				assert.Equals(t, tc.err.Error(), err.Error())
			}
		})
	}
}

func TestDB_addAndDeleteEAKID(t *testing.T) {
	provID := "provID"
	callCounter := 0
	type test struct {
		ctx context.Context
		db  nosql.DB
		err error
	}
	var tests = map[string]func(t *testing.T) test{
		"ok/multi": func(t *testing.T) test {
			return test{
				ctx: context.Background(),
				db: &certdb.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						switch callCounter {
						case 0:
							return nil, nosqldb.ErrNotFound
						case 1:
							b, _ := json.Marshal([]string{"eakID"})
							return b, nil
						case 2:
							b, _ := json.Marshal([]string{})
							return b, nil
						case 3:
							b, _ := json.Marshal([]string{"eakID1"})
							return b, nil
						case 4:
							b, _ := json.Marshal([]string{"eakID1", "eakID2"})
							return b, nil
						case 5:
							b, _ := json.Marshal([]string{"eakID2"})
							return b, nil
						default:
							assert.FatalError(t, errors.New("unexpected get iteration"))
							return nil, errors.New("force get default")
						}
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, externalAccountKeyIDsByProvisionerIDTable)
						assert.Equals(t, string(key), provID)
						switch callCounter {
						case 0:
							assert.Equals(t, old, nil)
							newB, _ := json.Marshal([]string{"eakID"})
							assert.Equals(t, nu, newB)
							return newB, true, nil
						case 1:
							oldB, _ := json.Marshal([]string{"eakID"})
							assert.Equals(t, old, oldB)
							newB, _ := json.Marshal([]string{})
							return newB, true, nil
						case 2:
							assert.Equals(t, old, nil)
							newB, _ := json.Marshal([]string{"eakID1"})
							assert.Equals(t, nu, newB)
							return newB, true, nil
						case 3:
							oldB, _ := json.Marshal([]string{"eakID1"})
							assert.Equals(t, old, oldB)
							newB, _ := json.Marshal([]string{"eakID1", "eakID2"})
							assert.Equals(t, nu, newB)
							return newB, true, nil
						case 4:
							oldB, _ := json.Marshal([]string{"eakID1", "eakID2"})
							assert.Equals(t, old, oldB)
							newB, _ := json.Marshal([]string{"eakID2"})
							assert.Equals(t, nu, newB)
							return newB, true, nil
						case 5:
							oldB, _ := json.Marshal([]string{"eakID2"})
							assert.Equals(t, old, oldB)
							newB, _ := json.Marshal([]string{})
							assert.Equals(t, nu, newB)
							return newB, true, nil
						default:
							assert.FatalError(t, errors.New("unexpected get iteration"))
							return nil, true, errors.New("force save default")
						}
					},
				},
				err: nil,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {

			// goal of this test is to simulate multiple calls; no errors expected.

			db := &DB{
				db: tc.db,
			}

			err := db.addEAKID(tc.ctx, provID, "eakID")
			if err != nil {
				t.Errorf("DB.addEAKID() error = %v", err)
			}

			callCounter++
			err = db.deleteEAKID(tc.ctx, provID, "eakID")
			if err != nil {
				t.Errorf("DB.deleteEAKID() error = %v", err)
			}

			callCounter++
			err = db.addEAKID(tc.ctx, provID, "eakID1")
			if err != nil {
				t.Errorf("DB.addEAKID() error = %v", err)
			}

			callCounter++
			err = db.addEAKID(tc.ctx, provID, "eakID2")
			if err != nil {
				t.Errorf("DB.addEAKID() error = %v", err)
			}

			callCounter++
			err = db.deleteEAKID(tc.ctx, provID, "eakID1")
			if err != nil {
				t.Errorf("DB.deleteEAKID() error = %v", err)
			}

			callCounter++
			err = db.deleteEAKID(tc.ctx, provID, "eakID2")
			if err != nil {
				t.Errorf("DB.deleteAKID() error = %v", err)
			}
		})
	}
}

func Test_removeElement(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		item  string
		want  []string
	}{
		{
			name:  "remove-first",
			slice: []string{"id1", "id2", "id3"},
			item:  "id1",
			want:  []string{"id2", "id3"},
		},
		{
			name:  "remove-last",
			slice: []string{"id1", "id2", "id3"},
			item:  "id3",
			want:  []string{"id1", "id2"},
		},
		{
			name:  "remove-middle",
			slice: []string{"id1", "id2", "id3"},
			item:  "id2",
			want:  []string{"id1", "id3"},
		},
		{
			name:  "remove-non-existing",
			slice: []string{"id1", "id2", "id3"},
			item:  "none",
			want:  []string{"id1", "id2", "id3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removeElement(tt.slice, tt.item)
			if !cmp.Equal(tt.want, got) {
				t.Errorf("removeElement() diff =\n %s", cmp.Diff(tt.want, got))
			}
		})
	}
}
