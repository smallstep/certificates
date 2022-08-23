package nosql

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	nosqldb "github.com/smallstep/nosql/database"
	"go.step.sm/linkedca"
)

func TestDB_getDBAuthorityPolicyBytes(t *testing.T) {
	authID := "authID"
	type test struct {
		ctx         context.Context
		authorityID string
		db          nosql.DB
		err         error
		adminErr    *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "authority policy not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading authority policy: force"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						return []byte("foo"), nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db}
			if b, err := d.getDBAuthorityPolicyBytes(tc.ctx, tc.authorityID); err != nil {
				var ae *admin.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, ae.Type, tc.adminErr.Type)
						assert.Equals(t, ae.Detail, tc.adminErr.Detail)
						assert.Equals(t, ae.Status, tc.adminErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.adminErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) && assert.Nil(t, tc.adminErr) {
				assert.Equals(t, string(b), "foo")
			}
		})
	}
}

func TestDB_getDBAuthorityPolicy(t *testing.T) {
	authID := "authID"
	type test struct {
		ctx         context.Context
		authorityID string
		db          nosql.DB
		err         error
		adminErr    *admin.Error
		dbap        *dbAuthorityPolicy
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "authority policy not found"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling policy bytes into dbAuthorityPolicy"),
			}
		},
		"fail/authorityID-error": func(t *testing.T) test {
			dbp := &dbAuthorityPolicy{
				ID:          "ID",
				AuthorityID: "diffAuthID",
				Policy: linkedToDB(&linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"*.local"},
						},
					},
				}),
			}
			b, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						return b, nil
					},
				},
				adminErr: admin.NewError(admin.ErrorAuthorityMismatchType,
					"authority policy is not owned by authority authID"),
			}
		},
		"ok/empty-bytes": func(t *testing.T) test {
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						return []byte{}, nil
					},
				},
			}
		},
		"ok": func(t *testing.T) test {
			dbap := &dbAuthorityPolicy{
				ID:          "ID",
				AuthorityID: authID,
				Policy: linkedToDB(&linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"*.local"},
						},
					},
				}),
			}
			b, err := json.Marshal(dbap)
			assert.FatalError(t, err)
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						return b, nil
					},
				},
				dbap: dbap,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			dbp, err := d.getDBAuthorityPolicy(tc.ctx, tc.authorityID)
			switch {
			case err != nil:
				var ae *admin.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, ae.Type, tc.adminErr.Type)
						assert.Equals(t, ae.Detail, tc.adminErr.Detail)
						assert.Equals(t, ae.Status, tc.adminErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.adminErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			case assert.Nil(t, tc.err) && assert.Nil(t, tc.adminErr) && tc.dbap == nil:
				assert.Nil(t, dbp)
			case assert.Nil(t, tc.err) && assert.Nil(t, tc.adminErr):
				assert.Equals(t, dbp.ID, "ID")
				assert.Equals(t, dbp.AuthorityID, tc.dbap.AuthorityID)
				assert.Equals(t, dbp.Policy, tc.dbap.Policy)
			}
		})
	}
}

func TestDB_CreateAuthorityPolicy(t *testing.T) {
	authID := "authID"
	type test struct {
		ctx         context.Context
		authorityID string
		policy      *linkedca.Policy
		db          nosql.DB
		err         error
		adminErr    *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/save-error": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				policy:      policy,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)

						var _dbap = new(dbAuthorityPolicy)
						assert.FatalError(t, json.Unmarshal(nu, _dbap))

						assert.Equals(t, _dbap.ID, authID)
						assert.Equals(t, _dbap.AuthorityID, authID)
						assert.Equals(t, _dbap.Policy, linkedToDB(policy))

						return nil, false, errors.New("force")
					},
				},
				adminErr: admin.NewErrorISE("error creating authority policy: error saving authority authority_policy: force"),
			}
		},
		"ok": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				policy:      policy,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, old, nil)

						var _dbap = new(dbAuthorityPolicy)
						assert.FatalError(t, json.Unmarshal(nu, _dbap))

						assert.Equals(t, _dbap.ID, authID)
						assert.Equals(t, _dbap.AuthorityID, authID)
						assert.Equals(t, _dbap.Policy, linkedToDB(policy))

						return nil, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: tc.authorityID}
			if err := d.CreateAuthorityPolicy(tc.ctx, tc.policy); err != nil {
				var ae *admin.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, ae.Type, tc.adminErr.Type)
						assert.Equals(t, ae.Detail, tc.adminErr.Detail)
						assert.Equals(t, ae.Status, tc.adminErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.adminErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			}
		})
	}
}

func TestDB_GetAuthorityPolicy(t *testing.T) {
	authID := "authID"
	type test struct {
		ctx         context.Context
		authorityID string
		policy      *linkedca.Policy
		db          nosql.DB
		err         error
		adminErr    *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "authority policy not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading authority policy: force"),
			}
		},
		"ok": func(t *testing.T) test {
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				policy:      policy,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)

						dbap := &dbAuthorityPolicy{
							ID:          authID,
							AuthorityID: authID,
							Policy:      linkedToDB(policy),
						}

						b, err := json.Marshal(dbap)
						assert.FatalError(t, err)

						return b, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: tc.authorityID}
			got, err := d.GetAuthorityPolicy(tc.ctx)
			if err != nil {
				var ae *admin.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, ae.Type, tc.adminErr.Type)
						assert.Equals(t, ae.Detail, tc.adminErr.Detail)
						assert.Equals(t, ae.Status, tc.adminErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.adminErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
				return
			}

			assert.NotNil(t, got)
			assert.Equals(t, tc.policy, got)
		})
	}
}

func TestDB_UpdateAuthorityPolicy(t *testing.T) {
	authID := "authID"
	type test struct {
		ctx         context.Context
		authorityID string
		policy      *linkedca.Policy
		db          nosql.DB
		err         error
		adminErr    *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "authority policy not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading authority policy: force"),
			}
		},
		"fail/save-error": func(t *testing.T) test {
			oldPolicy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.localhost"},
					},
				},
			}
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				policy:      policy,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)

						dbap := &dbAuthorityPolicy{
							ID:          authID,
							AuthorityID: authID,
							Policy:      linkedToDB(oldPolicy),
						}

						b, err := json.Marshal(dbap)
						assert.FatalError(t, err)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)

						var _dbap = new(dbAuthorityPolicy)
						assert.FatalError(t, json.Unmarshal(nu, _dbap))

						assert.Equals(t, _dbap.ID, authID)
						assert.Equals(t, _dbap.AuthorityID, authID)
						assert.Equals(t, _dbap.Policy, linkedToDB(policy))

						return nil, false, errors.New("force")
					},
				},
				adminErr: admin.NewErrorISE("error updating authority policy: error saving authority authority_policy: force"),
			}
		},
		"ok": func(t *testing.T) test {
			oldPolicy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.localhost"},
					},
				},
			}
			policy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.local"},
					},
				},
			}
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				policy:      policy,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)

						dbap := &dbAuthorityPolicy{
							ID:          authID,
							AuthorityID: authID,
							Policy:      linkedToDB(oldPolicy),
						}

						b, err := json.Marshal(dbap)
						assert.FatalError(t, err)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)

						var _dbap = new(dbAuthorityPolicy)
						assert.FatalError(t, json.Unmarshal(nu, _dbap))

						assert.Equals(t, _dbap.ID, authID)
						assert.Equals(t, _dbap.AuthorityID, authID)
						assert.Equals(t, _dbap.Policy, linkedToDB(policy))

						return nil, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: tc.authorityID}
			if err := d.UpdateAuthorityPolicy(tc.ctx, tc.policy); err != nil {
				var ae *admin.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, ae.Type, tc.adminErr.Type)
						assert.Equals(t, ae.Detail, tc.adminErr.Detail)
						assert.Equals(t, ae.Status, tc.adminErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.adminErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
				return
			}
		})
	}
}

func TestDB_DeleteAuthorityPolicy(t *testing.T) {
	authID := "authID"
	type test struct {
		ctx         context.Context
		authorityID string
		db          nosql.DB
		err         error
		adminErr    *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "authority policy not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading authority policy: force"),
			}
		},
		"fail/save-error": func(t *testing.T) test {
			oldPolicy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.localhost"},
					},
				},
			}
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)

						dbap := &dbAuthorityPolicy{
							ID:          authID,
							AuthorityID: authID,
							Policy:      linkedToDB(oldPolicy),
						}

						b, err := json.Marshal(dbap)
						assert.FatalError(t, err)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						assert.Equals(t, nil, nu)

						return nil, false, errors.New("force")
					},
				},
				adminErr: admin.NewErrorISE("error deleting authority policy: error saving authority authority_policy: force"),
			}
		},
		"ok": func(t *testing.T) test {
			oldPolicy := &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns: []string{"*.localhost"},
					},
				},
			}
			return test{
				ctx:         context.Background(),
				authorityID: authID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)

						dbap := &dbAuthorityPolicy{
							ID:          authID,
							AuthorityID: authID,
							Policy:      linkedToDB(oldPolicy),
						}

						b, err := json.Marshal(dbap)
						assert.FatalError(t, err)

						return b, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, authorityPoliciesTable)
						assert.Equals(t, string(key), authID)
						assert.Equals(t, nil, nu)

						return nil, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: tc.authorityID}
			if err := d.DeleteAuthorityPolicy(tc.ctx); err != nil {
				var ae *admin.Error
				if errors.As(err, &ae) {
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, ae.Type, tc.adminErr.Type)
						assert.Equals(t, ae.Detail, tc.adminErr.Detail)
						assert.Equals(t, ae.Status, tc.adminErr.Status)
						assert.Equals(t, ae.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, ae.Detail, tc.adminErr.Detail)
					}
				} else {
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
				return
			}
		})
	}
}

func Test_linkedToDB(t *testing.T) {
	type args struct {
		p *linkedca.Policy
	}
	tests := []struct {
		name string
		args args
		want *dbPolicy
	}{
		{
			name: "nil policy",
			args: args{
				p: nil,
			},
			want: nil,
		},
		{
			name: "no x509 nor ssh",
			args: args{
				p: &linkedca.Policy{},
			},
			want: nil,
		},
		{
			name: "x509",
			args: args{
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns:         []string{"*.local"},
							Ips:         []string{"192.168.0.1/24"},
							Emails:      []string{"@example.com"},
							Uris:        []string{"*.example.com"},
							CommonNames: []string{"some name"},
						},
						Deny: &linkedca.X509Names{
							Dns:         []string{"badhost.local"},
							Ips:         []string{"192.168.0.30"},
							Emails:      []string{"root@example.com"},
							Uris:        []string{"bad.example.com"},
							CommonNames: []string{"bad name"},
						},
						AllowWildcardNames: true,
					},
				},
			},
			want: &dbPolicy{
				X509: &dbX509Policy{
					Allow: &dbX509Names{
						DNSDomains:     []string{"*.local"},
						IPRanges:       []string{"192.168.0.1/24"},
						EmailAddresses: []string{"@example.com"},
						URIDomains:     []string{"*.example.com"},
						CommonNames:    []string{"some name"},
					},
					Deny: &dbX509Names{
						DNSDomains:     []string{"badhost.local"},
						IPRanges:       []string{"192.168.0.30"},
						EmailAddresses: []string{"root@example.com"},
						URIDomains:     []string{"bad.example.com"},
						CommonNames:    []string{"bad name"},
					},
					AllowWildcardNames: true,
				},
			},
		},
		{
			name: "ssh user",
			args: args{
				p: &linkedca.Policy{
					Ssh: &linkedca.SSHPolicy{
						User: &linkedca.SSHUserPolicy{
							Allow: &linkedca.SSHUserNames{
								Emails:     []string{"@example.com"},
								Principals: []string{"user"},
							},
							Deny: &linkedca.SSHUserNames{
								Emails:     []string{"root@example.com"},
								Principals: []string{"root"},
							},
						},
					},
				},
			},
			want: &dbPolicy{
				SSH: &dbSSHPolicy{
					User: &dbSSHUserPolicy{
						Allow: &dbSSHUserNames{
							EmailAddresses: []string{"@example.com"},
							Principals:     []string{"user"},
						},
						Deny: &dbSSHUserNames{
							EmailAddresses: []string{"root@example.com"},
							Principals:     []string{"root"},
						},
					},
				},
			},
		},
		{
			name: "full ssh policy",
			args: args{
				p: &linkedca.Policy{
					Ssh: &linkedca.SSHPolicy{
						Host: &linkedca.SSHHostPolicy{
							Allow: &linkedca.SSHHostNames{
								Dns:        []string{"*.local"},
								Ips:        []string{"192.168.0.1/24"},
								Principals: []string{"host"},
							},
							Deny: &linkedca.SSHHostNames{
								Dns:        []string{"badhost.local"},
								Ips:        []string{"192.168.0.30"},
								Principals: []string{"bad"},
							},
						},
					},
				},
			},
			want: &dbPolicy{
				SSH: &dbSSHPolicy{
					Host: &dbSSHHostPolicy{
						Allow: &dbSSHHostNames{
							DNSDomains: []string{"*.local"},
							IPRanges:   []string{"192.168.0.1/24"},
							Principals: []string{"host"},
						},
						Deny: &dbSSHHostNames{
							DNSDomains: []string{"badhost.local"},
							IPRanges:   []string{"192.168.0.30"},
							Principals: []string{"bad"},
						},
					},
				},
			},
		},
		{
			name: "full policy",
			args: args{
				p: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns:         []string{"*.local"},
							Ips:         []string{"192.168.0.1/24"},
							Emails:      []string{"@example.com"},
							Uris:        []string{"*.example.com"},
							CommonNames: []string{"some name"},
						},
						Deny: &linkedca.X509Names{
							Dns:         []string{"badhost.local"},
							Ips:         []string{"192.168.0.30"},
							Emails:      []string{"root@example.com"},
							Uris:        []string{"bad.example.com"},
							CommonNames: []string{"bad name"},
						},
						AllowWildcardNames: true,
					},
					Ssh: &linkedca.SSHPolicy{
						User: &linkedca.SSHUserPolicy{
							Allow: &linkedca.SSHUserNames{
								Emails:     []string{"@example.com"},
								Principals: []string{"user"},
							},
							Deny: &linkedca.SSHUserNames{
								Emails:     []string{"root@example.com"},
								Principals: []string{"root"},
							},
						},
						Host: &linkedca.SSHHostPolicy{
							Allow: &linkedca.SSHHostNames{
								Dns:        []string{"*.local"},
								Ips:        []string{"192.168.0.1/24"},
								Principals: []string{"host"},
							},
							Deny: &linkedca.SSHHostNames{
								Dns:        []string{"badhost.local"},
								Ips:        []string{"192.168.0.30"},
								Principals: []string{"bad"},
							},
						},
					},
				},
			},
			want: &dbPolicy{
				X509: &dbX509Policy{
					Allow: &dbX509Names{
						DNSDomains:     []string{"*.local"},
						IPRanges:       []string{"192.168.0.1/24"},
						EmailAddresses: []string{"@example.com"},
						URIDomains:     []string{"*.example.com"},
						CommonNames:    []string{"some name"},
					},
					Deny: &dbX509Names{
						DNSDomains:     []string{"badhost.local"},
						IPRanges:       []string{"192.168.0.30"},
						EmailAddresses: []string{"root@example.com"},
						URIDomains:     []string{"bad.example.com"},
						CommonNames:    []string{"bad name"},
					},
					AllowWildcardNames: true,
				},
				SSH: &dbSSHPolicy{
					User: &dbSSHUserPolicy{
						Allow: &dbSSHUserNames{
							EmailAddresses: []string{"@example.com"},
							Principals:     []string{"user"},
						},
						Deny: &dbSSHUserNames{
							EmailAddresses: []string{"root@example.com"},
							Principals:     []string{"root"},
						},
					},
					Host: &dbSSHHostPolicy{
						Allow: &dbSSHHostNames{
							DNSDomains: []string{"*.local"},
							IPRanges:   []string{"192.168.0.1/24"},
							Principals: []string{"host"},
						},
						Deny: &dbSSHHostNames{
							DNSDomains: []string{"badhost.local"},
							IPRanges:   []string{"192.168.0.30"},
							Principals: []string{"bad"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linkedToDB(tt.args.p); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("linkedToDB() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_dbToLinked(t *testing.T) {
	type args struct {
		p *dbPolicy
	}
	tests := []struct {
		name string
		args args
		want *linkedca.Policy
	}{
		{
			name: "nil policy",
			args: args{
				p: nil,
			},
			want: nil,
		},
		{
			name: "x509",
			args: args{
				p: &dbPolicy{
					X509: &dbX509Policy{
						Allow: &dbX509Names{
							DNSDomains:     []string{"*.local"},
							IPRanges:       []string{"192.168.0.1/24"},
							EmailAddresses: []string{"@example.com"},
							URIDomains:     []string{"*.example.com"},
							CommonNames:    []string{"some name"},
						},
						Deny: &dbX509Names{
							DNSDomains:     []string{"badhost.local"},
							IPRanges:       []string{"192.168.0.30"},
							EmailAddresses: []string{"root@example.com"},
							URIDomains:     []string{"bad.example.com"},
							CommonNames:    []string{"bad name"},
						},
						AllowWildcardNames: true,
					},
				},
			},
			want: &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns:         []string{"*.local"},
						Ips:         []string{"192.168.0.1/24"},
						Emails:      []string{"@example.com"},
						Uris:        []string{"*.example.com"},
						CommonNames: []string{"some name"},
					},
					Deny: &linkedca.X509Names{
						Dns:         []string{"badhost.local"},
						Ips:         []string{"192.168.0.30"},
						Emails:      []string{"root@example.com"},
						Uris:        []string{"bad.example.com"},
						CommonNames: []string{"bad name"},
					},
					AllowWildcardNames: true,
				},
			},
		},
		{
			name: "ssh user",
			args: args{
				p: &dbPolicy{
					SSH: &dbSSHPolicy{
						User: &dbSSHUserPolicy{
							Allow: &dbSSHUserNames{
								EmailAddresses: []string{"@example.com"},
								Principals:     []string{"user"},
							},
							Deny: &dbSSHUserNames{
								EmailAddresses: []string{"root@example.com"},
								Principals:     []string{"root"},
							},
						},
					},
				},
			},
			want: &linkedca.Policy{
				Ssh: &linkedca.SSHPolicy{
					User: &linkedca.SSHUserPolicy{
						Allow: &linkedca.SSHUserNames{
							Emails:     []string{"@example.com"},
							Principals: []string{"user"},
						},
						Deny: &linkedca.SSHUserNames{
							Emails:     []string{"root@example.com"},
							Principals: []string{"root"},
						},
					},
				},
			},
		},
		{
			name: "ssh host",
			args: args{
				p: &dbPolicy{
					SSH: &dbSSHPolicy{
						Host: &dbSSHHostPolicy{
							Allow: &dbSSHHostNames{
								DNSDomains: []string{"*.local"},
								IPRanges:   []string{"192.168.0.1/24"},
								Principals: []string{"host"},
							},
							Deny: &dbSSHHostNames{
								DNSDomains: []string{"badhost.local"},
								IPRanges:   []string{"192.168.0.30"},
								Principals: []string{"bad"},
							},
						},
					},
				},
			},
			want: &linkedca.Policy{
				Ssh: &linkedca.SSHPolicy{
					Host: &linkedca.SSHHostPolicy{
						Allow: &linkedca.SSHHostNames{
							Dns:        []string{"*.local"},
							Ips:        []string{"192.168.0.1/24"},
							Principals: []string{"host"},
						},
						Deny: &linkedca.SSHHostNames{
							Dns:        []string{"badhost.local"},
							Ips:        []string{"192.168.0.30"},
							Principals: []string{"bad"},
						},
					},
				},
			},
		},
		{
			name: "full policy",
			args: args{
				p: &dbPolicy{
					X509: &dbX509Policy{
						Allow: &dbX509Names{
							DNSDomains:     []string{"*.local"},
							IPRanges:       []string{"192.168.0.1/24"},
							EmailAddresses: []string{"@example.com"},
							URIDomains:     []string{"*.example.com"},
							CommonNames:    []string{"some name"},
						},
						Deny: &dbX509Names{
							DNSDomains:     []string{"badhost.local"},
							IPRanges:       []string{"192.168.0.30"},
							EmailAddresses: []string{"root@example.com"},
							URIDomains:     []string{"bad.example.com"},
							CommonNames:    []string{"bad name"},
						},
						AllowWildcardNames: true,
					},
					SSH: &dbSSHPolicy{
						User: &dbSSHUserPolicy{
							Allow: &dbSSHUserNames{
								EmailAddresses: []string{"@example.com"},
								Principals:     []string{"user"},
							},
							Deny: &dbSSHUserNames{
								EmailAddresses: []string{"root@example.com"},
								Principals:     []string{"root"},
							},
						},
						Host: &dbSSHHostPolicy{
							Allow: &dbSSHHostNames{
								DNSDomains: []string{"*.local"},
								IPRanges:   []string{"192.168.0.1/24"},
								Principals: []string{"host"},
							},
							Deny: &dbSSHHostNames{
								DNSDomains: []string{"badhost.local"},
								IPRanges:   []string{"192.168.0.30"},
								Principals: []string{"bad"},
							},
						},
					},
				},
			},
			want: &linkedca.Policy{
				X509: &linkedca.X509Policy{
					Allow: &linkedca.X509Names{
						Dns:         []string{"*.local"},
						Ips:         []string{"192.168.0.1/24"},
						Emails:      []string{"@example.com"},
						Uris:        []string{"*.example.com"},
						CommonNames: []string{"some name"},
					},
					Deny: &linkedca.X509Names{
						Dns:         []string{"badhost.local"},
						Ips:         []string{"192.168.0.30"},
						Emails:      []string{"root@example.com"},
						Uris:        []string{"bad.example.com"},
						CommonNames: []string{"bad name"},
					},
					AllowWildcardNames: true,
				},
				Ssh: &linkedca.SSHPolicy{
					User: &linkedca.SSHUserPolicy{
						Allow: &linkedca.SSHUserNames{
							Emails:     []string{"@example.com"},
							Principals: []string{"user"},
						},
						Deny: &linkedca.SSHUserNames{
							Emails:     []string{"root@example.com"},
							Principals: []string{"root"},
						},
					},
					Host: &linkedca.SSHHostPolicy{
						Allow: &linkedca.SSHHostNames{
							Dns:        []string{"*.local"},
							Ips:        []string{"192.168.0.1/24"},
							Principals: []string{"host"},
						},
						Deny: &linkedca.SSHHostNames{
							Dns:        []string{"badhost.local"},
							Ips:        []string{"192.168.0.30"},
							Principals: []string{"bad"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dbToLinked(tt.args.p); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dbToLinked() = %v, want %v", got, tt.want)
			}
		})
	}
}
