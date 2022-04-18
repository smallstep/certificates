package nosql

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"go.step.sm/linkedca"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	nosqldb "github.com/smallstep/nosql/database"
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
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
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
				Policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"*.local"},
						},
					},
				},
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
				Policy: &linkedca.Policy{
					X509: &linkedca.X509Policy{
						Allow: &linkedca.X509Names{
							Dns: []string{"*.local"},
						},
					},
				},
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
			if dbp, err := d.getDBAuthorityPolicy(tc.ctx, tc.authorityID); err != nil {
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
			} else if assert.Nil(t, tc.err) && assert.Nil(t, tc.adminErr) && tc.dbap == nil {
				assert.Nil(t, dbp)
			} else if assert.Nil(t, tc.err) && assert.Nil(t, tc.adminErr) {
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
						assert.Equals(t, _dbap.Policy, policy)

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
						assert.Equals(t, _dbap.Policy, policy)

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
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
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
							Policy:      policy,
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
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
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
							Policy:      oldPolicy,
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
						assert.Equals(t, _dbap.Policy, policy)

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
							Policy:      oldPolicy,
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
						assert.Equals(t, _dbap.Policy, policy)

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
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
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
							Policy:      oldPolicy,
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
							Policy:      oldPolicy,
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
				switch k := err.(type) {
				case *admin.Error:
					if assert.NotNil(t, tc.adminErr) {
						assert.Equals(t, k.Type, tc.adminErr.Type)
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
						assert.Equals(t, k.Status, tc.adminErr.Status)
						assert.Equals(t, k.Err.Error(), tc.adminErr.Err.Error())
						assert.Equals(t, k.Detail, tc.adminErr.Detail)
					}
				default:
					if assert.NotNil(t, tc.err) {
						assert.HasPrefix(t, err.Error(), tc.err.Error())
					}
				}
				return
			}
		})
	}
}
