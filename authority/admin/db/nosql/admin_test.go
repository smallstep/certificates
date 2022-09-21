package nosql

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	nosqldb "github.com/smallstep/nosql/database"
	"go.step.sm/linkedca"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDB_getDBAdminBytes(t *testing.T) {
	adminID := "adminID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "admin adminID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading admin adminID: force"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

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
			if b, err := d.getDBAdminBytes(context.Background(), adminID); err != nil {
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
			} else if assert.Nil(t, tc.err) {
				assert.Equals(t, string(b), "foo")
			}
		})
	}
}

func TestDB_getDBAdmin(t *testing.T) {
	adminID := "adminID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		dba      *dbAdmin
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "admin adminID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading admin adminID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling admin adminID into dbAdmin"),
			}
		},
		"fail/deleted": func(t *testing.T) test {
			now := clock.Now()
			dba := &dbAdmin{
				ID:            adminID,
				AuthorityID:   admin.DefaultAuthorityID,
				ProvisionerID: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     now,
				DeletedAt:     now,
			}
			b, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return b, nil
					},
				},
				adminErr: admin.NewError(admin.ErrorDeletedType, "admin adminID is deleted"),
			}
		},
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dba := &dbAdmin{
				ID:            adminID,
				AuthorityID:   admin.DefaultAuthorityID,
				ProvisionerID: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     now,
			}
			b, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return b, nil
					},
				},
				dba: dba,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if dba, err := d.getDBAdmin(context.Background(), adminID); err != nil {
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
				assert.Equals(t, dba.ID, adminID)
				assert.Equals(t, dba.AuthorityID, tc.dba.AuthorityID)
				assert.Equals(t, dba.ProvisionerID, tc.dba.ProvisionerID)
				assert.Equals(t, dba.Subject, tc.dba.Subject)
				assert.Equals(t, dba.Type, tc.dba.Type)
				assert.Equals(t, dba.CreatedAt, tc.dba.CreatedAt)
				assert.Fatal(t, dba.DeletedAt.IsZero())
			}
		})
	}
}

func TestDB_unmarshalDBAdmin(t *testing.T) {
	adminID := "adminID"
	type test struct {
		in       []byte
		err      error
		adminErr *admin.Error
		dba      *dbAdmin
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				in:  []byte("foo"),
				err: errors.New("error unmarshaling admin adminID into dbAdmin"),
			}
		},
		"fail/deleted-error": func(t *testing.T) test {
			dba := &dbAdmin{
				DeletedAt: time.Now(),
			}
			data, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				in:       data,
				adminErr: admin.NewError(admin.ErrorDeletedType, "admin adminID is deleted"),
			}
		},
		"fail/authority-mismatch-error": func(t *testing.T) test {
			dba := &dbAdmin{
				ID:          adminID,
				AuthorityID: "foo",
			}
			data, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				in: data,
				adminErr: admin.NewError(admin.ErrorAuthorityMismatchType,
					"admin %s is not owned by authority %s", adminID, admin.DefaultAuthorityID),
			}
		},
		"ok": func(t *testing.T) test {
			dba := &dbAdmin{
				ID:            adminID,
				Subject:       "max@smallstep.com",
				ProvisionerID: "provID",
				AuthorityID:   admin.DefaultAuthorityID,
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     clock.Now(),
			}
			data, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				in:  data,
				dba: dba,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{authorityID: admin.DefaultAuthorityID}
			if dba, err := d.unmarshalDBAdmin(tc.in, adminID); err != nil {
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
				assert.Equals(t, dba.ID, adminID)
				assert.Equals(t, dba.AuthorityID, tc.dba.AuthorityID)
				assert.Equals(t, dba.ProvisionerID, tc.dba.ProvisionerID)
				assert.Equals(t, dba.Subject, tc.dba.Subject)
				assert.Equals(t, dba.Type, tc.dba.Type)
				assert.Equals(t, dba.CreatedAt, tc.dba.CreatedAt)
				assert.Fatal(t, dba.DeletedAt.IsZero())
			}
		})
	}
}

func TestDB_unmarshalAdmin(t *testing.T) {
	adminID := "adminID"
	type test struct {
		in       []byte
		err      error
		adminErr *admin.Error
		dba      *dbAdmin
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				in:  []byte("foo"),
				err: errors.New("error unmarshaling admin adminID into dbAdmin"),
			}
		},
		"fail/deleted-error": func(t *testing.T) test {
			dba := &dbAdmin{
				DeletedAt: time.Now(),
			}
			data, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				in:       data,
				adminErr: admin.NewError(admin.ErrorDeletedType, "admin adminID is deleted"),
			}
		},
		"ok": func(t *testing.T) test {
			dba := &dbAdmin{
				ID:            adminID,
				Subject:       "max@smallstep.com",
				ProvisionerID: "provID",
				AuthorityID:   admin.DefaultAuthorityID,
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     clock.Now(),
			}
			data, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				in:  data,
				dba: dba,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{authorityID: admin.DefaultAuthorityID}
			if adm, err := d.unmarshalAdmin(tc.in, adminID); err != nil {
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
				assert.Equals(t, adm.Id, adminID)
				assert.Equals(t, adm.AuthorityId, tc.dba.AuthorityID)
				assert.Equals(t, adm.ProvisionerId, tc.dba.ProvisionerID)
				assert.Equals(t, adm.Subject, tc.dba.Subject)
				assert.Equals(t, adm.Type, tc.dba.Type)
				assert.Equals(t, adm.CreatedAt, timestamppb.New(tc.dba.CreatedAt))
				assert.Equals(t, adm.DeletedAt, timestamppb.New(tc.dba.DeletedAt))
			}
		})
	}
}

func TestDB_GetAdmin(t *testing.T) {
	adminID := "adminID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		dba      *dbAdmin
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "admin adminID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading admin adminID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling admin adminID into dbAdmin"),
			}
		},
		"fail/deleted": func(t *testing.T) test {
			dba := &dbAdmin{
				ID:            adminID,
				AuthorityID:   admin.DefaultAuthorityID,
				ProvisionerID: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     clock.Now(),
				DeletedAt:     clock.Now(),
			}
			b, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return b, nil
					},
				},
				dba:      dba,
				adminErr: admin.NewError(admin.ErrorDeletedType, "admin adminID is deleted"),
			}
		},
		"fail/authorityID-mismatch": func(t *testing.T) test {
			dba := &dbAdmin{
				ID:            adminID,
				AuthorityID:   "foo",
				ProvisionerID: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     clock.Now(),
			}
			b, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return b, nil
					},
				},
				dba: dba,
				adminErr: admin.NewError(admin.ErrorAuthorityMismatchType,
					"admin %s is not owned by authority %s", dba.ID, admin.DefaultAuthorityID),
			}
		},
		"ok": func(t *testing.T) test {
			dba := &dbAdmin{
				ID:            adminID,
				AuthorityID:   admin.DefaultAuthorityID,
				ProvisionerID: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     clock.Now(),
			}
			b, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return b, nil
					},
				},
				dba: dba,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if adm, err := d.GetAdmin(context.Background(), adminID); err != nil {
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
				assert.Equals(t, adm.Id, adminID)
				assert.Equals(t, adm.AuthorityId, tc.dba.AuthorityID)
				assert.Equals(t, adm.ProvisionerId, tc.dba.ProvisionerID)
				assert.Equals(t, adm.Subject, tc.dba.Subject)
				assert.Equals(t, adm.Type, tc.dba.Type)
				assert.Equals(t, adm.CreatedAt, timestamppb.New(tc.dba.CreatedAt))
				assert.Equals(t, adm.DeletedAt, timestamppb.New(tc.dba.DeletedAt))
			}
		})
	}
}

func TestDB_DeleteAdmin(t *testing.T) {
	adminID := "adminID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "admin adminID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading admin adminID: force"),
			}
		},
		"fail/save-error": func(t *testing.T) test {
			dba := &dbAdmin{
				ID:            adminID,
				AuthorityID:   admin.DefaultAuthorityID,
				ProvisionerID: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     clock.Now(),
			}
			data, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return data, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)
						assert.Equals(t, string(old), string(data))

						var _dba = new(dbAdmin)
						assert.FatalError(t, json.Unmarshal(nu, _dba))

						assert.Equals(t, _dba.ID, dba.ID)
						assert.Equals(t, _dba.AuthorityID, dba.AuthorityID)
						assert.Equals(t, _dba.ProvisionerID, dba.ProvisionerID)
						assert.Equals(t, _dba.Subject, dba.Subject)
						assert.Equals(t, _dba.Type, dba.Type)
						assert.Equals(t, _dba.CreatedAt, dba.CreatedAt)

						assert.True(t, _dba.DeletedAt.Before(time.Now()))
						assert.True(t, _dba.DeletedAt.After(time.Now().Add(-time.Minute)))

						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving authority admin: force"),
			}
		},
		"ok": func(t *testing.T) test {
			dba := &dbAdmin{
				ID:            adminID,
				AuthorityID:   admin.DefaultAuthorityID,
				ProvisionerID: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     clock.Now(),
			}
			data, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return data, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)
						assert.Equals(t, string(old), string(data))

						var _dba = new(dbAdmin)
						assert.FatalError(t, json.Unmarshal(nu, _dba))

						assert.Equals(t, _dba.ID, dba.ID)
						assert.Equals(t, _dba.AuthorityID, dba.AuthorityID)
						assert.Equals(t, _dba.ProvisionerID, dba.ProvisionerID)
						assert.Equals(t, _dba.Subject, dba.Subject)
						assert.Equals(t, _dba.Type, dba.Type)
						assert.Equals(t, _dba.CreatedAt, dba.CreatedAt)

						assert.True(t, _dba.DeletedAt.Before(time.Now()))
						assert.True(t, _dba.DeletedAt.After(time.Now().Add(-time.Minute)))

						return nu, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if err := d.DeleteAdmin(context.Background(), adminID); err != nil {
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

func TestDB_UpdateAdmin(t *testing.T) {
	adminID := "adminID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		adm      *linkedca.Admin
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				adm: &linkedca.Admin{Id: adminID},
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "admin adminID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				adm: &linkedca.Admin{Id: adminID},
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading admin adminID: force"),
			}
		},
		"fail/save-error": func(t *testing.T) test {
			dba := &dbAdmin{
				ID:            adminID,
				AuthorityID:   admin.DefaultAuthorityID,
				ProvisionerID: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     clock.Now(),
			}

			upd := dba.convert()
			upd.Type = linkedca.Admin_ADMIN

			data, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				adm: upd,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return data, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)
						assert.Equals(t, string(old), string(data))

						var _dba = new(dbAdmin)
						assert.FatalError(t, json.Unmarshal(nu, _dba))

						assert.Equals(t, _dba.ID, dba.ID)
						assert.Equals(t, _dba.AuthorityID, dba.AuthorityID)
						assert.Equals(t, _dba.ProvisionerID, dba.ProvisionerID)
						assert.Equals(t, _dba.Subject, dba.Subject)
						assert.Equals(t, _dba.Type, linkedca.Admin_ADMIN)
						assert.Equals(t, _dba.CreatedAt, dba.CreatedAt)

						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving authority admin: force"),
			}
		},
		"ok": func(t *testing.T) test {
			dba := &dbAdmin{
				ID:            adminID,
				AuthorityID:   admin.DefaultAuthorityID,
				ProvisionerID: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_SUPER_ADMIN,
				CreatedAt:     clock.Now(),
			}

			upd := dba.convert()
			upd.Type = linkedca.Admin_ADMIN

			data, err := json.Marshal(dba)
			assert.FatalError(t, err)
			return test{
				adm: upd,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)

						return data, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, string(key), adminID)
						assert.Equals(t, string(old), string(data))

						var _dba = new(dbAdmin)
						assert.FatalError(t, json.Unmarshal(nu, _dba))

						assert.Equals(t, _dba.ID, dba.ID)
						assert.Equals(t, _dba.AuthorityID, dba.AuthorityID)
						assert.Equals(t, _dba.ProvisionerID, dba.ProvisionerID)
						assert.Equals(t, _dba.Subject, dba.Subject)
						assert.Equals(t, _dba.Type, linkedca.Admin_ADMIN)
						assert.Equals(t, _dba.CreatedAt, dba.CreatedAt)

						return nu, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if err := d.UpdateAdmin(context.Background(), tc.adm); err != nil {
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

func TestDB_CreateAdmin(t *testing.T) {
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		adm      *linkedca.Admin
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/save-error": func(t *testing.T) test {
			adm := &linkedca.Admin{
				AuthorityId:   admin.DefaultAuthorityID,
				ProvisionerId: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_ADMIN,
			}

			return test{
				adm: adm,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, old, nil)

						var _dba = new(dbAdmin)
						assert.FatalError(t, json.Unmarshal(nu, _dba))

						assert.True(t, len(_dba.ID) > 0 && _dba.ID == string(key))
						assert.Equals(t, _dba.AuthorityID, adm.AuthorityId)
						assert.Equals(t, _dba.ProvisionerID, adm.ProvisionerId)
						assert.Equals(t, _dba.Subject, adm.Subject)
						assert.Equals(t, _dba.Type, linkedca.Admin_ADMIN)

						assert.True(t, _dba.CreatedAt.Before(time.Now()))
						assert.True(t, _dba.CreatedAt.After(time.Now().Add(-time.Minute)))

						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving authority admin: force"),
			}
		},
		"ok": func(t *testing.T) test {
			adm := &linkedca.Admin{
				AuthorityId:   admin.DefaultAuthorityID,
				ProvisionerId: "provID",
				Subject:       "max@smallstep.com",
				Type:          linkedca.Admin_ADMIN,
			}

			return test{
				adm: adm,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, adminsTable)
						assert.Equals(t, old, nil)

						var _dba = new(dbAdmin)
						assert.FatalError(t, json.Unmarshal(nu, _dba))

						assert.True(t, len(_dba.ID) > 0 && _dba.ID == string(key))
						assert.Equals(t, _dba.AuthorityID, adm.AuthorityId)
						assert.Equals(t, _dba.ProvisionerID, adm.ProvisionerId)
						assert.Equals(t, _dba.Subject, adm.Subject)
						assert.Equals(t, _dba.Type, linkedca.Admin_ADMIN)

						assert.True(t, _dba.CreatedAt.Before(time.Now()))
						assert.True(t, _dba.CreatedAt.After(time.Now().Add(-time.Minute)))

						return nu, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if err := d.CreateAdmin(context.Background(), tc.adm); err != nil {
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

func TestDB_GetAdmins(t *testing.T) {
	now := clock.Now()
	fooAdmin := &dbAdmin{
		ID:            "foo",
		AuthorityID:   admin.DefaultAuthorityID,
		ProvisionerID: "provID",
		Subject:       "foo@smallstep.com",
		Type:          linkedca.Admin_SUPER_ADMIN,
		CreatedAt:     now,
	}
	foob, err := json.Marshal(fooAdmin)
	assert.FatalError(t, err)

	barAdmin := &dbAdmin{
		ID:            "bar",
		AuthorityID:   admin.DefaultAuthorityID,
		ProvisionerID: "provID",
		Subject:       "bar@smallstep.com",
		Type:          linkedca.Admin_ADMIN,
		CreatedAt:     now,
		DeletedAt:     now,
	}
	barb, err := json.Marshal(barAdmin)
	assert.FatalError(t, err)

	bazAdmin := &dbAdmin{
		ID:            "baz",
		AuthorityID:   "bazzer",
		ProvisionerID: "provID",
		Subject:       "baz@smallstep.com",
		Type:          linkedca.Admin_ADMIN,
		CreatedAt:     now,
	}
	bazb, err := json.Marshal(bazAdmin)
	assert.FatalError(t, err)

	zapAdmin := &dbAdmin{
		ID:            "zap",
		AuthorityID:   admin.DefaultAuthorityID,
		ProvisionerID: "provID",
		Subject:       "zap@smallstep.com",
		Type:          linkedca.Admin_ADMIN,
		CreatedAt:     now,
	}
	zapb, err := json.Marshal(zapAdmin)
	assert.FatalError(t, err)
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		verify   func(*testing.T, []*linkedca.Admin)
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.List-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, bucket, adminsTable)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading admins: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			ret := []*nosqldb.Entry{
				{Bucket: adminsTable, Key: []byte("foo"), Value: foob},
				{Bucket: adminsTable, Key: []byte("bar"), Value: barb},
				{Bucket: adminsTable, Key: []byte("zap"), Value: []byte("zap")},
			}
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, bucket, adminsTable)

						return ret, nil
					},
				},
				err: errors.New("error unmarshaling admin zap into dbAdmin"),
			}
		},
		"ok/none": func(t *testing.T) test {
			ret := []*nosqldb.Entry{}
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, bucket, adminsTable)

						return ret, nil
					},
				},
				verify: func(t *testing.T, admins []*linkedca.Admin) {
					assert.Equals(t, len(admins), 0)
				},
			}
		},
		"ok/only-invalid": func(t *testing.T) test {
			ret := []*nosqldb.Entry{
				{Bucket: adminsTable, Key: []byte("bar"), Value: barb},
				{Bucket: adminsTable, Key: []byte("baz"), Value: bazb},
			}
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, bucket, adminsTable)

						return ret, nil
					},
				},
				verify: func(t *testing.T, admins []*linkedca.Admin) {
					assert.Equals(t, len(admins), 0)
				},
			}
		},
		"ok": func(t *testing.T) test {
			ret := []*nosqldb.Entry{
				{Bucket: adminsTable, Key: []byte("foo"), Value: foob},
				{Bucket: adminsTable, Key: []byte("bar"), Value: barb},
				{Bucket: adminsTable, Key: []byte("baz"), Value: bazb},
				{Bucket: adminsTable, Key: []byte("zap"), Value: zapb},
			}
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, bucket, adminsTable)

						return ret, nil
					},
				},
				verify: func(t *testing.T, admins []*linkedca.Admin) {
					assert.Equals(t, len(admins), 2)

					assert.Equals(t, admins[0].Id, fooAdmin.ID)
					assert.Equals(t, admins[0].AuthorityId, fooAdmin.AuthorityID)
					assert.Equals(t, admins[0].ProvisionerId, fooAdmin.ProvisionerID)
					assert.Equals(t, admins[0].Subject, fooAdmin.Subject)
					assert.Equals(t, admins[0].Type, fooAdmin.Type)
					assert.Equals(t, admins[0].CreatedAt, timestamppb.New(fooAdmin.CreatedAt))
					assert.Equals(t, admins[0].DeletedAt, timestamppb.New(fooAdmin.DeletedAt))

					assert.Equals(t, admins[1].Id, zapAdmin.ID)
					assert.Equals(t, admins[1].AuthorityId, zapAdmin.AuthorityID)
					assert.Equals(t, admins[1].ProvisionerId, zapAdmin.ProvisionerID)
					assert.Equals(t, admins[1].Subject, zapAdmin.Subject)
					assert.Equals(t, admins[1].Type, zapAdmin.Type)
					assert.Equals(t, admins[1].CreatedAt, timestamppb.New(zapAdmin.CreatedAt))
					assert.Equals(t, admins[1].DeletedAt, timestamppb.New(zapAdmin.DeletedAt))
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if admins, err := d.GetAdmins(context.Background()); err != nil {
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
				tc.verify(t, admins)
			}
		})
	}
}
