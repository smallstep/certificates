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
)

func TestDB_getDBProvisionerBytes(t *testing.T) {
	provID := "provID"
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
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "provisioner provID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading provisioner provID: force"),
			}
		},
		"ok": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

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
			if b, err := d.getDBProvisionerBytes(context.Background(), provID); err != nil {
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

func TestDB_getDBProvisioner(t *testing.T) {
	provID := "provID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		dbp      *dbProvisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "provisioner provID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading provisioner provID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling provisioner provID into dbProvisioner"),
			}
		},
		"fail/deleted": func(t *testing.T) test {

			now := clock.Now()
			dbp := &dbProvisioner{
				ID:          provID,
				AuthorityID: admin.DefaultAuthorityID,
				Type:        linkedca.Provisioner_JWK,
				Name:        "provName",
				CreatedAt:   now,
				DeletedAt:   now,
			}
			b, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return b, nil
					},
				},
				adminErr: admin.NewError(admin.ErrorDeletedType, "provisioner provID is deleted"),
			}
		},
		"ok": func(t *testing.T) test {
			now := clock.Now()
			dbp := &dbProvisioner{
				ID:          provID,
				AuthorityID: admin.DefaultAuthorityID,
				Type:        linkedca.Provisioner_JWK,
				Name:        "provName",
				CreatedAt:   now,
			}
			b, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return b, nil
					},
				},
				dbp: dbp,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if dbp, err := d.getDBProvisioner(context.Background(), provID); err != nil {
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
				assert.Equals(t, dbp.ID, provID)
				assert.Equals(t, dbp.AuthorityID, tc.dbp.AuthorityID)
				assert.Equals(t, dbp.Type, tc.dbp.Type)
				assert.Equals(t, dbp.Name, tc.dbp.Name)
				assert.Equals(t, dbp.CreatedAt, tc.dbp.CreatedAt)
				assert.Fatal(t, dbp.DeletedAt.IsZero())
				assert.Equals(t, dbp.Webhooks, tc.dbp.Webhooks)
			}
		})
	}
}

func TestDB_unmarshalDBProvisioner(t *testing.T) {
	provID := "provID"
	type test struct {
		in       []byte
		err      error
		adminErr *admin.Error
		dbp      *dbProvisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				in:  []byte("foo"),
				err: errors.New("error unmarshaling provisioner provID into dbProvisioner"),
			}
		},
		"fail/deleted-error": func(t *testing.T) test {
			dbp := &dbProvisioner{
				DeletedAt: clock.Now(),
			}
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				in:       data,
				adminErr: admin.NewError(admin.ErrorDeletedType, "provisioner %s is deleted", provID),
			}
		},
		"fail/authority-mismatch-error": func(t *testing.T) test {
			dbp := &dbProvisioner{
				ID:          provID,
				AuthorityID: "foo",
			}
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				in: data,
				adminErr: admin.NewError(admin.ErrorAuthorityMismatchType,
					"provisioner %s is not owned by authority %s", provID, admin.DefaultAuthorityID),
			}
		},
		"ok": func(t *testing.T) test {
			dbp := &dbProvisioner{
				ID:          provID,
				AuthorityID: admin.DefaultAuthorityID,
				Type:        linkedca.Provisioner_JWK,
				Name:        "provName",
				CreatedAt:   clock.Now(),
			}
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				in:  data,
				dbp: dbp,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{authorityID: admin.DefaultAuthorityID}
			if dbp, err := d.unmarshalDBProvisioner(tc.in, provID); err != nil {
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
				assert.Equals(t, dbp.ID, provID)
				assert.Equals(t, dbp.AuthorityID, tc.dbp.AuthorityID)
				assert.Equals(t, dbp.Type, tc.dbp.Type)
				assert.Equals(t, dbp.Name, tc.dbp.Name)
				assert.Equals(t, dbp.Details, tc.dbp.Details)
				assert.Equals(t, dbp.Claims, tc.dbp.Claims)
				assert.Equals(t, dbp.X509Template, tc.dbp.X509Template)
				assert.Equals(t, dbp.SSHTemplate, tc.dbp.SSHTemplate)
				assert.Equals(t, dbp.CreatedAt, tc.dbp.CreatedAt)
				assert.Fatal(t, dbp.DeletedAt.IsZero())
				assert.Equals(t, dbp.Webhooks, tc.dbp.Webhooks)
			}
		})
	}
}

func defaultDBP(t *testing.T) *dbProvisioner {
	details := &linkedca.ProvisionerDetails_ACME{
		ACME: &linkedca.ACMEProvisioner{
			ForceCn: true,
		},
	}
	detailBytes, err := json.Marshal(details)
	assert.FatalError(t, err)

	return &dbProvisioner{
		ID:          "provID",
		AuthorityID: admin.DefaultAuthorityID,
		Type:        linkedca.Provisioner_ACME,
		Name:        "provName",
		Details:     detailBytes,
		Claims: &linkedca.Claims{
			DisableRenewal: true,
			X509: &linkedca.X509Claims{
				Enabled: true,
				Durations: &linkedca.Durations{
					Min:     "5m",
					Max:     "12h",
					Default: "6h",
				},
			},
			Ssh: &linkedca.SSHClaims{
				Enabled: true,
				UserDurations: &linkedca.Durations{
					Min:     "5m",
					Max:     "12h",
					Default: "6h",
				},
				HostDurations: &linkedca.Durations{
					Min:     "5m",
					Max:     "12h",
					Default: "6h",
				},
			},
		},
		X509Template: &linkedca.Template{
			Template: []byte("foo"),
			Data:     []byte("bar"),
		},
		SSHTemplate: &linkedca.Template{
			Template: []byte("baz"),
			Data:     []byte("zap"),
		},
		CreatedAt: clock.Now(),
		Webhooks: []dbWebhook{
			{
				Name:        "metadata",
				URL:         "https://inventory.smallstep.com",
				Kind:        linkedca.Webhook_ENRICHING.String(),
				Secret:      "secret",
				BearerToken: "token",
			},
		},
	}
}

func TestDB_unmarshalProvisioner(t *testing.T) {
	provID := "provID"
	type test struct {
		in       []byte
		err      error
		adminErr *admin.Error
		dbp      *dbProvisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				in:  []byte("foo"),
				err: errors.New("error unmarshaling provisioner provID into dbProvisioner"),
			}
		},
		"fail/deleted-error": func(t *testing.T) test {
			dbp := &dbProvisioner{
				DeletedAt: time.Now(),
			}
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				in:       data,
				adminErr: admin.NewError(admin.ErrorDeletedType, "provisioner provID is deleted"),
			}
		},
		"ok": func(t *testing.T) test {
			dbp := defaultDBP(t)
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				in:  data,
				dbp: dbp,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{authorityID: admin.DefaultAuthorityID}
			if prov, err := d.unmarshalProvisioner(tc.in, provID); err != nil {
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
				assert.Equals(t, prov.Id, provID)
				assert.Equals(t, prov.AuthorityId, tc.dbp.AuthorityID)
				assert.Equals(t, prov.Type, tc.dbp.Type)
				assert.Equals(t, prov.Name, tc.dbp.Name)
				assert.Equals(t, prov.Claims, tc.dbp.Claims)
				assert.Equals(t, prov.X509Template, tc.dbp.X509Template)
				assert.Equals(t, prov.SshTemplate, tc.dbp.SSHTemplate)
				assert.Equals(t, prov.Webhooks, dbWebhooksToLinkedca(tc.dbp.Webhooks))

				retDetailsBytes, err := json.Marshal(prov.Details.GetData())
				assert.FatalError(t, err)
				assert.Equals(t, retDetailsBytes, tc.dbp.Details)
			}
		})
	}
}

func TestDB_GetProvisioner(t *testing.T) {
	provID := "provID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		dbp      *dbProvisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "provisioner provID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading provisioner provID: force"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return []byte("foo"), nil
					},
				},
				err: errors.New("error unmarshaling provisioner provID into dbProvisioner"),
			}
		},
		"fail/deleted": func(t *testing.T) test {
			dbp := defaultDBP(t)
			dbp.DeletedAt = clock.Now()
			b, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return b, nil
					},
				},
				dbp:      dbp,
				adminErr: admin.NewError(admin.ErrorDeletedType, "provisioner provID is deleted"),
			}
		},
		"fail/authorityID-mismatch": func(t *testing.T) test {
			dbp := defaultDBP(t)
			dbp.AuthorityID = "foo"
			b, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return b, nil
					},
				},
				dbp: dbp,
				adminErr: admin.NewError(admin.ErrorAuthorityMismatchType,
					"provisioner %s is not owned by authority %s", dbp.ID, admin.DefaultAuthorityID),
			}
		},
		"ok": func(t *testing.T) test {
			dbp := defaultDBP(t)
			b, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return b, nil
					},
				},
				dbp: dbp,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if prov, err := d.GetProvisioner(context.Background(), provID); err != nil {
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
				assert.Equals(t, prov.Id, provID)
				assert.Equals(t, prov.AuthorityId, tc.dbp.AuthorityID)
				assert.Equals(t, prov.Type, tc.dbp.Type)
				assert.Equals(t, prov.Name, tc.dbp.Name)
				assert.Equals(t, prov.Claims, tc.dbp.Claims)
				assert.Equals(t, prov.X509Template, tc.dbp.X509Template)
				assert.Equals(t, prov.SshTemplate, tc.dbp.SSHTemplate)
				assert.Equals(t, prov.Webhooks, dbWebhooksToLinkedca(tc.dbp.Webhooks))

				retDetailsBytes, err := json.Marshal(prov.Details.GetData())
				assert.FatalError(t, err)
				assert.Equals(t, retDetailsBytes, tc.dbp.Details)
			}
		})
	}
}

func TestDB_DeleteProvisioner(t *testing.T) {
	provID := "provID"
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
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "provisioner provID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading provisioner provID: force"),
			}
		},
		"fail/save-error": func(t *testing.T) test {
			dbp := defaultDBP(t)
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return data, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)
						assert.Equals(t, string(old), string(data))

						var _dbp = new(dbProvisioner)
						assert.FatalError(t, json.Unmarshal(nu, _dbp))

						assert.Equals(t, _dbp.ID, provID)
						assert.Equals(t, _dbp.AuthorityID, dbp.AuthorityID)
						assert.Equals(t, _dbp.Type, dbp.Type)
						assert.Equals(t, _dbp.Name, dbp.Name)
						assert.Equals(t, _dbp.Claims, dbp.Claims)
						assert.Equals(t, _dbp.X509Template, dbp.X509Template)
						assert.Equals(t, _dbp.SSHTemplate, dbp.SSHTemplate)
						assert.Equals(t, _dbp.CreatedAt, dbp.CreatedAt)
						assert.Equals(t, _dbp.Details, dbp.Details)
						assert.Equals(t, _dbp.Webhooks, dbp.Webhooks)

						assert.True(t, _dbp.DeletedAt.Before(time.Now()))
						assert.True(t, _dbp.DeletedAt.After(time.Now().Add(-time.Minute)))

						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving authority provisioner: force"),
			}
		},
		"ok": func(t *testing.T) test {
			dbp := defaultDBP(t)
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return data, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)
						assert.Equals(t, string(old), string(data))

						var _dbp = new(dbProvisioner)
						assert.FatalError(t, json.Unmarshal(nu, _dbp))

						assert.Equals(t, _dbp.ID, provID)
						assert.Equals(t, _dbp.AuthorityID, dbp.AuthorityID)
						assert.Equals(t, _dbp.Type, dbp.Type)
						assert.Equals(t, _dbp.Name, dbp.Name)
						assert.Equals(t, _dbp.Claims, dbp.Claims)
						assert.Equals(t, _dbp.X509Template, dbp.X509Template)
						assert.Equals(t, _dbp.SSHTemplate, dbp.SSHTemplate)
						assert.Equals(t, _dbp.CreatedAt, dbp.CreatedAt)
						assert.Equals(t, _dbp.Details, dbp.Details)
						assert.Equals(t, _dbp.Webhooks, dbp.Webhooks)

						assert.True(t, _dbp.DeletedAt.Before(time.Now()))
						assert.True(t, _dbp.DeletedAt.After(time.Now().Add(-time.Minute)))

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
			if err := d.DeleteProvisioner(context.Background(), provID); err != nil {
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

func TestDB_GetProvisioners(t *testing.T) {
	fooProv := defaultDBP(t)
	fooProv.Name = "foo"
	foob, err := json.Marshal(fooProv)
	assert.FatalError(t, err)

	barProv := defaultDBP(t)
	barProv.Name = "bar"
	barProv.DeletedAt = clock.Now()
	barb, err := json.Marshal(barProv)
	assert.FatalError(t, err)

	bazProv := defaultDBP(t)
	bazProv.Name = "baz"
	bazProv.AuthorityID = "baz"
	bazb, err := json.Marshal(bazProv)
	assert.FatalError(t, err)

	zapProv := defaultDBP(t)
	zapProv.Name = "zap"
	zapb, err := json.Marshal(zapProv)
	assert.FatalError(t, err)

	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		verify   func(*testing.T, []*linkedca.Provisioner)
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/db.List-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, bucket, provisionersTable)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading provisioners"),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			ret := []*nosqldb.Entry{
				{Bucket: provisionersTable, Key: []byte("foo"), Value: foob},
				{Bucket: provisionersTable, Key: []byte("bar"), Value: barb},
				{Bucket: provisionersTable, Key: []byte("zap"), Value: []byte("zap")},
			}
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, bucket, provisionersTable)

						return ret, nil
					},
				},
				err: errors.New("error unmarshaling provisioner zap into dbProvisioner"),
			}
		},
		"ok/none": func(t *testing.T) test {
			ret := []*nosqldb.Entry{}
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, bucket, provisionersTable)

						return ret, nil
					},
				},
				verify: func(t *testing.T, provs []*linkedca.Provisioner) {
					assert.Equals(t, len(provs), 0)
				},
			}
		},
		"ok/only-invalid": func(t *testing.T) test {
			ret := []*nosqldb.Entry{
				{Bucket: provisionersTable, Key: []byte("bar"), Value: barb},
				{Bucket: provisionersTable, Key: []byte("baz"), Value: bazb},
			}
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, bucket, provisionersTable)

						return ret, nil
					},
				},
				verify: func(t *testing.T, provs []*linkedca.Provisioner) {
					assert.Equals(t, len(provs), 0)
				},
			}
		},
		"ok": func(t *testing.T) test {
			ret := []*nosqldb.Entry{
				{Bucket: provisionersTable, Key: []byte("foo"), Value: foob},
				{Bucket: provisionersTable, Key: []byte("bar"), Value: barb},
				{Bucket: provisionersTable, Key: []byte("baz"), Value: bazb},
				{Bucket: provisionersTable, Key: []byte("zap"), Value: zapb},
			}
			return test{
				db: &db.MockNoSQLDB{
					MList: func(bucket []byte) ([]*nosqldb.Entry, error) {
						assert.Equals(t, bucket, provisionersTable)

						return ret, nil
					},
				},
				verify: func(t *testing.T, provs []*linkedca.Provisioner) {
					assert.Equals(t, len(provs), 2)

					assert.Equals(t, provs[0].Id, fooProv.ID)
					assert.Equals(t, provs[0].AuthorityId, fooProv.AuthorityID)
					assert.Equals(t, provs[0].Type, fooProv.Type)
					assert.Equals(t, provs[0].Name, fooProv.Name)
					assert.Equals(t, provs[0].Claims, fooProv.Claims)
					assert.Equals(t, provs[0].X509Template, fooProv.X509Template)
					assert.Equals(t, provs[0].SshTemplate, fooProv.SSHTemplate)
					assert.Equals(t, provs[0].Webhooks, dbWebhooksToLinkedca(fooProv.Webhooks))

					retDetailsBytes, err := json.Marshal(provs[0].Details.GetData())
					assert.FatalError(t, err)
					assert.Equals(t, retDetailsBytes, fooProv.Details)

					assert.Equals(t, provs[1].Id, zapProv.ID)
					assert.Equals(t, provs[1].AuthorityId, zapProv.AuthorityID)
					assert.Equals(t, provs[1].Type, zapProv.Type)
					assert.Equals(t, provs[1].Name, zapProv.Name)
					assert.Equals(t, provs[1].Claims, zapProv.Claims)
					assert.Equals(t, provs[1].X509Template, zapProv.X509Template)
					assert.Equals(t, provs[1].SshTemplate, zapProv.SSHTemplate)
					assert.Equals(t, provs[1].Webhooks, dbWebhooksToLinkedca(zapProv.Webhooks))

					retDetailsBytes, err = json.Marshal(provs[1].Details.GetData())
					assert.FatalError(t, err)
					assert.Equals(t, retDetailsBytes, zapProv.Details)
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			d := DB{db: tc.db, authorityID: admin.DefaultAuthorityID}
			if provs, err := d.GetProvisioners(context.Background()); err != nil {
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
				tc.verify(t, provs)
			}
		})
	}
}

func TestDB_CreateProvisioner(t *testing.T) {
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		prov     *linkedca.Provisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/save-error": func(t *testing.T) test {
			dbp := defaultDBP(t)
			prov, err := dbp.convert2linkedca()
			assert.FatalError(t, err)

			return test{
				prov: prov,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, old, nil)

						var _dbp = new(dbProvisioner)
						assert.FatalError(t, json.Unmarshal(nu, _dbp))

						assert.True(t, len(_dbp.ID) > 0 && _dbp.ID == string(key))
						assert.Equals(t, _dbp.AuthorityID, prov.AuthorityId)
						assert.Equals(t, _dbp.Type, prov.Type)
						assert.Equals(t, _dbp.Name, prov.Name)
						assert.Equals(t, _dbp.Claims, prov.Claims)
						assert.Equals(t, _dbp.X509Template, prov.X509Template)
						assert.Equals(t, _dbp.SSHTemplate, prov.SshTemplate)
						assert.Equals(t, _dbp.Webhooks, linkedcaWebhooksToDB(prov.Webhooks))

						retDetailsBytes, err := json.Marshal(prov.Details.GetData())
						assert.FatalError(t, err)
						assert.Equals(t, retDetailsBytes, _dbp.Details)

						assert.True(t, _dbp.DeletedAt.IsZero())
						assert.True(t, _dbp.CreatedAt.Before(time.Now()))
						assert.True(t, _dbp.CreatedAt.After(time.Now().Add(-time.Minute)))

						return nil, false, errors.New("force")
					},
				},
				adminErr: admin.NewErrorISE("error creating provisioner provName: error saving authority provisioner: force"),
			}
		},
		"ok": func(t *testing.T) test {
			dbp := defaultDBP(t)
			prov, err := dbp.convert2linkedca()
			assert.FatalError(t, err)

			return test{
				prov: prov,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, old, nil)

						var _dbp = new(dbProvisioner)
						assert.FatalError(t, json.Unmarshal(nu, _dbp))

						assert.True(t, len(_dbp.ID) > 0 && _dbp.ID == string(key))
						assert.Equals(t, _dbp.AuthorityID, prov.AuthorityId)
						assert.Equals(t, _dbp.Type, prov.Type)
						assert.Equals(t, _dbp.Name, prov.Name)
						assert.Equals(t, _dbp.Claims, prov.Claims)
						assert.Equals(t, _dbp.X509Template, prov.X509Template)
						assert.Equals(t, _dbp.SSHTemplate, prov.SshTemplate)
						assert.Equals(t, _dbp.Webhooks, linkedcaWebhooksToDB(prov.Webhooks))

						retDetailsBytes, err := json.Marshal(prov.Details.GetData())
						assert.FatalError(t, err)
						assert.Equals(t, retDetailsBytes, _dbp.Details)

						assert.True(t, _dbp.DeletedAt.IsZero())
						assert.True(t, _dbp.CreatedAt.Before(time.Now()))
						assert.True(t, _dbp.CreatedAt.After(time.Now().Add(-time.Minute)))

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
			if err := d.CreateProvisioner(context.Background(), tc.prov); err != nil {
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

func TestDB_UpdateProvisioner(t *testing.T) {
	provID := "provID"
	type test struct {
		db       nosql.DB
		err      error
		adminErr *admin.Error
		prov     *linkedca.Provisioner
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			return test{
				prov: &linkedca.Provisioner{Id: provID},
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, nosqldb.ErrNotFound
					},
				},
				adminErr: admin.NewError(admin.ErrorNotFoundType, "provisioner provID not found"),
			}
		},
		"fail/db.Get-error": func(t *testing.T) test {
			return test{
				prov: &linkedca.Provisioner{Id: provID},
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return nil, errors.New("force")
					},
				},
				err: errors.New("error loading provisioner provID: force"),
			}
		},
		"fail/update-deleted": func(t *testing.T) test {
			dbp := defaultDBP(t)
			dbp.DeletedAt = clock.Now()
			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				prov: &linkedca.Provisioner{Id: provID},
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return data, nil
					},
				},
				adminErr: admin.NewError(admin.ErrorDeletedType, "provisioner %s is deleted", provID),
			}
		},
		"fail/update-type-error": func(t *testing.T) test {
			dbp := defaultDBP(t)

			upd, err := dbp.convert2linkedca()
			assert.FatalError(t, err)
			upd.Type = linkedca.Provisioner_JWK

			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				prov: upd,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return data, nil
					},
				},
				adminErr: admin.NewError(admin.ErrorBadRequestType, "cannot update provisioner type"),
			}
		},
		"fail/save-error": func(t *testing.T) test {
			dbp := defaultDBP(t)

			prov, err := dbp.convert2linkedca()
			assert.FatalError(t, err)

			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				prov: prov,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return data, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)
						assert.Equals(t, string(old), string(data))

						var _dbp = new(dbProvisioner)
						assert.FatalError(t, json.Unmarshal(nu, _dbp))

						assert.True(t, len(_dbp.ID) > 0 && _dbp.ID == string(key))
						assert.Equals(t, _dbp.AuthorityID, prov.AuthorityId)
						assert.Equals(t, _dbp.Type, prov.Type)
						assert.Equals(t, _dbp.Name, prov.Name)
						assert.Equals(t, _dbp.Claims, prov.Claims)
						assert.Equals(t, _dbp.X509Template, prov.X509Template)
						assert.Equals(t, _dbp.SSHTemplate, prov.SshTemplate)
						assert.Equals(t, _dbp.Webhooks, linkedcaWebhooksToDB(prov.Webhooks))

						retDetailsBytes, err := json.Marshal(prov.Details.GetData())
						assert.FatalError(t, err)
						assert.Equals(t, retDetailsBytes, _dbp.Details)

						assert.True(t, _dbp.DeletedAt.IsZero())
						assert.True(t, _dbp.CreatedAt.Before(time.Now()))
						assert.True(t, _dbp.CreatedAt.After(time.Now().Add(-time.Minute)))

						return nil, false, errors.New("force")
					},
				},
				err: errors.New("error saving authority provisioner: force"),
			}
		},
		"ok": func(t *testing.T) test {
			dbp := defaultDBP(t)

			prov, err := dbp.convert2linkedca()
			assert.FatalError(t, err)

			prov.Name = "new-name"
			prov.Claims = &linkedca.Claims{
				DisableRenewal: true,
				X509: &linkedca.X509Claims{
					Enabled: true,
					Durations: &linkedca.Durations{
						Min:     "10m",
						Max:     "8h",
						Default: "4h",
					},
				},
				Ssh: &linkedca.SSHClaims{
					Enabled: true,
					UserDurations: &linkedca.Durations{
						Min:     "7m",
						Max:     "11h",
						Default: "5h",
					},
					HostDurations: &linkedca.Durations{
						Min:     "4m",
						Max:     "24h",
						Default: "24h",
					},
				},
			}
			prov.X509Template = &linkedca.Template{
				Template: []byte("x"),
				Data:     []byte("y"),
			}
			prov.SshTemplate = &linkedca.Template{
				Template: []byte("z"),
				Data:     []byte("w"),
			}
			prov.Details = &linkedca.ProvisionerDetails{
				Data: &linkedca.ProvisionerDetails_ACME{
					ACME: &linkedca.ACMEProvisioner{
						ForceCn: false,
					},
				},
			}
			prov.Webhooks = []*linkedca.Webhook{
				{
					Name: "users",
					Url:  "https://example.com/users",
				},
			}

			data, err := json.Marshal(dbp)
			assert.FatalError(t, err)
			return test{
				prov: prov,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)

						return data, nil
					},
					MCmpAndSwap: func(bucket, key, old, nu []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, provisionersTable)
						assert.Equals(t, string(key), provID)
						assert.Equals(t, string(old), string(data))

						var _dbp = new(dbProvisioner)
						assert.FatalError(t, json.Unmarshal(nu, _dbp))

						assert.True(t, len(_dbp.ID) > 0 && _dbp.ID == string(key))
						assert.Equals(t, _dbp.AuthorityID, prov.AuthorityId)
						assert.Equals(t, _dbp.Type, prov.Type)
						assert.Equals(t, _dbp.Name, prov.Name)
						assert.Equals(t, _dbp.Claims, prov.Claims)
						assert.Equals(t, _dbp.X509Template, prov.X509Template)
						assert.Equals(t, _dbp.SSHTemplate, prov.SshTemplate)
						assert.Equals(t, _dbp.Webhooks, linkedcaWebhooksToDB(prov.Webhooks))

						retDetailsBytes, err := json.Marshal(prov.Details.GetData())
						assert.FatalError(t, err)
						assert.Equals(t, retDetailsBytes, _dbp.Details)

						assert.True(t, _dbp.DeletedAt.IsZero())
						assert.True(t, _dbp.CreatedAt.Before(time.Now()))
						assert.True(t, _dbp.CreatedAt.After(time.Now().Add(-time.Minute)))

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
			if err := d.UpdateProvisioner(context.Background(), tc.prov); err != nil {
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

func Test_linkedcaWebhooksToDB(t *testing.T) {
	type test struct {
		in   []*linkedca.Webhook
		want []dbWebhook
	}
	var tests = map[string]test{
		"nil": {
			in:   nil,
			want: nil,
		},
		"zero": {
			in:   []*linkedca.Webhook{},
			want: nil,
		},
		"bearer": {
			in: []*linkedca.Webhook{
				{
					Name:   "bearer",
					Url:    "https://example.com",
					Kind:   linkedca.Webhook_ENRICHING,
					Secret: "secret",
					Auth: &linkedca.Webhook_BearerToken{
						BearerToken: &linkedca.BearerToken{
							BearerToken: "token",
						},
					},
					DisableTlsClientAuth: true,
					CertType:             linkedca.Webhook_X509,
				},
			},
			want: []dbWebhook{
				{
					Name:                 "bearer",
					URL:                  "https://example.com",
					Kind:                 "ENRICHING",
					Secret:               "secret",
					BearerToken:          "token",
					DisableTLSClientAuth: true,
					CertType:             linkedca.Webhook_X509.String(),
				},
			},
		},
		"basic": {
			in: []*linkedca.Webhook{
				{
					Name:   "basic",
					Url:    "https://example.com",
					Kind:   linkedca.Webhook_ENRICHING,
					Secret: "secret",
					Auth: &linkedca.Webhook_BasicAuth{
						BasicAuth: &linkedca.BasicAuth{
							Username: "user",
							Password: "pass",
						},
					},
				},
			},
			want: []dbWebhook{
				{
					Name:   "basic",
					URL:    "https://example.com",
					Kind:   "ENRICHING",
					Secret: "secret",
					BasicAuth: &dbBasicAuth{
						Username: "user",
						Password: "pass",
					},
					CertType: linkedca.Webhook_ALL.String(),
				},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := linkedcaWebhooksToDB(tc.in)
			assert.Equals(t, tc.want, got)
		})
	}
}

func Test_dbWebhooksToLinkedca(t *testing.T) {
	type test struct {
		in   []dbWebhook
		want []*linkedca.Webhook
	}
	var tests = map[string]test{
		"nil": {
			in:   nil,
			want: nil,
		},
		"zero": {
			in:   []dbWebhook{},
			want: nil,
		},
		"bearer": {
			in: []dbWebhook{
				{
					Name:                 "bearer",
					ID:                   "69350cb6-6c31-4b5e-bf25-affd5053427d",
					URL:                  "https://example.com",
					Kind:                 "ENRICHING",
					Secret:               "secret",
					BearerToken:          "token",
					DisableTLSClientAuth: true,
				},
			},
			want: []*linkedca.Webhook{
				{
					Name:   "bearer",
					Id:     "69350cb6-6c31-4b5e-bf25-affd5053427d",
					Url:    "https://example.com",
					Kind:   linkedca.Webhook_ENRICHING,
					Secret: "secret",
					Auth: &linkedca.Webhook_BearerToken{
						BearerToken: &linkedca.BearerToken{
							BearerToken: "token",
						},
					},
					DisableTlsClientAuth: true,
				},
			},
		},
		"basic": {
			in: []dbWebhook{
				{
					Name:   "basic",
					ID:     "69350cb6-6c31-4b5e-bf25-affd5053427d",
					URL:    "https://example.com",
					Kind:   "ENRICHING",
					Secret: "secret",
					BasicAuth: &dbBasicAuth{
						Username: "user",
						Password: "pass",
					},
				},
			},
			want: []*linkedca.Webhook{
				{
					Name:   "basic",
					Id:     "69350cb6-6c31-4b5e-bf25-affd5053427d",
					Url:    "https://example.com",
					Kind:   linkedca.Webhook_ENRICHING,
					Secret: "secret",
					Auth: &linkedca.Webhook_BasicAuth{
						BasicAuth: &linkedca.BasicAuth{
							Username: "user",
							Password: "pass",
						},
					},
				},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := dbWebhooksToLinkedca(tc.in)
			assert.Equals(t, tc.want, got)
		})
	}
}
