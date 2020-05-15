package acme

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

func newAz() (authz, error) {
	mockdb := &db.MockNoSQLDB{
		MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
			return []byte("foo"), true, nil
		},
	}
	return newAuthz(mockdb, "1234", Identifier{
		Type: "dns", Value: "acme.example.com",
	})
}

func TestGetAuthz(t *testing.T) {
	type test struct {
		id  string
		db  nosql.DB
		az  authz
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			return test{
				az: az,
				id: az.getID(),
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, database.ErrNotFound
					},
				},
				err: MalformedErr(errors.Errorf("authz %s not found: not found", az.getID())),
			}
		},
		"fail/db-error": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			return test{
				az: az,
				id: az.getID(),
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.Errorf("error loading authz %s: force", az.getID())),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			_az, ok := az.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az.baseAuthz.Identifier.Type = "foo"
			b, err := json.Marshal(az)
			assert.FatalError(t, err)
			return test{
				az: az,
				id: az.getID(),
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, key, []byte(az.getID()))
						return b, nil
					},
				},
				err: ServerInternalErr(errors.New("unexpected authz type foo")),
			}
		},
		"ok": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			b, err := json.Marshal(az)
			assert.FatalError(t, err)
			return test{
				az: az,
				id: az.getID(),
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, key, []byte(az.getID()))
						return b, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if az, err := getAuthz(tc.db, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.az.getID(), az.getID())
					assert.Equals(t, tc.az.getAccountID(), az.getAccountID())
					assert.Equals(t, tc.az.getStatus(), az.getStatus())
					assert.Equals(t, tc.az.getIdentifier(), az.getIdentifier())
					assert.Equals(t, tc.az.getCreated(), az.getCreated())
					assert.Equals(t, tc.az.getExpiry(), az.getExpiry())
					assert.Equals(t, tc.az.getChallenges(), az.getChallenges())
				}
			}
		})
	}
}

func TestAuthzClone(t *testing.T) {
	az, err := newAz()
	assert.FatalError(t, err)

	clone := az.clone()

	assert.Equals(t, clone.getID(), az.getID())
	assert.Equals(t, clone.getAccountID(), az.getAccountID())
	assert.Equals(t, clone.getStatus(), az.getStatus())
	assert.Equals(t, clone.getIdentifier(), az.getIdentifier())
	assert.Equals(t, clone.getExpiry(), az.getExpiry())
	assert.Equals(t, clone.getCreated(), az.getCreated())
	assert.Equals(t, clone.getChallenges(), az.getChallenges())

	clone.Status = StatusValid

	assert.NotEquals(t, clone.getStatus(), az.getStatus())
}

func TestNewAuthz(t *testing.T) {
	iden := Identifier{
		Type: "dns", Value: "acme.example.com",
	}
	accID := "1234"
	type test struct {
		iden   Identifier
		db     nosql.DB
		err    *Error
		resChs *([]string)
	}
	tests := map[string]func(t *testing.T) test{
		"fail/unexpected-type": func(t *testing.T) test {
			return test{
				iden: Identifier{Type: "foo", Value: "acme.example.com"},
				err:  MalformedErr(errors.New("unexpected authz type foo")),
			}
		},
		"fail/new-http-chall-error": func(t *testing.T) test {
			return test{
				iden: iden,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error creating http challenge: error saving acme challenge: force")),
			}
		},
		"fail/new-tls-alpn-chall-error": func(t *testing.T) test {
			count := 0
			return test{
				iden: iden,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count == 1 {
							return nil, false, errors.New("force")
						}
						count++
						return nil, true, nil
					},
				},
				err: ServerInternalErr(errors.New("error creating alpn challenge: error saving acme challenge: force")),
			}
		},
		"fail/new-dns-chall-error": func(t *testing.T) test {
			count := 0
			return test{
				iden: iden,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count == 2 {
							return nil, false, errors.New("force")
						}
						count++
						return nil, true, nil
					},
				},
				err: ServerInternalErr(errors.New("error creating dns challenge: error saving acme challenge: force")),
			}
		},
		"fail/save-authz-error": func(t *testing.T) test {
			count := 0
			return test{
				iden: iden,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count == 3 {
							return nil, false, errors.New("force")
						}
						count++
						return nil, true, nil
					},
				},
				err: ServerInternalErr(errors.New("error storing authz: force")),
			}
		},
		"ok": func(t *testing.T) test {
			chs := &([]string{})
			count := 0
			return test{
				iden: iden,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count == 3 {
							assert.Equals(t, bucket, authzTable)
							assert.Equals(t, old, nil)

							az, err := unmarshalAuthz(newval)
							assert.FatalError(t, err)

							assert.Equals(t, az.getID(), string(key))
							assert.Equals(t, az.getAccountID(), accID)
							assert.Equals(t, az.getStatus(), StatusPending)
							assert.Equals(t, az.getIdentifier(), iden)
							assert.Equals(t, az.getWildcard(), false)

							*chs = az.getChallenges()

							assert.True(t, az.getCreated().Before(time.Now().UTC().Add(time.Minute)))
							assert.True(t, az.getCreated().After(time.Now().UTC().Add(-1*time.Minute)))

							expiry := az.getCreated().Add(defaultExpiryDuration)
							assert.True(t, az.getExpiry().Before(expiry.Add(time.Minute)))
							assert.True(t, az.getExpiry().After(expiry.Add(-1*time.Minute)))
						}
						count++
						return nil, true, nil
					},
				},
				resChs: chs,
			}
		},
		"ok/wildcard": func(t *testing.T) test {
			chs := &([]string{})
			count := 0
			_iden := Identifier{Type: "dns", Value: "*.acme.example.com"}
			return test{
				iden: _iden,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count == 1 {
							assert.Equals(t, bucket, authzTable)
							assert.Equals(t, old, nil)

							az, err := unmarshalAuthz(newval)
							assert.FatalError(t, err)

							assert.Equals(t, az.getID(), string(key))
							assert.Equals(t, az.getAccountID(), accID)
							assert.Equals(t, az.getStatus(), StatusPending)
							assert.Equals(t, az.getIdentifier(), iden)
							assert.Equals(t, az.getWildcard(), true)

							*chs = az.getChallenges()
							// Verify that we only have 1 challenge instead of 2.
							assert.True(t, len(*chs) == 1)

							assert.True(t, az.getCreated().Before(time.Now().UTC().Add(time.Minute)))
							assert.True(t, az.getCreated().After(time.Now().UTC().Add(-1*time.Minute)))

							expiry := az.getCreated().Add(defaultExpiryDuration)
							assert.True(t, az.getExpiry().Before(expiry.Add(time.Minute)))
							assert.True(t, az.getExpiry().After(expiry.Add(-1*time.Minute)))
						}
						count++
						return nil, true, nil
					},
				},
				resChs: chs,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			az, err := newAuthz(tc.db, accID, tc.iden)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, az.getAccountID(), accID)
					assert.Equals(t, az.getType(), "dns")
					assert.Equals(t, az.getStatus(), StatusPending)

					assert.True(t, az.getCreated().Before(time.Now().UTC().Add(time.Minute)))
					assert.True(t, az.getCreated().After(time.Now().UTC().Add(-1*time.Minute)))

					expiry := az.getCreated().Add(defaultExpiryDuration)
					assert.True(t, az.getExpiry().Before(expiry.Add(time.Minute)))
					assert.True(t, az.getExpiry().After(expiry.Add(-1*time.Minute)))

					assert.Equals(t, az.getChallenges(), *(tc.resChs))

					if strings.HasPrefix(tc.iden.Value, "*.") {
						assert.True(t, az.getWildcard())
						assert.Equals(t, az.getIdentifier().Value, strings.TrimPrefix(tc.iden.Value, "*."))
					} else {
						assert.False(t, az.getWildcard())
						assert.Equals(t, az.getIdentifier().Value, tc.iden.Value)
					}

					assert.True(t, az.getID() != "")
				}
			}
		})
	}
}

func TestAuthzToACME(t *testing.T) {
	dir := newDirectory("ca.smallstep.com", "acme")

	var (
		ch1, ch2           challenge
		ch1Bytes, ch2Bytes = &([]byte{}), &([]byte{})
		err                error
	)

	count := 0
	mockdb := &db.MockNoSQLDB{
		MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
			if count == 0 {
				*ch1Bytes = newval
				ch1, err = unmarshalChallenge(newval)
				assert.FatalError(t, err)
			} else if count == 1 {
				*ch2Bytes = newval
				ch2, err = unmarshalChallenge(newval)
				assert.FatalError(t, err)
			}
			count++
			return []byte("foo"), true, nil
		},
	}
	iden := Identifier{
		Type: "dns", Value: "acme.example.com",
	}
	az, err := newAuthz(mockdb, "1234", iden)
	assert.FatalError(t, err)

	prov := newProv()
	ctx := context.WithValue(context.Background(), ProvisionerContextKey, prov)
	ctx = context.WithValue(ctx, BaseURLContextKey, "https://test.ca.smallstep.com:8080")

	type test struct {
		db  nosql.DB
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getChallenge1-error": func(t *testing.T) test {
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error loading challenge")),
			}
		},
		"fail/getChallenge2-error": func(t *testing.T) test {
			count := 0
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						if count == 1 {
							return nil, errors.New("force")
						}
						count++
						return *ch1Bytes, nil
					},
				},
				err: ServerInternalErr(errors.New("error loading challenge")),
			}
		},
		"ok": func(t *testing.T) test {
			count := 0
			return test{
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						if count == 0 {
							count++
							return *ch1Bytes, nil
						}
						return *ch2Bytes, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			acmeAz, err := az.toACME(ctx, tc.db, dir)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, acmeAz.ID, az.getID())
					assert.Equals(t, acmeAz.Identifier, iden)
					assert.Equals(t, acmeAz.Status, StatusPending)

					acmeCh1, err := ch1.toACME(ctx, nil, dir)
					assert.FatalError(t, err)
					acmeCh2, err := ch2.toACME(ctx, nil, dir)
					assert.FatalError(t, err)

					assert.Equals(t, acmeAz.Challenges[0], acmeCh1)
					assert.Equals(t, acmeAz.Challenges[1], acmeCh2)

					expiry, err := time.Parse(time.RFC3339, acmeAz.Expires)
					assert.FatalError(t, err)
					assert.Equals(t, expiry.String(), az.getExpiry().String())
				}
			}
		})
	}
}

func TestAuthzSave(t *testing.T) {
	type test struct {
		az, old authz
		db      nosql.DB
		err     *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/old-nil/swap-error": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			return test{
				az:  az,
				old: nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error storing authz: force")),
			}
		},
		"fail/old-nil/swap-false": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			return test{
				az:  az,
				old: nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return []byte("foo"), false, nil
					},
				},
				err: ServerInternalErr(errors.New("error storing authz; value has changed since last read")),
			}
		},
		"ok/old-nil": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			b, err := json.Marshal(az)
			assert.FatalError(t, err)
			return test{
				az:  az,
				old: nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, old, nil)
						assert.Equals(t, b, newval)
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, []byte(az.getID()), key)
						return nil, true, nil
					},
				},
			}
		},
		"ok/old-not-nil": func(t *testing.T) test {
			oldAz, err := newAz()
			assert.FatalError(t, err)
			az, err := newAz()
			assert.FatalError(t, err)

			oldb, err := json.Marshal(oldAz)
			assert.FatalError(t, err)
			b, err := json.Marshal(az)
			assert.FatalError(t, err)
			return test{
				az:  az,
				old: oldAz,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, old, oldb)
						assert.Equals(t, b, newval)
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, []byte(az.getID()), key)
						return []byte("foo"), true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := tc.az.save(tc.db, tc.old); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestAuthzUnmarshal(t *testing.T) {
	type test struct {
		az  authz
		azb []byte
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/nil": func(t *testing.T) test {
			return test{
				azb: nil,
				err: ServerInternalErr(errors.New("error unmarshaling authz type: unexpected end of JSON input")),
			}
		},
		"fail/unexpected-type": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			_az, ok := az.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az.baseAuthz.Identifier.Type = "foo"
			b, err := json.Marshal(az)
			assert.FatalError(t, err)
			return test{
				azb: b,
				err: ServerInternalErr(errors.New("unexpected authz type foo")),
			}
		},
		"ok/dns": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			b, err := json.Marshal(az)
			assert.FatalError(t, err)
			return test{
				az:  az,
				azb: b,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if az, err := unmarshalAuthz(tc.azb); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.az.getID(), az.getID())
					assert.Equals(t, tc.az.getAccountID(), az.getAccountID())
					assert.Equals(t, tc.az.getStatus(), az.getStatus())
					assert.Equals(t, tc.az.getCreated(), az.getCreated())
					assert.Equals(t, tc.az.getExpiry(), az.getExpiry())
					assert.Equals(t, tc.az.getWildcard(), az.getWildcard())
					assert.Equals(t, tc.az.getChallenges(), az.getChallenges())
				}
			}
		})
	}
}

func TestAuthzUpdateStatus(t *testing.T) {
	type test struct {
		az, res authz
		err     *Error
		db      nosql.DB
	}
	tests := map[string]func(t *testing.T) test{
		"fail/already-invalid": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			_az, ok := az.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az.baseAuthz.Status = StatusInvalid
			return test{
				az:  az,
				res: az,
			}
		},
		"fail/already-valid": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			_az, ok := az.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az.baseAuthz.Status = StatusValid
			return test{
				az:  az,
				res: az,
			}
		},
		"fail/unexpected-status": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			_az, ok := az.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az.baseAuthz.Status = StatusReady
			return test{
				az:  az,
				res: az,
				err: ServerInternalErr(errors.New("unrecognized authz status: ready")),
			}
		},
		"fail/save-error": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			_az, ok := az.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az.baseAuthz.Expires = time.Now().UTC().Add(-time.Minute)
			return test{
				az:  az,
				res: az,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error storing authz: force")),
			}
		},
		"ok/expired": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			_az, ok := az.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az.baseAuthz.Expires = time.Now().UTC().Add(-time.Minute)

			clone := az.clone()
			clone.Error = MalformedErr(errors.New("authz has expired"))
			clone.Status = StatusInvalid
			return test{
				az:  az,
				res: clone.parent(),
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, true, nil
					},
				},
			}
		},
		"fail/get-challenge-error": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)

			return test{
				az:  az,
				res: az,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error loading challenge")),
			}
		},
		"ok/valid": func(t *testing.T) test {
			var (
				ch3      challenge
				ch2Bytes = &([]byte{})
				ch1Bytes = &([]byte{})
				err      error
			)

			count := 0
			mockdb := &db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					if count == 0 {
						*ch1Bytes = newval
					} else if count == 1 {
						*ch2Bytes = newval
					} else if count == 2 {
						ch3, err = unmarshalChallenge(newval)
						assert.FatalError(t, err)
					}
					count++
					return nil, true, nil
				},
			}
			iden := Identifier{
				Type: "dns", Value: "acme.example.com",
			}
			az, err := newAuthz(mockdb, "1234", iden)
			assert.FatalError(t, err)
			_az, ok := az.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az.baseAuthz.Error = MalformedErr(nil)

			_ch, ok := ch3.(*dns01Challenge)
			assert.Fatal(t, ok)
			_ch.baseChallenge.Status = StatusValid
			chb, err := json.Marshal(ch3)

			clone := az.clone()
			clone.Status = StatusValid
			clone.Error = nil

			count = 0
			return test{
				az:  az,
				res: clone.parent(),
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						if count == 0 {
							count++
							return *ch1Bytes, nil
						}
						if count == 1 {
							count++
							return *ch2Bytes, nil
						}
						count++
						return chb, nil
					},
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, true, nil
					},
				},
			}
		},
		"ok/still-pending": func(t *testing.T) test {
			var ch1Bytes, ch2Bytes = &([]byte{}), &([]byte{})

			count := 0
			mockdb := &db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					if count == 0 {
						*ch1Bytes = newval
					} else if count == 1 {
						*ch2Bytes = newval
					}
					count++
					return nil, true, nil
				},
			}
			iden := Identifier{
				Type: "dns", Value: "acme.example.com",
			}
			az, err := newAuthz(mockdb, "1234", iden)
			assert.FatalError(t, err)

			count = 0
			return test{
				az:  az,
				res: az,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						if count == 0 {
							count++
							return *ch1Bytes, nil
						}
						count++
						return *ch2Bytes, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			az, err := tc.az.updateStatus(tc.db)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					expB, err := json.Marshal(tc.res)
					assert.FatalError(t, err)
					b, err := json.Marshal(az)
					assert.FatalError(t, err)
					assert.Equals(t, expB, b)
				}
			}
		})
	}
}
