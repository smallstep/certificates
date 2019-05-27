package acme

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

var testOps = ChallengeOptions{
	AccountID: "accID",
	AuthzID:   "authzID",
	Identifier: Identifier{
		Type:  "", // will get set correctly depending on the "new.." method.
		Value: "zap.internal",
	},
}

func newDNSCh() (challenge, error) {
	mockdb := &db.MockNoSQLDB{
		MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
			return []byte("foo"), true, nil
		},
	}
	return newDNS01Challenge(mockdb, testOps)
}

func newHTTPCh() (challenge, error) {
	mockdb := &db.MockNoSQLDB{
		MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
			return []byte("foo"), true, nil
		},
	}
	return newHTTP01Challenge(mockdb, testOps)
}

func TestNewHTTP01Challenge(t *testing.T) {
	ops := ChallengeOptions{
		AccountID: "accID",
		AuthzID:   "authzID",
		Identifier: Identifier{
			Type:  "http",
			Value: "zap.internal",
		},
	}
	type test struct {
		ops ChallengeOptions
		db  nosql.DB
		err *Error
	}
	tests := map[string]test{
		"fail/store-error": {
			ops: ops,
			db: &db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			},
			err: ServerInternalErr(errors.New("error saving acme challenge: force")),
		},
		"ok": {
			ops: ops,
			db: &db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return []byte("foo"), true, nil
				},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ch, err := newHTTP01Challenge(tc.db, tc.ops)
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
					assert.Equals(t, ch.getAccountID(), ops.AccountID)
					assert.Equals(t, ch.getAuthzID(), ops.AuthzID)
					assert.Equals(t, ch.getType(), "http-01")
					assert.Equals(t, ch.getValue(), "zap.internal")
					assert.Equals(t, ch.getStatus(), StatusPending)

					assert.True(t, ch.getValidated().IsZero())
					assert.True(t, ch.getCreated().Before(time.Now().UTC().Add(time.Minute)))
					assert.True(t, ch.getCreated().After(time.Now().UTC().Add(-1*time.Minute)))

					assert.True(t, ch.getID() != "")
					assert.True(t, ch.getToken() != "")
				}
			}
		})
	}
}

func TestNewDNS01Challenge(t *testing.T) {
	ops := ChallengeOptions{
		AccountID: "accID",
		AuthzID:   "authzID",
		Identifier: Identifier{
			Type:  "dns",
			Value: "zap.internal",
		},
	}
	type test struct {
		ops ChallengeOptions
		db  nosql.DB
		err *Error
	}
	tests := map[string]test{
		"fail/store-error": {
			ops: ops,
			db: &db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			},
			err: ServerInternalErr(errors.New("error saving acme challenge: force")),
		},
		"ok": {
			ops: ops,
			db: &db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return []byte("foo"), true, nil
				},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ch, err := newDNS01Challenge(tc.db, tc.ops)
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
					assert.Equals(t, ch.getAccountID(), ops.AccountID)
					assert.Equals(t, ch.getAuthzID(), ops.AuthzID)
					assert.Equals(t, ch.getType(), "dns-01")
					assert.Equals(t, ch.getValue(), "zap.internal")
					assert.Equals(t, ch.getStatus(), StatusPending)

					assert.True(t, ch.getValidated().IsZero())
					assert.True(t, ch.getCreated().Before(time.Now().UTC().Add(time.Minute)))
					assert.True(t, ch.getCreated().After(time.Now().UTC().Add(-1*time.Minute)))

					assert.True(t, ch.getID() != "")
					assert.True(t, ch.getToken() != "")
				}
			}
		})
	}
}

func TestChallengeToACME(t *testing.T) {
	dir := newDirectory("ca.smallstep.com", "acme")

	httpCh, err := newHTTPCh()
	assert.FatalError(t, err)
	_httpCh, ok := httpCh.(*http01Challenge)
	assert.Fatal(t, ok)
	_httpCh.baseChallenge.Validated = clock.Now()

	dnsCh, err := newDNSCh()
	assert.FatalError(t, err)
	prov := newProv()
	tests := map[string]challenge{
		"dns":  dnsCh,
		"http": httpCh,
	}
	for name, ch := range tests {
		t.Run(name, func(t *testing.T) {
			ach, err := ch.toACME(nil, dir, prov)
			assert.FatalError(t, err)

			assert.Equals(t, ach.Type, ch.getType())
			assert.Equals(t, ach.Status, ch.getStatus())
			assert.Equals(t, ach.Token, ch.getToken())
			assert.Equals(t, ach.URL,
				fmt.Sprintf("https://ca.smallstep.com/acme/%s/challenge/%s",
					URLSafeProvisionerName(prov), ch.getID()))
			assert.Equals(t, ach.ID, ch.getID())
			assert.Equals(t, ach.AuthzID, ch.getAuthzID())

			if ach.Type == "http-01" {
				v, err := time.Parse(time.RFC3339, ach.Validated)
				assert.FatalError(t, err)
				assert.Equals(t, v.String(), _httpCh.baseChallenge.Validated.String())
			} else {
				assert.Equals(t, ach.Validated, "")
			}
		})
	}
}

func TestChallengeSave(t *testing.T) {
	type test struct {
		ch  challenge
		old challenge
		db  nosql.DB
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/old-nil/swap-error": func(t *testing.T) test {
			httpCh, err := newHTTPCh()
			assert.FatalError(t, err)
			return test{
				ch:  httpCh,
				old: nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error saving acme challenge: force")),
			}
		},
		"fail/old-nil/swap-false": func(t *testing.T) test {
			httpCh, err := newHTTPCh()
			assert.FatalError(t, err)
			return test{
				ch:  httpCh,
				old: nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return []byte("foo"), false, nil
					},
				},
				err: ServerInternalErr(errors.New("error saving acme challenge; acme challenge has changed since last read")),
			}
		},
		"ok/old-nil": func(t *testing.T) test {
			httpCh, err := newHTTPCh()
			assert.FatalError(t, err)
			b, err := json.Marshal(httpCh)
			assert.FatalError(t, err)
			return test{
				ch:  httpCh,
				old: nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, old, nil)
						assert.Equals(t, b, newval)
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, []byte(httpCh.getID()), key)
						return []byte("foo"), true, nil
					},
				},
			}
		},
		"ok/old-not-nil": func(t *testing.T) test {
			oldHTTPCh, err := newHTTPCh()
			assert.FatalError(t, err)
			httpCh, err := newHTTPCh()
			assert.FatalError(t, err)

			oldb, err := json.Marshal(oldHTTPCh)
			assert.FatalError(t, err)
			b, err := json.Marshal(httpCh)
			assert.FatalError(t, err)
			return test{
				ch:  httpCh,
				old: oldHTTPCh,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, old, oldb)
						assert.Equals(t, b, newval)
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, []byte(httpCh.getID()), key)
						return []byte("foo"), true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := tc.ch.save(tc.db, tc.old); err != nil {
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

func TestChallengeClone(t *testing.T) {
	ch, err := newHTTPCh()
	assert.FatalError(t, err)

	clone := ch.clone()

	assert.Equals(t, clone.getID(), ch.getID())
	assert.Equals(t, clone.getAccountID(), ch.getAccountID())
	assert.Equals(t, clone.getAuthzID(), ch.getAuthzID())
	assert.Equals(t, clone.getStatus(), ch.getStatus())
	assert.Equals(t, clone.getToken(), ch.getToken())
	assert.Equals(t, clone.getCreated(), ch.getCreated())
	assert.Equals(t, clone.getValidated(), ch.getValidated())

	clone.Status = StatusValid

	assert.NotEquals(t, clone.getStatus(), ch.getStatus())
}

func TestChallengeUnmarshal(t *testing.T) {
	type test struct {
		ch  challenge
		chb []byte
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/nil": func(t *testing.T) test {
			return test{
				chb: nil,
				err: ServerInternalErr(errors.New("error unmarshaling challenge type: unexpected end of JSON input")),
			}
		},
		"fail/unexpected-type": func(t *testing.T) test {
			httpCh, err := newHTTPCh()
			assert.FatalError(t, err)
			_httpCh, ok := httpCh.(*http01Challenge)
			assert.Fatal(t, ok)
			_httpCh.baseChallenge.Type = "foo"
			b, err := json.Marshal(httpCh)
			assert.FatalError(t, err)
			return test{
				chb: b,
				err: ServerInternalErr(errors.New("unexpected challenge type foo")),
			}
		},
		"ok/dns": func(t *testing.T) test {
			dnsCh, err := newDNSCh()
			assert.FatalError(t, err)
			b, err := json.Marshal(dnsCh)
			assert.FatalError(t, err)
			return test{
				ch:  dnsCh,
				chb: b,
			}
		},
		"ok/http": func(t *testing.T) test {
			httpCh, err := newHTTPCh()
			assert.FatalError(t, err)
			b, err := json.Marshal(httpCh)
			assert.FatalError(t, err)
			return test{
				ch:  httpCh,
				chb: b,
			}
		},
		"ok/err": func(t *testing.T) test {
			httpCh, err := newHTTPCh()
			assert.FatalError(t, err)
			_httpCh, ok := httpCh.(*http01Challenge)
			assert.Fatal(t, ok)
			_httpCh.baseChallenge.Error = ServerInternalErr(errors.New("force")).ToACME()
			b, err := json.Marshal(httpCh)
			assert.FatalError(t, err)
			return test{
				ch:  httpCh,
				chb: b,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if ch, err := unmarshalChallenge(tc.chb); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.ch.getID(), ch.getID())
					assert.Equals(t, tc.ch.getAccountID(), ch.getAccountID())
					assert.Equals(t, tc.ch.getAuthzID(), ch.getAuthzID())
					assert.Equals(t, tc.ch.getStatus(), ch.getStatus())
					assert.Equals(t, tc.ch.getToken(), ch.getToken())
					assert.Equals(t, tc.ch.getCreated(), ch.getCreated())
					assert.Equals(t, tc.ch.getValidated(), ch.getValidated())
				}
			}
		})
	}
}
func TestGetChallenge(t *testing.T) {
	type test struct {
		id  string
		db  nosql.DB
		ch  challenge
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			dnsCh, err := newDNSCh()
			assert.FatalError(t, err)
			return test{
				ch: dnsCh,
				id: dnsCh.getID(),
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, database.ErrNotFound
					},
				},
				err: MalformedErr(errors.Errorf("challenge %s not found: not found", dnsCh.getID())),
			}
		},
		"fail/db-error": func(t *testing.T) test {
			dnsCh, err := newDNSCh()
			assert.FatalError(t, err)
			return test{
				ch: dnsCh,
				id: dnsCh.getID(),
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.Errorf("error loading challenge %s: force", dnsCh.getID())),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			dnsCh, err := newDNSCh()
			assert.FatalError(t, err)
			_dnsCh, ok := dnsCh.(*dns01Challenge)
			assert.Fatal(t, ok)
			_dnsCh.baseChallenge.Type = "foo"
			b, err := json.Marshal(dnsCh)
			assert.FatalError(t, err)
			return test{
				ch: dnsCh,
				id: dnsCh.getID(),
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(dnsCh.getID()))
						return b, nil
					},
				},
				err: ServerInternalErr(errors.New("unexpected challenge type foo")),
			}
		},
		"ok": func(t *testing.T) test {
			dnsCh, err := newDNSCh()
			assert.FatalError(t, err)
			b, err := json.Marshal(dnsCh)
			assert.FatalError(t, err)
			return test{
				ch: dnsCh,
				id: dnsCh.getID(),
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(dnsCh.getID()))
						return b, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if ch, err := getChallenge(tc.db, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.ch.getID(), ch.getID())
					assert.Equals(t, tc.ch.getAccountID(), ch.getAccountID())
					assert.Equals(t, tc.ch.getAuthzID(), ch.getAuthzID())
					assert.Equals(t, tc.ch.getStatus(), ch.getStatus())
					assert.Equals(t, tc.ch.getToken(), ch.getToken())
					assert.Equals(t, tc.ch.getCreated(), ch.getCreated())
					assert.Equals(t, tc.ch.getValidated(), ch.getValidated())
				}
			}
		})
	}
}

func TestKeyAuthorization(t *testing.T) {
	type test struct {
		token string
		jwk   *jose.JSONWebKey
		exp   string
		err   *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/jwk-thumbprint-error": func(t *testing.T) test {
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			jwk.Key = "foo"
			return test{
				token: "1234",
				jwk:   jwk,
				err:   ServerInternalErr(errors.Errorf("error generating JWK thumbprint: square/go-jose: unknown key type 'string'")),
			}
		},
		"ok": func(t *testing.T) test {
			token := "1234"
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			thumbprint, err := jwk.Thumbprint(crypto.SHA256)
			assert.FatalError(t, err)
			encPrint := base64.RawURLEncoding.EncodeToString(thumbprint)
			return test{
				token: token,
				jwk:   jwk,
				exp:   fmt.Sprintf("%s.%s", token, encPrint),
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if ka, err := KeyAuthorization(tc.token, tc.jwk); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.exp, ka)
				}
			}
		})
	}
}

type errReader int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("force")
}
func (errReader) Close() error {
	return nil
}

func TestHTTP01Validate(t *testing.T) {
	type test struct {
		vo  validateOptions
		ch  challenge
		res challenge
		jwk *jose.JSONWebKey
		db  nosql.DB
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"ok/status-already-valid": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			_ch, ok := ch.(*http01Challenge)
			assert.Fatal(t, ok)
			_ch.baseChallenge.Status = StatusValid
			return test{
				ch:  ch,
				res: ch,
			}
		},
		"ok/status-already-invalid": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			_ch, ok := ch.(*http01Challenge)
			assert.Fatal(t, ok)
			_ch.baseChallenge.Status = StatusInvalid
			return test{
				ch:  ch,
				res: ch,
			}
		},
		"ok/http-get-error": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			oldb, err := json.Marshal(ch)
			assert.FatalError(t, err)

			expErr := ConnectionErr(errors.Errorf("error doing http GET for url "+
				"http://zap.internal/.well-known/acme-challenge/%s: force", ch.getToken()))
			baseClone := ch.clone()
			baseClone.Error = expErr.ToACME()
			newCh := &http01Challenge{baseClone}
			newb, err := json.Marshal(newCh)
			assert.FatalError(t, err)
			return test{
				ch: ch,
				vo: validateOptions{
					httpGet: func(url string) (*http.Response, error) {
						return nil, errors.New("force")
					},
				},
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch.getID()))
						assert.Equals(t, old, oldb)
						assert.Equals(t, newval, newb)
						return nil, true, nil
					},
				},
				res: ch,
			}
		},
		"ok/http-get->=400": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			oldb, err := json.Marshal(ch)
			assert.FatalError(t, err)

			expErr := ConnectionErr(errors.Errorf("error doing http GET for url "+
				"http://zap.internal/.well-known/acme-challenge/%s with status code 400", ch.getToken()))
			baseClone := ch.clone()
			baseClone.Error = expErr.ToACME()
			newCh := &http01Challenge{baseClone}
			newb, err := json.Marshal(newCh)
			assert.FatalError(t, err)
			return test{
				ch: ch,
				vo: validateOptions{
					httpGet: func(url string) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusBadRequest,
						}, nil
					},
				},
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch.getID()))
						assert.Equals(t, old, oldb)
						assert.Equals(t, newval, newb)
						return nil, true, nil
					},
				},
				res: ch,
			}
		},
		"fail/read-body": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			jwk.Key = "foo"

			return test{
				ch: ch,
				vo: validateOptions{
					httpGet: func(url string) (*http.Response, error) {
						return &http.Response{
							Body: errReader(0),
						}, nil
					},
				},
				jwk: jwk,
				err: ServerInternalErr(errors.Errorf("error reading response "+
					"body for url http://zap.internal/.well-known/acme-challenge/%s: force",
					ch.getToken())),
			}
		},
		"fail/key-authorization-gen-error": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			jwk.Key = "foo"
			return test{
				ch: ch,
				vo: validateOptions{
					httpGet: func(url string) (*http.Response, error) {
						return &http.Response{
							Body: ioutil.NopCloser(bytes.NewBufferString("foo")),
						}, nil
					},
				},
				jwk: jwk,
				err: ServerInternalErr(errors.New("error generating JWK thumbprint: square/go-jose: unknown key type 'string'")),
			}
		},
		"ok/key-auth-mismatch": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			oldb, err := json.Marshal(ch)
			assert.FatalError(t, err)

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.getToken(), jwk)
			assert.FatalError(t, err)

			expErr := RejectedIdentifierErr(errors.Errorf("keyAuthorization does not match; "+
				"expected %s, but got foo", expKeyAuth))
			baseClone := ch.clone()
			baseClone.Error = expErr.ToACME()
			newCh := &http01Challenge{baseClone}
			newb, err := json.Marshal(newCh)
			assert.FatalError(t, err)

			return test{
				ch: ch,
				vo: validateOptions{
					httpGet: func(url string) (*http.Response, error) {
						return &http.Response{
							Body: ioutil.NopCloser(bytes.NewBufferString("foo")),
						}, nil
					},
				},
				jwk: jwk,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch.getID()))
						assert.Equals(t, old, oldb)
						assert.Equals(t, newval, newb)
						return nil, true, nil
					},
				},
				res: ch,
			}
		},
		"fail/save-error": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.getToken(), jwk)
			assert.FatalError(t, err)
			return test{
				ch: ch,
				vo: validateOptions{
					httpGet: func(url string) (*http.Response, error) {
						return &http.Response{
							Body: ioutil.NopCloser(bytes.NewBufferString(expKeyAuth)),
						}, nil
					},
				},
				jwk: jwk,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error saving acme challenge: force")),
			}
		},
		"ok": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			_ch, ok := ch.(*http01Challenge)
			assert.Fatal(t, ok)
			_ch.baseChallenge.Error = MalformedErr(nil).ToACME()
			oldb, err := json.Marshal(ch)
			assert.FatalError(t, err)

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.getToken(), jwk)
			assert.FatalError(t, err)

			baseClone := ch.clone()
			baseClone.Status = StatusValid
			baseClone.Error = nil
			newCh := &http01Challenge{baseClone}

			return test{
				ch:  ch,
				res: newCh,
				vo: validateOptions{
					httpGet: func(url string) (*http.Response, error) {
						return &http.Response{
							Body: ioutil.NopCloser(bytes.NewBufferString(expKeyAuth)),
						}, nil
					},
				},
				jwk: jwk,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch.getID()))
						assert.Equals(t, old, oldb)

						httpCh, err := unmarshalChallenge(newval)
						assert.FatalError(t, err)
						assert.Equals(t, httpCh.getStatus(), StatusValid)
						assert.True(t, httpCh.getValidated().Before(time.Now().UTC().Add(time.Minute)))
						assert.True(t, httpCh.getValidated().After(time.Now().UTC().Add(-1*time.Second)))

						baseClone.Validated = httpCh.getValidated()

						return nil, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if ch, err := tc.ch.validate(tc.db, tc.jwk, tc.vo); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.res.getID(), ch.getID())
					assert.Equals(t, tc.res.getAccountID(), ch.getAccountID())
					assert.Equals(t, tc.res.getAuthzID(), ch.getAuthzID())
					assert.Equals(t, tc.res.getStatus(), ch.getStatus())
					assert.Equals(t, tc.res.getToken(), ch.getToken())
					assert.Equals(t, tc.res.getCreated(), ch.getCreated())
					assert.Equals(t, tc.res.getValidated(), ch.getValidated())
					assert.Equals(t, tc.res.getError(), ch.getError())
				}
			}
		})
	}
}

func TestDNS01Validate(t *testing.T) {
	type test struct {
		vo  validateOptions
		ch  challenge
		res challenge
		jwk *jose.JSONWebKey
		db  nosql.DB
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"ok/status-already-valid": func(t *testing.T) test {
			ch, err := newDNSCh()
			assert.FatalError(t, err)
			_ch, ok := ch.(*dns01Challenge)
			assert.Fatal(t, ok)
			_ch.baseChallenge.Status = StatusValid
			return test{
				ch:  ch,
				res: ch,
			}
		},
		"ok/status-already-invalid": func(t *testing.T) test {
			ch, err := newDNSCh()
			assert.FatalError(t, err)
			_ch, ok := ch.(*dns01Challenge)
			assert.Fatal(t, ok)
			_ch.baseChallenge.Status = StatusInvalid
			return test{
				ch:  ch,
				res: ch,
			}
		},
		"ok/lookup-txt-error": func(t *testing.T) test {
			ch, err := newDNSCh()
			assert.FatalError(t, err)
			oldb, err := json.Marshal(ch)
			assert.FatalError(t, err)

			expErr := DNSErr(errors.Errorf("error looking up TXT records for "+
				"domain %s: force", ch.getValue()))
			baseClone := ch.clone()
			baseClone.Error = expErr.ToACME()
			newCh := &dns01Challenge{baseClone}
			newb, err := json.Marshal(newCh)
			assert.FatalError(t, err)
			return test{
				ch: ch,
				vo: validateOptions{
					lookupTxt: func(url string) ([]string, error) {
						return nil, errors.New("force")
					},
				},
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch.getID()))
						assert.Equals(t, old, oldb)
						assert.Equals(t, newval, newb)
						return nil, true, nil
					},
				},
				res: ch,
			}
		},
		"fail/key-authorization-gen-error": func(t *testing.T) test {
			ch, err := newDNSCh()
			assert.FatalError(t, err)
			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			jwk.Key = "foo"
			return test{
				ch: ch,
				vo: validateOptions{
					lookupTxt: func(url string) ([]string, error) {
						return []string{"foo", "bar"}, nil
					},
				},
				jwk: jwk,
				err: ServerInternalErr(errors.New("error generating JWK thumbprint: square/go-jose: unknown key type 'string'")),
			}
		},
		"ok/key-auth-mismatch": func(t *testing.T) test {
			ch, err := newDNSCh()
			assert.FatalError(t, err)
			oldb, err := json.Marshal(ch)
			assert.FatalError(t, err)

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.getToken(), jwk)
			assert.FatalError(t, err)

			expErr := RejectedIdentifierErr(errors.Errorf("keyAuthorization does not match; "+
				"expected %s, but got %s", expKeyAuth, []string{"foo", "bar"}))
			baseClone := ch.clone()
			baseClone.Error = expErr.ToACME()
			newCh := &http01Challenge{baseClone}
			newb, err := json.Marshal(newCh)
			assert.FatalError(t, err)

			return test{
				ch: ch,
				vo: validateOptions{
					lookupTxt: func(url string) ([]string, error) {
						return []string{"foo", "bar"}, nil
					},
				},
				jwk: jwk,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch.getID()))
						assert.Equals(t, old, oldb)
						assert.Equals(t, newval, newb)
						return nil, true, nil
					},
				},
				res: ch,
			}
		},
		"fail/save-error": func(t *testing.T) test {
			ch, err := newDNSCh()
			assert.FatalError(t, err)

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.getToken(), jwk)
			assert.FatalError(t, err)
			h := sha256.Sum256([]byte(expKeyAuth))
			expected := base64.RawURLEncoding.EncodeToString(h[:])
			return test{
				ch: ch,
				vo: validateOptions{
					lookupTxt: func(url string) ([]string, error) {
						return []string{"foo", expected}, nil
					},
				},
				jwk: jwk,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error saving acme challenge: force")),
			}
		},
		"ok": func(t *testing.T) test {
			ch, err := newDNSCh()
			assert.FatalError(t, err)
			_ch, ok := ch.(*dns01Challenge)
			assert.Fatal(t, ok)
			_ch.baseChallenge.Error = MalformedErr(nil).ToACME()
			oldb, err := json.Marshal(ch)
			assert.FatalError(t, err)

			jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)

			expKeyAuth, err := KeyAuthorization(ch.getToken(), jwk)
			assert.FatalError(t, err)
			h := sha256.Sum256([]byte(expKeyAuth))
			expected := base64.RawURLEncoding.EncodeToString(h[:])

			baseClone := ch.clone()
			baseClone.Status = StatusValid
			baseClone.Error = nil
			newCh := &dns01Challenge{baseClone}

			return test{
				ch:  ch,
				res: newCh,
				vo: validateOptions{
					lookupTxt: func(url string) ([]string, error) {
						return []string{"foo", expected}, nil
					},
				},
				jwk: jwk,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch.getID()))
						assert.Equals(t, old, oldb)

						dnsCh, err := unmarshalChallenge(newval)
						assert.FatalError(t, err)
						assert.Equals(t, dnsCh.getStatus(), StatusValid)
						assert.True(t, dnsCh.getValidated().Before(time.Now().UTC()))
						assert.True(t, dnsCh.getValidated().After(time.Now().UTC().Add(-1*time.Second)))

						baseClone.Validated = dnsCh.getValidated()

						return nil, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if ch, err := tc.ch.validate(tc.db, tc.jwk, tc.vo); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.res.getID(), ch.getID())
					assert.Equals(t, tc.res.getAccountID(), ch.getAccountID())
					assert.Equals(t, tc.res.getAuthzID(), ch.getAuthzID())
					assert.Equals(t, tc.res.getStatus(), ch.getStatus())
					assert.Equals(t, tc.res.getToken(), ch.getToken())
					assert.Equals(t, tc.res.getCreated(), ch.getCreated())
					assert.Equals(t, tc.res.getValidated(), ch.getValidated())
					assert.Equals(t, tc.res.getError(), ch.getError())
				}
			}
		})
	}
}
