package authority

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/ca-component/provisioner"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/jose"
)

func TestGetEncryptedKey(t *testing.T) {
	type ek struct {
		a   *Authority
		kid string
		err *apiError
	}
	tests := map[string]func(t *testing.T) *ek{
		"ok": func(t *testing.T) *ek {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			a, err := New(c)
			assert.FatalError(t, err)
			return &ek{
				a:   a,
				kid: c.AuthorityConfig.Provisioners[1].Key.KeyID,
			}
		},
		"fail-not-found": func(t *testing.T) *ek {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			a, err := New(c)
			assert.FatalError(t, err)
			return &ek{
				a:   a,
				kid: "foo",
				err: &apiError{errors.Errorf("encrypted key with kid foo was not found"),
					http.StatusNotFound, context{}},
			}
		},
		"fail-invalid-type-found": func(t *testing.T) *ek {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			a, err := New(c)
			assert.FatalError(t, err)
			a.encryptedKeyIndex.Store("foo", 5)
			return &ek{
				a:   a,
				kid: "foo",
				err: &apiError{errors.Errorf("stored value is not a string"),
					http.StatusInternalServerError, context{}},
			}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			ek, err := tc.a.GetEncryptedKey(tc.kid)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					switch v := err.(type) {
					case *apiError:
						assert.HasPrefix(t, v.err.Error(), tc.err.Error())
						assert.Equals(t, v.code, tc.err.code)
						assert.Equals(t, v.context, tc.err.context)
					default:
						t.Errorf("unexpected error type: %T", v)
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					val, ok := tc.a.provisionerIDIndex.Load(tc.kid)
					assert.Fatal(t, ok)
					p, ok := val.(*Provisioner)
					assert.Fatal(t, ok)
					assert.Equals(t, p.EncryptedKey, ek)
				}
			}
		})
	}
}

func TestGetProvisioners(t *testing.T) {
	type gp struct {
		a   *Authority
		err *apiError
	}
	tests := map[string]func(t *testing.T) *gp{
		"ok": func(t *testing.T) *gp {
			c, err := LoadConfiguration("../ca/testdata/ca.json")
			assert.FatalError(t, err)
			a, err := New(c)
			assert.FatalError(t, err)
			return &gp{a: a}
		},
	}

	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			ps, err := tc.a.GetProvisioners()
			if err != nil {
				if assert.NotNil(t, tc.err) {
					switch v := err.(type) {
					case *apiError:
						assert.HasPrefix(t, v.err.Error(), tc.err.Error())
						assert.Equals(t, v.code, tc.err.code)
						assert.Equals(t, v.context, tc.err.context)
					default:
						t.Errorf("unexpected error type: %T", v)
					}
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, ps, tc.a.config.AuthorityConfig.Provisioners)
				}
			}
		})
	}
}

func generateProvisioner(t *testing.T) *provisioner.Provisioner {
	issuer, err := randutil.Alphanumeric(10)
	assert.FatalError(t, err)
	// Create a new JWK
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	// Encrypt JWK
	salt, err := randutil.Salt(jose.PBKDF2SaltSize)
	assert.FatalError(t, err)
	b, err := json.Marshal(jwk)
	assert.FatalError(t, err)
	recipient := jose.Recipient{
		Algorithm:  jose.PBES2_HS256_A128KW,
		Key:        []byte("password"),
		PBES2Count: jose.PBKDF2Iterations,
		PBES2Salt:  salt,
	}
	opts := new(jose.EncrypterOptions)
	opts.WithContentType(jose.ContentType("jwk+json"))
	encrypter, err := jose.NewEncrypter(jose.DefaultEncAlgorithm, recipient, opts)
	assert.FatalError(t, err)
	jwe, err := encrypter.Encrypt(b)
	assert.FatalError(t, err)
	// get public and encrypted keys
	public := jwk.Public()
	encrypted, err := jwe.CompactSerialize()
	assert.FatalError(t, err)
	return &provisioner.Provisioner{
		Issuer:       issuer,
		Type:         "JWT",
		Key:          &public,
		EncryptedKey: encrypted,
	}
}

func Test_newSortedProvisioners(t *testing.T) {
	provisioners := make([]*provisioner.Provisioner, 20)
	for i := range provisioners {
		provisioners[i] = generateProvisioner(t)
	}

	ps, err := newSortedProvisioners(provisioners)
	assert.FatalError(t, err)
	prev := ""
	for i, p := range ps {
		if p.uid < prev {
			t.Errorf("%s should be less that %s", p.uid, prev)
		}
		if p.provisioner.Key.KeyID != provisioners[i].Key.KeyID {
			t.Errorf("provisioner order is not the same: %s != %s", p.provisioner.Key.KeyID, provisioners[i].Key.KeyID)
		}
		prev = p.uid
	}
}

func Test_provisionerSlice_Find(t *testing.T) {
	trim := func(s string) string {
		return strings.TrimLeft(s, "0")
	}
	provisioners := make([]*provisioner.Provisioner, 20)
	for i := range provisioners {
		provisioners[i] = generateProvisioner(t)
	}
	ps, err := newSortedProvisioners(provisioners)
	assert.FatalError(t, err)

	type args struct {
		cursor string
		limit  int
	}
	tests := []struct {
		name  string
		p     provisionerSlice
		args  args
		want  []*provisioner.Provisioner
		want1 string
	}{
		{"all", ps, args{"", DefaultProvisionersMax}, provisioners[0:20], ""},
		{"0 to 19", ps, args{"", 20}, provisioners[0:20], ""},
		{"0 to 9", ps, args{"", 10}, provisioners[0:10], trim(ps[10].uid)},
		{"9 to 19", ps, args{trim(ps[10].uid), 10}, provisioners[10:20], ""},
		{"1", ps, args{trim(ps[1].uid), 1}, provisioners[1:2], trim(ps[2].uid)},
		{"1 to 5", ps, args{trim(ps[1].uid), 4}, provisioners[1:5], trim(ps[5].uid)},
		{"defaultLimit", ps, args{"", 0}, provisioners[0:20], ""},
		{"overTheLimit", ps, args{"", DefaultProvisionersMax + 1}, provisioners[0:20], ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := tt.p.Find(tt.args.cursor, tt.args.limit)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("provisionerSlice.Find() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("provisionerSlice.Find() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
