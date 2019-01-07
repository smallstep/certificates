package authority

import (
	"net/http"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
)

func TestRoot(t *testing.T) {
	a := testAuthority(t)
	a.certificates.Store("invaliddata", "a string") // invalid cert for testing

	tests := map[string]struct {
		sum string
		err *apiError
	}{
		"not-found":                  {"foo", &apiError{errors.New("certificate with fingerprint foo was not found"), http.StatusNotFound, context{}}},
		"invalid-stored-certificate": {"invaliddata", &apiError{errors.New("stored value is not a *x509.Certificate"), http.StatusInternalServerError, context{}}},
		"success":                    {"189f573cfa159251e445530847ef80b1b62a3a380ee670dcb49e33ed34da0616", nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			crt, err := a.Root(tc.sum)
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
					assert.Equals(t, crt, a.rootX509Certs[0])
				}
			}
		})
	}
}
