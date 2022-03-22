package read

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
)

func TestJSON(t *testing.T) {
	cases := []struct {
		src  io.Reader
		exp  interface{}
		ok   bool
		code int
	}{
		0: {
			src:  strings.NewReader(`{"foo":"bar"}`),
			exp:  map[string]interface{}{"foo": "bar"},
			ok:   true,
			code: http.StatusOK,
		},
		1: {
			src:  strings.NewReader(`{"foo"}`),
			code: http.StatusBadRequest,
		},
		2: {
			src: io.MultiReader(
				strings.NewReader(`{`),
				iotest.ErrReader(assert.AnError),
				strings.NewReader(`"foo":"bar"}`),
			),
			code: http.StatusBadRequest,
		},
	}

	for caseIndex := range cases {
		kase := cases[caseIndex]

		t.Run(strconv.Itoa(caseIndex), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", kase.src)
			rec := httptest.NewRecorder()

			var body interface{}
			got := JSON(rec, req, &body)

			assert.Equal(t, kase.ok, got)
			assert.Equal(t, kase.code, rec.Result().StatusCode)
			assert.Equal(t, kase.exp, body)
		})
	}
}
