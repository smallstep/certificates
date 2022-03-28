package render

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smallstep/certificates/logging"
)

func TestJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := logging.NewResponseLogger(rec)

	JSON(rw, map[string]interface{}{"foo": "bar"})

	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "{\"foo\":\"bar\"}\n", rec.Body.String())

	assert.Empty(t, rw.Fields())
}

func TestJSONPanics(t *testing.T) {
	assert.Panics(t, func() {
		JSON(httptest.NewRecorder(), make(chan struct{}))
	})
}

type renderableTestError struct {
	Code    int    `json:"-"`
	Message string `json:"message"`
}

func (err renderableTestError) Error() string {
	return err.Message
}

func (err renderableTestError) Render(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "something/custom")

	JSONStatus(w, err, err.Code)
}

type codedTestError struct {
	Contents string
}

func (err codedTestError) Error() string { return err.Contents }

func (codedTestError) StatusCode() int { return 432 }

func TestError(t *testing.T) {
	cases := []struct {
		err    error
		code   int
		body   string
		header string
	}{
		0: {
			err:    renderableTestError{532, "some string"},
			code:   532,
			body:   "{\"message\":\"some string\"}\n",
			header: "something/custom",
		},
		1: {
			err:    codedTestError{"123"},
			code:   432,
			body:   "{\"Contents\":\"123\"}\n",
			header: "application/json",
		},
	}

	for caseIndex := range cases {
		kase := cases[caseIndex]

		t.Run(strconv.Itoa(caseIndex), func(t *testing.T) {
			rec := httptest.NewRecorder()

			Error(rec, kase.err)

			assert.Equal(t, kase.code, rec.Result().StatusCode)
			assert.Equal(t, kase.body, rec.Body.String())
			assert.Equal(t, kase.header, rec.Header().Get("Content-Type"))
		})
	}
}
