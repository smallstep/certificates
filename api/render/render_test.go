package render

import (
	"fmt"
	"io"
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

type renderableError struct {
	Code    int    `json:"-"`
	Message string `json:"message"`
}

func (err renderableError) Error() string {
	return err.Message
}

func (err renderableError) Render(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "something/custom")

	JSONStatus(w, err, err.Code)
}

type statusedError struct {
	Contents string
}

func (err statusedError) Error() string { return err.Contents }

func (statusedError) StatusCode() int { return 432 }

func TestError(t *testing.T) {
	cases := []struct {
		err    error
		code   int
		body   string
		header string
	}{
		0: {
			err:    renderableError{532, "some string"},
			code:   532,
			body:   "{\"message\":\"some string\"}\n",
			header: "something/custom",
		},
		1: {
			err:    statusedError{"123"},
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

type causedError struct {
	cause error
}

func (err causedError) Error() string { return fmt.Sprintf("cause: %s", err.cause) }
func (err causedError) Cause() error  { return err.cause }

func TestStatusCodeFromError(t *testing.T) {
	cases := []struct {
		err error
		exp int
	}{
		0: {nil, http.StatusInternalServerError},
		1: {io.EOF, http.StatusInternalServerError},
		2: {statusedError{"123"}, 432},
		3: {causedError{statusedError{"432"}}, 432},
	}

	for caseIndex, kase := range cases {
		assert.Equal(t, kase.exp, statusCodeFromError(kase.err), "case: %d", caseIndex)
	}
}
