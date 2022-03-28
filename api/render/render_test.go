package render

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smallstep/certificates/logging"
	"github.com/stretchr/testify/assert"
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
