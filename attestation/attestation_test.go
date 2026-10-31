package attestation

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormat_Validate(t *testing.T) {
	for _, f := range []Format{FormatTDX, FormatSEVSNP, FormatConfidentialSpace} {
		assert.NoError(t, f.Validate(), f)
	}
	assert.EqualError(t, Format("tpm").Validate(), `attestation format "tpm" is not supported`)
}

func TestInvalid(t *testing.T) {
	cause := errors.New("bad signature")
	err := Invalid(cause)
	assert.ErrorIs(t, err, ErrInvalidEvidence)
	assert.ErrorIs(t, err, cause)
	assert.EqualError(t, err, "bad signature")
	assert.NoError(t, Invalid(nil))

	err = Invalidf("report data has %d bytes", 12)
	assert.ErrorIs(t, err, ErrInvalidEvidence)
	assert.EqualError(t, err, "report data has 12 bytes")

	assert.NotErrorIs(t, errors.New("fetch failed"), ErrInvalidEvidence)
}
