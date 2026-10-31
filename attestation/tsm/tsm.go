// Package tsm parses Linux configfs-tsm reports in the media types Veraison
// registered for them, application/vnd.veraison.tsm-report+json and
// application/vnd.veraison.tsm-report+cbor, described by
// https://github.com/veraison/ratsd/blob/main/docs/tsm-report.cddl.
package tsm

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/smallstep/certificates/attestation"
)

// The media types of a configfs-tsm report.
const (
	MediaTypeJSON = "application/vnd.veraison.tsm-report+json"
	MediaTypeCBOR = "application/vnd.veraison.tsm-report+cbor"
)

// The providers of the configfs-tsm reports this package's callers verify.
const (
	// ProviderTDX is an Intel TDX guest, whose outblob is a quote.
	ProviderTDX = "tdx_guest"
	// ProviderSEVSNP is an AMD SEV-SNP guest, whose outblob is an attestation
	// report and whose auxblob is its certificate table.
	ProviderSEVSNP = "sev_guest"
)

// Report is a configfs-tsm report.
type Report struct {
	// Provider names the format of OutBlob, for example tdx_guest.
	Provider string
	// OutBlob is the evidence the provider generated.
	OutBlob []byte
	// AuxBlob is the provider's auxiliary data, if any.
	AuxBlob []byte
}

// IsMediaType reports whether mediaType, with or without parameters, is one of
// the media types of a configfs-tsm report.
func IsMediaType(mediaType string) bool {
	mt, _, err := mime.ParseMediaType(mediaType)
	return err == nil && (mt == MediaTypeJSON || mt == MediaTypeCBOR)
}

// Parse parses a configfs-tsm report sent with the given media type. If the
// media type has a provider parameter, it must match the report's provider.
// Errors match attestation.ErrInvalidEvidence.
func Parse(mediaType string, value []byte) (*Report, error) {
	mt, params, err := mime.ParseMediaType(mediaType)
	if err != nil {
		return nil, attestation.Invalidf("error parsing media type %q: %w", mediaType, err)
	}

	var r *Report
	switch mt {
	case MediaTypeJSON:
		r, err = parseJSON(value)
	case MediaTypeCBOR:
		r, err = parseCBOR(value)
	default:
		return nil, attestation.Invalidf("media type %q is not a tsm report", mt)
	}
	if err != nil {
		return nil, attestation.Invalid(err)
	}

	if r.Provider == "" {
		return nil, attestation.Invalidf("tsm report has no provider")
	}
	if len(r.OutBlob) == 0 {
		return nil, attestation.Invalidf("tsm report has no outblob")
	}
	if p, ok := params["provider"]; ok && p != r.Provider {
		return nil, attestation.Invalidf("tsm report provider %q does not match the media type's provider %q", r.Provider, p)
	}
	return r, nil
}

func parseJSON(value []byte) (*Report, error) {
	var v struct {
		Provider string `json:"provider"`
		OutBlob  string `json:"outblob"`
		AuxBlob  string `json:"auxblob"`
	}
	if err := json.Unmarshal(value, &v); err != nil {
		return nil, fmt.Errorf("error parsing tsm report: %w", err)
	}
	out, err := decodeBase64(v.OutBlob)
	if err != nil {
		return nil, fmt.Errorf("tsm report outblob must be base64url: %w", err)
	}
	aux, err := decodeBase64(v.AuxBlob)
	if err != nil {
		return nil, fmt.Errorf("tsm report auxblob must be base64url: %w", err)
	}
	return &Report{Provider: v.Provider, OutBlob: out, AuxBlob: aux}, nil
}

func parseCBOR(value []byte) (*Report, error) {
	var v struct {
		Provider string `cbor:"provider"`
		OutBlob  []byte `cbor:"outblob"`
		AuxBlob  []byte `cbor:"auxblob"`
	}
	if err := cbor.Unmarshal(value, &v); err != nil {
		return nil, fmt.Errorf("error parsing tsm report: %w", err)
	}
	return &Report{Provider: v.Provider, OutBlob: v.OutBlob, AuxBlob: v.AuxBlob}, nil
}

// decodeBase64 decodes base64url, as the CDDL requires, and also accepts the
// standard alphabet and padding.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, nil
	}
	if strings.ContainsAny(s, "+/") {
		return base64.RawStdEncoding.DecodeString(s)
	}
	return base64.RawURLEncoding.DecodeString(s)
}
