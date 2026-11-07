package tdx

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"mime"

	"github.com/smallstep/certificates/attestation"
)

// AzureMediaType is the media type of the evidence of an Azure confidential VM
// with Intel TDX: a JSON object of the paravisor's TDX quote and the runtime
// claims it commits to.
const AzureMediaType = "application/vnd.smallstep.azure-tdx+json"

// AzureUserDataSize is the size of the user data in an Azure confidential VM's
// runtime claims, which the guest writes to the vTPM before the paravisor
// produces its report.
const AzureUserDataSize = 64

// IsAzureMediaType reports whether mediaType is AzureMediaType, with or without
// parameters.
func IsAzureMediaType(mediaType string) bool {
	mt, _, err := mime.ParseMediaType(mediaType)
	return err == nil && mt == AzureMediaType
}

// AzureEvidence is the evidence of an Azure confidential VM with Intel TDX.
//
// The guest of such a VM cannot get a TDX quote itself: there is no
// /dev/tdx_guest and configfs-tsm has no provider. Its paravisor produces a TD
// report whose report data is SHA-256 of a JSON document of runtime claims,
// zero-padded to 64 bytes. The runtime claims carry the vTPM's keys, the VM's
// configuration and 64 bytes of user data the guest chose. Azure's instance
// metadata service turns the TD report into a quote signed by Intel's quoting
// enclave.
type AzureEvidence struct {
	// Quote is the TDX quote of the paravisor's TD report.
	Quote []byte `json:"quote"`
	// RuntimeData is the runtime claims document, exactly as the paravisor
	// hashed it.
	RuntimeData []byte `json:"runtimeData"`
}

// ParseAzureEvidence parses the evidence of an Azure confidential VM. Its
// errors match attestation.ErrInvalidEvidence.
func ParseAzureEvidence(value []byte) (*AzureEvidence, error) {
	var e AzureEvidence
	dec := json.NewDecoder(bytes.NewReader(value))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, attestation.Invalidf("error parsing azure tdx evidence: %w", err)
	}
	if dec.More() {
		return nil, attestation.Invalidf("azure tdx evidence has trailing data")
	}
	if len(e.Quote) == 0 || len(e.RuntimeData) == 0 {
		return nil, attestation.Invalidf("azure tdx evidence needs a quote and runtime data")
	}
	return &e, nil
}

// azureRuntimeClaims is the runtime claims document of an Azure confidential
// VM.
type azureRuntimeClaims struct {
	Keys            []map[string]any `json:"keys"`
	VMConfiguration map[string]any   `json:"vm-configuration"`
	UserData        string           `json:"user-data"`
}

// Claims checks that the report data of the evidence's verified quote commits
// to its runtime data, and returns the runtime claims and the user data they
// carry. Its errors match attestation.ErrInvalidEvidence.
func (e *AzureEvidence) Claims(reportData []byte) (*attestation.AzureRuntime, []byte, error) {
	if len(reportData) != ReportDataSize {
		return nil, nil, attestation.Invalidf("tdx quote report data has %d bytes, not %d", len(reportData), ReportDataSize)
	}
	want := make([]byte, ReportDataSize)
	sum := sha256.Sum256(e.RuntimeData)
	copy(want, sum[:])
	if subtle.ConstantTimeCompare(reportData, want) != 1 {
		return nil, nil, attestation.Invalidf("tdx quote report data does not commit to the azure runtime data")
	}

	var claims azureRuntimeClaims
	if err := json.Unmarshal(e.RuntimeData, &claims); err != nil {
		return nil, nil, attestation.Invalidf("error parsing azure runtime claims: %w", err)
	}
	userData, err := hex.DecodeString(claims.UserData)
	if err != nil || len(userData) != AzureUserDataSize {
		return nil, nil, attestation.Invalidf("azure runtime claims user-data is not the hex encoding of %d bytes", AzureUserDataSize)
	}
	return &attestation.AzureRuntime{
		Keys:            claims.Keys,
		VMConfiguration: claims.VMConfiguration,
	}, userData, nil
}
