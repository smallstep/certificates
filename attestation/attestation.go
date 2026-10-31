// Package attestation holds the results of verified remote attestation
// evidence, shared by the verifiers in its subpackages and by the code that
// stores them, sends them to webhooks and gives them to certificate templates.
//
// The verifiers return what the evidence binds, for example the report data of
// a TDX quote or the nonces of an attestation token, and leave the binding rule
// to their callers, since each protocol binds evidence differently.
//
// This package has no dependencies outside the standard library, so packages
// that only describe results, such as webhook, can import it without pulling in
// the verifiers' dependencies.
package attestation

import (
	"errors"
	"fmt"
)

// Format is the format of attestation evidence.
type Format string

const (
	// FormatTDX is an Intel TDX quote.
	FormatTDX Format = "tdx"
	// FormatSEVSNP is an AMD SEV-SNP attestation report.
	FormatSEVSNP Format = "sev-snp"
	// FormatConfidentialSpace is a Google Cloud Attestation token for a
	// Confidential Space workload.
	FormatConfidentialSpace Format = "confidential-space"
)

// Validate returns an error if the format is not supported.
func (f Format) Validate() error {
	switch f {
	case FormatTDX, FormatSEVSNP, FormatConfidentialSpace:
		return nil
	default:
		return fmt.Errorf("attestation format %q is not supported", f)
	}
}

// Result is verified attestation evidence. Binary values are hex encoded.
// Exactly one of TDX, SEVSNP and ConfidentialSpace is set, as Format says.
type Result struct {
	// Format is the format of the evidence.
	Format Format `json:"format"`
	// MediaType is the media type the evidence was sent with, if any.
	MediaType string `json:"mediaType,omitempty"`
	// Evidence is the evidence as it was sent, so that a relying party can
	// verify it again.
	Evidence          []byte             `json:"evidence,omitempty"`
	TDX               *TDX               `json:"tdx,omitempty"`
	SEVSNP            *SEVSNP            `json:"sevSnp,omitempty"`
	ConfidentialSpace *ConfidentialSpace `json:"confidentialSpace,omitempty"`
}

// TDX holds the measurements and attributes of a verified Intel TDX quote.
type TDX struct {
	MRTD          string   `json:"mrtd"`
	RTMRs         []string `json:"rtmrs"`
	MRSeam        string   `json:"mrSeam"`
	MRConfigID    string   `json:"mrConfigId"`
	MROwner       string   `json:"mrOwner"`
	MROwnerConfig string   `json:"mrOwnerConfig"`
	TDAttributes  string   `json:"tdAttributes"`
	XFAM          string   `json:"xfam"`
	TEETCBSVN     string   `json:"teeTcbSvn"`
	// FMSPC identifies the platform's family, model and configuration in
	// the PCK certificate.
	FMSPC string `json:"fmspc"`
	// TCBStatus is the TDX TCB status from Intel's collateral, for example
	// UpToDate.
	TCBStatus string `json:"tcbStatus,omitempty"`
}

// SEVSNP holds the measurements and attributes of a verified AMD SEV-SNP
// attestation report.
type SEVSNP struct {
	Measurement     string `json:"measurement"`
	HostData        string `json:"hostData"`
	IDKeyDigest     string `json:"idKeyDigest"`
	AuthorKeyDigest string `json:"authorKeyDigest"`
	FamilyID        string `json:"familyId"`
	ImageID         string `json:"imageId"`
	GuestSVN        uint32 `json:"guestSvn"`
	Policy          uint64 `json:"policy"`
	VMPL            uint32 `json:"vmpl"`
	CurrentTCB      uint64 `json:"currentTcb"`
	ReportedTCB     uint64 `json:"reportedTcb"`
	LaunchTCB       uint64 `json:"launchTcb"`
	ChipID          string `json:"chipId"`
	// SigningKey is the key that signed the report, "vcek" or "vlek".
	SigningKey string `json:"signingKey"`
	// Product is the AMD product line, for example Milan.
	Product string `json:"product"`
}

// ConfidentialSpace holds the claims of a verified Google Cloud Attestation
// token for a Confidential Space workload.
type ConfidentialSpace struct {
	// Claims are all the claims of the token.
	Claims map[string]any `json:"claims"`
	// SignerSerialNumber is the serial number of the certificate that signed
	// the token.
	SignerSerialNumber string `json:"signerSerialNumber,omitempty"`
}

// ErrInvalidEvidence is matched, with errors.Is, by the errors of evidence that
// is malformed, fails verification or does not meet a verifier's requirements.
// Other errors, such as a failure to fetch collateral, are the verifier's.
var ErrInvalidEvidence = errors.New("invalid attestation evidence")

type invalidError struct {
	err error
}

func (e *invalidError) Error() string { return e.err.Error() }

func (e *invalidError) Unwrap() []error { return []error{ErrInvalidEvidence, e.err} }

// Invalid marks err as an error of the evidence, so that it matches
// ErrInvalidEvidence. It returns nil if err is nil.
func Invalid(err error) error {
	if err == nil {
		return nil
	}
	return &invalidError{err: err}
}

// Invalidf formats an error of the evidence, which matches ErrInvalidEvidence.
func Invalidf(format string, args ...any) error {
	return &invalidError{err: fmt.Errorf(format, args...)}
}
