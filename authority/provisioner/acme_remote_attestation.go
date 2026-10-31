package provisioner

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"slices"
	"time"

	"github.com/smallstep/certificates/attestation"
	"github.com/smallstep/certificates/attestation/cmw"
	"github.com/smallstep/certificates/attestation/collateral"
	"github.com/smallstep/certificates/attestation/confidentialspace"
	"github.com/smallstep/certificates/attestation/sevsnp"
	"github.com/smallstep/certificates/attestation/tdx"
	"github.com/smallstep/certificates/attestation/tsm"
)

// RemoteAttestationBindingSize is the size of the binding the evidence of a
// remote-attest-01 challenge carries first: SHA-256 of the challenge's key
// authorization followed by the DER SubjectPublicKeyInfo of the key to be
// certified.
const RemoteAttestationBindingSize = sha256.Size

// RemoteAttestationClaimNonceSize is the size of the relying party's nonce a
// TDX quote or an SEV-SNP report carries after the binding, in the second half
// of its report data.
const RemoteAttestationClaimNonceSize = 32

// remoteAttestationTimeout bounds the verification of the evidence of a
// remote-attest-01 challenge, which may fetch collateral from Intel's and AMD's
// services.
const remoteAttestationTimeout = 10 * time.Second

// ACMERemoteAttestation configures the remote-attest-01 challenge of an ACME
// provisioner (draft-ietf-acme-rats). The challenge is enabled through the
// provisioner's challenges; this configures it.
type ACMERemoteAttestation struct {
	// Require adds a remote-attestation identifier to every order that does
	// not have one, so that every certificate needs attestation.
	Require bool `json:"require,omitempty"`
	// Formats are the evidence formats accepted: tdx, sev-snp and
	// confidential-space. It defaults to tdx and sev-snp, and to
	// confidential-space too if ConfidentialSpace is set.
	Formats []attestation.Format `json:"formats,omitempty"`
	// ClaimsHint is sent to clients as the challenge's attestClaimsHint.
	ClaimsHint []string `json:"claimsHint,omitempty"`
	// TDXRoots is a PEM bundle that replaces Intel's SGX root CA.
	TDXRoots []byte `json:"tdxRoots,omitempty"`
	// SEVSNPRoots is a PEM bundle of ARK, ASK and ASVK certificates that
	// replaces AMD's.
	SEVSNPRoots []byte `json:"sevSnpRoots,omitempty"`
	// ConfidentialSpace configures the confidential-space format.
	ConfidentialSpace *ACMEConfidentialSpace `json:"confidentialSpace,omitempty"`
}

// ACMEConfidentialSpace configures the confidential-space format of the
// remote-attest-01 challenge, which accepts the PKI tokens Google Cloud
// Attestation issues to Confidential Space workloads.
type ACMEConfidentialSpace struct {
	// Roots is a PEM bundle that replaces the root of Google Cloud
	// Attestation's PKI, which step-ca embeds.
	Roots []byte `json:"roots,omitempty"`
	// Audience is the audience the token must have been requested for. It
	// defaults to the ACME directory URL.
	Audience string `json:"audience,omitempty"`
	// MaxTokenAge is the maximum age of the token. It defaults to 5 minutes.
	MaxTokenAge *Duration `json:"maxTokenAge,omitempty"`
	// Expectations are the values the attested workload must match.
	confidentialspace.Expectations
}

// IsRequired reports whether every order needs a remote-attestation
// identifier.
func (o *ACMERemoteAttestation) IsRequired() bool {
	return o != nil && o.Require
}

// GetClaimsHint returns the claims hint sent to clients.
func (o *ACMERemoteAttestation) GetClaimsHint() []string {
	if o == nil {
		return nil
	}
	return o.ClaimsHint
}

// remoteAttestationVerifier verifies the evidence of remote-attest-01
// challenges with the provisioner's configuration.
type remoteAttestationVerifier struct {
	formats     []attestation.Format
	tdx         tdxVerifier
	sevsnp      sevSNPVerifier
	csRoots     *x509.CertPool
	csAudience  string
	csMaxAge    time.Duration
	csExpecting *confidentialspace.Expectations
	now         func() time.Time
}

// tdxVerifier is implemented by *tdx.Verifier. Tests replace it, since a real
// quote's report data cannot be chosen and a test quote cannot pass Intel's
// collateral.
type tdxVerifier interface {
	Verify(ctx context.Context, quote []byte) (*attestation.TDX, []byte, error)
}

// sevSNPVerifier is implemented by *sevsnp.Verifier.
type sevSNPVerifier interface {
	Verify(ctx context.Context, report, certTable []byte) (*attestation.SEVSNP, []byte, error)
}

// initializeRemoteAttestation validates the remote attestation options and
// creates the verifiers. It returns early if remote-attest-01 is not enabled.
func (p *ACME) initializeRemoteAttestation() error {
	if !slices.ContainsFunc(p.Challenges, func(c ACMEChallenge) bool {
		return ACMEChallenge(c.String()) == REMOTE_ATTEST_01
	}) {
		return nil
	}

	o := p.RemoteAttestation
	if o == nil {
		o = &ACMERemoteAttestation{}
	}
	if slices.Contains(o.ClaimsHint, "") {
		return errors.New("claimsHint cannot contain empty values")
	}

	v := &remoteAttestationVerifier{
		formats: o.Formats,
		now:     time.Now,
	}
	if len(v.formats) == 0 {
		v.formats = []attestation.Format{attestation.FormatTDX, attestation.FormatSEVSNP}
		if o.ConfidentialSpace != nil {
			v.formats = append(v.formats, attestation.FormatConfidentialSpace)
		}
	}

	getter := collateral.New(p.ctl.GetHTTPClient())
	for _, f := range v.formats {
		if err := f.Validate(); err != nil {
			return err
		}
		var err error
		switch f {
		case attestation.FormatTDX:
			v.tdx, err = tdx.New(o.TDXRoots, collateral.TDX{Getter: getter})
		case attestation.FormatSEVSNP:
			v.sevsnp, err = sevsnp.New(o.SEVSNPRoots, collateral.SEVSNP{Getter: getter})
		case attestation.FormatConfidentialSpace:
			err = v.initializeConfidentialSpace(o.ConfidentialSpace)
		}
		if err != nil {
			return fmt.Errorf("error initializing the %s format: %w", f, err)
		}
	}

	p.remoteAttestation = v
	return nil
}

func (v *remoteAttestationVerifier) initializeConfidentialSpace(o *ACMEConfidentialSpace) error {
	if o == nil {
		o = &ACMEConfidentialSpace{}
	}
	v.csRoots = confidentialspace.Roots()
	if len(o.Roots) > 0 {
		v.csRoots = x509.NewCertPool()
		if !v.csRoots.AppendCertsFromPEM(o.Roots) {
			return errors.New("no certificates found in confidentialSpace.roots")
		}
	}
	if o.MaxTokenAge != nil {
		if o.MaxTokenAge.Duration <= 0 {
			return errors.New("confidentialSpace.maxTokenAge must be greater than 0")
		}
		v.csMaxAge = o.MaxTokenAge.Duration
	}
	if err := o.Expectations.Validate(); err != nil {
		return fmt.Errorf("confidentialSpace: %w", err)
	}
	v.csAudience = o.Audience
	v.csExpecting = &o.Expectations
	return nil
}

// GetRemoteAttestation returns the remote attestation options.
func (p *ACME) GetRemoteAttestation() *ACMERemoteAttestation {
	return p.RemoteAttestation
}

// VerifyRemoteAttestation verifies the evidence of a remote-attest-01
// challenge, a CMW record, and returns it with the data it binds: first the
// RemoteAttestationBindingSize bytes of the binding, then, for a TDX quote or an
// SEV-SNP report, the relying party's RemoteAttestationClaimNonceSize bytes.
//
//   - For a TDX quote or an SEV-SNP report, sent as a configfs-tsm report
//     (application/vnd.veraison.tsm-report+json or +cbor), its 64 bytes of
//     report data.
//   - For a Confidential Space token (application/eat+jwt or application/jwt),
//     its first eat_nonce value, the base64url encoding, without padding, of 32
//     bytes. Its other nonces are the relying party's and stay in the claims.
//     The token must have been requested for the configured audience, or else
//     for the given default audience.
//
// The caller checks what the binding must be. Errors of the evidence match
// attestation.ErrInvalidEvidence.
func (p *ACME) VerifyRemoteAttestation(ctx context.Context, r *cmw.Record, defaultAudience string) (*attestation.Result, []byte, error) {
	v := p.remoteAttestation
	if v == nil {
		return nil, nil, errors.New("remote-attest-01 is not enabled")
	}
	ctx, cancel := context.WithTimeout(ctx, remoteAttestationTimeout)
	defer cancel()

	var (
		res   *attestation.Result
		bound []byte
		size  int
		err   error
	)
	switch {
	case tsm.IsMediaType(r.MediaType):
		res, bound, err = v.verifyTSMReport(ctx, r)
		size = RemoteAttestationBindingSize + RemoteAttestationClaimNonceSize
	case isJWTMediaType(r.MediaType):
		res, bound, err = v.verifyConfidentialSpace(r, defaultAudience)
		size = RemoteAttestationBindingSize
	default:
		return nil, nil, attestation.Invalidf("evidence media type %q is not supported", r.MediaType)
	}
	if err != nil {
		return nil, nil, err
	}
	if len(bound) != size {
		return nil, nil, attestation.Invalidf("evidence binds %d bytes, not %d", len(bound), size)
	}
	res.MediaType = r.MediaType
	res.Evidence = r.Value
	return res, bound, nil
}

func (v *remoteAttestationVerifier) enabled(f attestation.Format) error {
	if !slices.Contains(v.formats, f) {
		return attestation.Invalidf("attestation format %s is not enabled", f)
	}
	return nil
}

func (v *remoteAttestationVerifier) verifyTSMReport(ctx context.Context, r *cmw.Record) (*attestation.Result, []byte, error) {
	if r.Indicator != 0 && !r.Indicator.Has(cmw.Evidence) {
		return nil, nil, attestation.Invalidf("a tsm report must be indicated as evidence")
	}
	report, err := tsm.Parse(r.MediaType, r.Value)
	if err != nil {
		return nil, nil, err
	}

	switch report.Provider {
	case tsm.ProviderTDX:
		if err := v.enabled(attestation.FormatTDX); err != nil {
			return nil, nil, err
		}
		if len(report.AuxBlob) > 0 {
			return nil, nil, attestation.Invalidf("a tdx tsm report does not take an auxblob")
		}
		res, reportData, err := v.tdx.Verify(ctx, report.OutBlob)
		if err != nil {
			return nil, nil, err
		}
		return &attestation.Result{Format: attestation.FormatTDX, TDX: res}, reportData, nil
	case tsm.ProviderSEVSNP:
		if err := v.enabled(attestation.FormatSEVSNP); err != nil {
			return nil, nil, err
		}
		res, reportData, err := v.sevsnp.Verify(ctx, report.OutBlob, report.AuxBlob)
		if err != nil {
			return nil, nil, err
		}
		return &attestation.Result{Format: attestation.FormatSEVSNP, SEVSNP: res}, reportData, nil
	default:
		return nil, nil, attestation.Invalidf("tsm report provider %q is not supported", report.Provider)
	}
}

func (v *remoteAttestationVerifier) verifyConfidentialSpace(r *cmw.Record, defaultAudience string) (*attestation.Result, []byte, error) {
	if err := v.enabled(attestation.FormatConfidentialSpace); err != nil {
		return nil, nil, err
	}
	if r.Indicator != 0 && !r.Indicator.Has(cmw.AttestationResults) {
		return nil, nil, attestation.Invalidf("an attestation token must be indicated as an attestation result")
	}
	audience := v.csAudience
	if audience == "" {
		audience = defaultAudience
	}
	tok, err := confidentialspace.Verify(string(r.Value), confidentialspace.Options{
		Roots:       v.csRoots,
		Audience:    audience,
		MaxTokenAge: v.csMaxAge,
		MinNonces:   1,
		Now:         v.now(),
	})
	if err != nil {
		return nil, nil, err
	}
	if err := v.csExpecting.Check(&tok.Claims); err != nil {
		return nil, nil, err
	}

	bound, err := base64.RawURLEncoding.DecodeString(tok.Claims.EATNonce[0])
	if err != nil || len(bound) != RemoteAttestationBindingSize {
		return nil, nil, attestation.Invalidf("eat_nonce[0] is not the base64url encoding of %d bytes", RemoteAttestationBindingSize)
	}
	return &attestation.Result{
		Format:            attestation.FormatConfidentialSpace,
		ConfidentialSpace: tok.Result(),
	}, bound, nil
}

// isJWTMediaType reports whether mediaType is application/jwt or
// application/eat+jwt, with or without parameters.
func isJWTMediaType(mediaType string) bool {
	mt, _, err := mime.ParseMediaType(mediaType)
	return err == nil && (mt == "application/jwt" || mt == "application/eat+jwt")
}
