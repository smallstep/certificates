// Package tdx verifies Intel TDX quotes.
package tdx

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"

	"github.com/smallstep/certificates/attestation"
)

// ReportDataSize is the size of a TDX quote's report data.
const ReportDataSize = 64

// attributesDebug is the DEBUG bit of a TD's TD_ATTRIBUTES.
const attributesDebug = 1 << 0

// Verifier verifies Intel TDX quotes: the quote's signature by its attestation
// key, the quoting enclave's report, the PCK certificate chain to Intel's SGX
// root CA, and, with collateral from Intel's provisioning certification
// service, the revocation of the chain and the TCB status of the platform and
// the quoting enclave. go-tdx-guest refuses a TCB status other than UpToDate.
// Quotes from debug trust domains are refused.
type Verifier struct {
	// roots replaces Intel's SGX root CA, embedded in go-tdx-guest, if set.
	roots  *x509.CertPool
	getter tdxtrust.HTTPSGetter
	// getCollateral is always true outside of tests: without collateral the
	// TCB status and the revocation of the PCK chain are not checked.
	getCollateral bool
	now           func() time.Time
}

// New returns a Verifier that fetches collateral with the given getter. If
// roots, a PEM bundle, is not empty, it replaces Intel's root.
func New(roots []byte, getter tdxtrust.HTTPSGetter) (*Verifier, error) {
	v := &Verifier{
		getter:        getter,
		getCollateral: true,
		now:           time.Now,
	}
	if len(roots) > 0 {
		v.roots = x509.NewCertPool()
		if !v.roots.AppendCertsFromPEM(roots) {
			return nil, errors.New("no certificates found in the tdx roots")
		}
	}
	return v, nil
}

// Verify verifies a version 4 TDX quote and returns its measurements and its
// report data. Errors of the quote match attestation.ErrInvalidEvidence; a
// failure to fetch collateral does not.
func (v *Verifier) Verify(ctx context.Context, rawQuote []byte) (*attestation.TDX, []byte, error) {
	q, err := abi.QuoteToProto(rawQuote)
	if err != nil {
		return nil, nil, attestation.Invalidf("error parsing tdx quote: %w", err)
	}
	quote, ok := q.(*tdxpb.QuoteV4)
	if !ok {
		return nil, nil, attestation.Invalidf("unsupported tdx quote type %T", q)
	}

	getter := &recordingGetter{getter: v.getter}
	now := v.now()
	opts := &tdxverify.Options{
		CheckRevocations: v.getCollateral,
		GetCollateral:    v.getCollateral,
		Getter:           getter,
		TrustedRoots:     v.roots,
		Now: &tdxverify.TimeSet{
			PckCertChain: now,
			TcbInfo:      now,
			QeIdentity:   now,
			PckCrl:       now,
			RootCaCrl:    now,
		},
	}
	if err := tdxverify.TdxQuoteContext(ctx, quote, opts); err != nil {
		if getter.failed.Load() {
			return nil, nil, fmt.Errorf("error fetching tdx collateral: %w", err)
		}
		return nil, nil, attestation.Invalidf("error verifying tdx quote: %w", err)
	}

	body := quote.GetTdQuoteBody()
	if attrs := body.GetTdAttributes(); len(attrs) != 8 || binary.LittleEndian.Uint64(attrs)&attributesDebug != 0 {
		return nil, nil, attestation.Invalidf("tdx quote is from a debug trust domain")
	}

	result := &attestation.TDX{
		MRTD:          hex.EncodeToString(body.GetMrTd()),
		MRSeam:        hex.EncodeToString(body.GetMrSeam()),
		MRConfigID:    hex.EncodeToString(body.GetMrConfigId()),
		MROwner:       hex.EncodeToString(body.GetMrOwner()),
		MROwnerConfig: hex.EncodeToString(body.GetMrOwnerConfig()),
		TDAttributes:  hex.EncodeToString(body.GetTdAttributes()),
		XFAM:          hex.EncodeToString(body.GetXfam()),
		TEETCBSVN:     hex.EncodeToString(body.GetTeeTcbSvn()),
	}
	for _, rtmr := range body.GetRtmrs() {
		result.RTMRs = append(result.RTMRs, hex.EncodeToString(rtmr))
	}
	chain, err := tdxverify.ExtractChainFromQuote(quote)
	if err != nil {
		return nil, nil, attestation.Invalidf("error reading tdx pck certificate chain: %w", err)
	}
	exts, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		return nil, nil, attestation.Invalidf("error reading tdx pck certificate extensions: %w", err)
	}
	result.FMSPC = exts.FMSPC
	if v.getCollateral {
		tcb, _, err := tdxverify.SupportedTcbLevelsFromCollateral(quote, opts)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading tdx tcb status: %w", err)
		}
		result.TCBStatus = string(tcb.TcbStatus)
	}

	reportData := body.GetReportData()
	if len(reportData) != ReportDataSize {
		return nil, nil, attestation.Invalidf("tdx quote report data has %d bytes, not %d", len(reportData), ReportDataSize)
	}
	return result, reportData, nil
}

// recordingGetter records whether a fetch failed, so that a quote that cannot
// be verified because a service is unreachable is not called invalid.
type recordingGetter struct {
	getter tdxtrust.HTTPSGetter
	failed atomic.Bool
}

func (g *recordingGetter) Get(url string) (map[string][]string, []byte, error) {
	header, body, err := g.getter.Get(url)
	if err != nil {
		g.failed.Store(true)
	}
	return header, body, err
}

func (g *recordingGetter) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	cg, ok := g.getter.(tdxtrust.ContextHTTPSGetter)
	if !ok {
		return g.Get(url)
	}
	header, body, err := cg.GetContext(ctx, url)
	if err != nil {
		g.failed.Store(true)
	}
	return header, body, err
}
