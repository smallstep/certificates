// Package sevsnp verifies AMD SEV-SNP attestation reports.
package sevsnp

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	sevverify "github.com/google/go-sev-guest/verify"
	sevtrust "github.com/google/go-sev-guest/verify/trust"

	"github.com/smallstep/certificates/attestation"
)

// ReportDataSize is the size of an SEV-SNP report's report data.
const ReportDataSize = 64

// Verifier verifies AMD SEV-SNP attestation reports: the report's signature by
// the chip's VCEK or the provider's VLEK, and that key's chain through the ASK
// or ASVK to the ARK of the product line. Certificates the workload does not
// send are fetched from AMD's key distribution service, as are the revocation
// lists. Reports from guests whose policy allows debugging are refused. The TCB
// versions are reported, not checked against a minimum.
type Verifier struct {
	// roots are the ARK, ASK and ASVK certificates to trust per product
	// line: the configured ones, or AMD's.
	roots  map[string][]*sevtrust.AMDRootCerts
	getter sevtrust.HTTPSGetter
	// checkRevocations is always true outside of tests.
	checkRevocations bool
	now              func() time.Time
}

// amdRoots are AMD's ARK, ASK and ASVK certificates for every product line,
// from the VCEK and VLEK bundles embedded in go-sev-guest.
var amdRoots = sync.OnceValues(func() (map[string][]*sevtrust.AMDRootCerts, error) {
	return parseRoots(bytes.Join([][]byte{
		sevtrust.AskArkMilanVcekBytes, sevtrust.AskArkMilanVlekBytes,
		sevtrust.AskArkGenoaVcekBytes, sevtrust.AskArkGenoaVlekBytes,
		sevtrust.AskArkTurinVcekBytes, sevtrust.AskArkTurinVlekBytes,
	}, []byte("\n")))
})

// New returns a Verifier that fetches certificates and revocation lists with
// the given getter. If roots, a PEM bundle of ARK, ASK and ASVK certificates, is
// not empty, it replaces AMD's roots.
func New(roots []byte, getter sevtrust.HTTPSGetter) (*Verifier, error) {
	v := &Verifier{
		getter:           getter,
		checkRevocations: true,
		now:              time.Now,
	}
	// The roots are always passed to go-sev-guest. Before v0.15.0, without
	// them it took the ARK and ASK from the evidence's own certificate table
	// and, because its embedded roots hold no AMD SEV format certificates to
	// cross-check them with, trusted whatever ARK the workload sent.
	var err error
	if len(roots) > 0 {
		v.roots, err = parseRoots(roots)
	} else {
		v.roots, err = amdRoots()
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// parseRoots reads the ARK, ASK and ASVK certificates in a PEM bundle and
// groups them by product line, which AMD names in their common names: ARK-Milan,
// SEV-Milan and SEV-VLEK-Milan for Milan. Each product line needs its ARK and at
// least one of its ASK and ASVK.
func parseRoots(data []byte) (map[string][]*sevtrust.AMDRootCerts, error) {
	certs := make(map[string]*sevtrust.ProductCerts)
	line := func(name string) *sevtrust.ProductCerts {
		if certs[name] == nil {
			certs[name] = new(sevtrust.ProductCerts)
		}
		return certs[name]
	}
	for rest := data; len(rest) > 0; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing the sev-snp roots: %w", err)
		}
		switch cn := cert.Subject.CommonName; {
		case strings.HasPrefix(cn, "ARK-"):
			line(strings.TrimPrefix(cn, "ARK-")).Ark = cert
		case strings.HasPrefix(cn, "SEV-VLEK-"):
			line(strings.TrimPrefix(cn, "SEV-VLEK-")).Asvk = cert
		case strings.HasPrefix(cn, "SEV-"):
			line(strings.TrimPrefix(cn, "SEV-")).Ask = cert
		default:
			return nil, fmt.Errorf("sev-snp roots: %q is not an AMD ARK, ASK or ASVK", cn)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found in the sev-snp roots")
	}
	roots := make(map[string][]*sevtrust.AMDRootCerts, len(certs))
	for name, pc := range certs {
		if pc.Ark == nil || (pc.Ask == nil && pc.Asvk == nil) {
			return nil, fmt.Errorf("sev-snp roots: product line %s needs its ARK and its ASK or ASVK", name)
		}
		r := sevtrust.AMDRootCertsProduct(name)
		r.ProductCerts = pc
		roots[name] = []*sevtrust.AMDRootCerts{r}
	}
	return roots, nil
}

// Verify verifies an SEV-SNP attestation report, with the certificate table an
// extended report returns if it is not empty, and returns the report's
// measurements and its report data. Errors of the report match
// attestation.ErrInvalidEvidence; a failure to fetch certificates or revocation
// lists does not.
func (v *Verifier) Verify(ctx context.Context, rawReport, certTable []byte) (*attestation.SEVSNP, []byte, error) {
	report, err := abi.ReportToProto(rawReport)
	if err != nil {
		return nil, nil, attestation.Invalidf("error parsing sev-snp report: %w", err)
	}
	att := &spb.Attestation{Report: report}
	if len(certTable) > 0 {
		var table abi.CertTable
		if err := table.Unmarshal(certTable); err != nil {
			return nil, nil, attestation.Invalidf("error parsing sev-snp certificate table: %w", err)
		}
		att.CertificateChain = table.Proto()
	}

	getter := &recordingGetter{getter: v.getter}
	opts := &sevverify.Options{
		CheckRevocations: v.checkRevocations,
		Getter:           getter,
		Now:              v.now(),
		TrustedRoots:     v.roots,
	}
	if err := sevverify.SnpAttestationContext(ctx, att, opts); err != nil {
		if getter.failed.Load() {
			return nil, nil, fmt.Errorf("error fetching sev-snp certificates: %w", err)
		}
		return nil, nil, attestation.Invalidf("error verifying sev-snp report: %w", err)
	}

	policy, err := abi.ParseSnpPolicy(report.GetPolicy())
	if err != nil {
		return nil, nil, attestation.Invalidf("error parsing sev-snp guest policy: %w", err)
	}
	if policy.Debug {
		return nil, nil, attestation.Invalidf("sev-snp report is from a guest whose policy allows debugging")
	}
	signer, err := abi.ParseSignerInfo(report.GetSignerInfo())
	if err != nil {
		return nil, nil, attestation.Invalidf("error parsing sev-snp signer info: %w", err)
	}
	product := kds.ProductLine(att.GetProduct())
	if fms := report.GetCpuid1EaxFms(); fms != 0 {
		product = kds.ProductLineFromFms(fms)
	}

	reportData := report.GetReportData()
	if len(reportData) != ReportDataSize {
		return nil, nil, attestation.Invalidf("sev-snp report data has %d bytes, not %d", len(reportData), ReportDataSize)
	}
	return &attestation.SEVSNP{
		Measurement:     hex.EncodeToString(report.GetMeasurement()),
		HostData:        hex.EncodeToString(report.GetHostData()),
		IDKeyDigest:     hex.EncodeToString(report.GetIdKeyDigest()),
		AuthorKeyDigest: hex.EncodeToString(report.GetAuthorKeyDigest()),
		FamilyID:        hex.EncodeToString(report.GetFamilyId()),
		ImageID:         hex.EncodeToString(report.GetImageId()),
		GuestSVN:        report.GetGuestSvn(),
		Policy:          report.GetPolicy(),
		VMPL:            report.GetVmpl(),
		CurrentTCB:      report.GetCurrentTcb(),
		ReportedTCB:     report.GetReportedTcb(),
		LaunchTCB:       report.GetLaunchTcb(),
		ChipID:          hex.EncodeToString(report.GetChipId()),
		SigningKey:      strings.ToLower(signer.SigningKey.String()),
		Product:         product,
	}, reportData, nil
}

// recordingGetter records whether a fetch failed, so that a report that cannot
// be verified because a service is unreachable is not called invalid.
type recordingGetter struct {
	getter sevtrust.HTTPSGetter
	failed atomic.Bool
}

func (g *recordingGetter) Get(url string) ([]byte, error) {
	body, err := g.getter.Get(url)
	if err != nil {
		g.failed.Store(true)
	}
	return body, err
}

func (g *recordingGetter) GetContext(ctx context.Context, url string) ([]byte, error) {
	cg, ok := g.getter.(sevtrust.ContextHTTPSGetter)
	if !ok {
		return g.Get(url)
	}
	body, err := cg.GetContext(ctx, url)
	if err != nil {
		g.failed.Store(true)
	}
	return body, err
}
