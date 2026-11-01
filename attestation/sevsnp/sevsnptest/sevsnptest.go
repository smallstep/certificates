//go:build unix

// go-sev-guest's testing package, which signs reports with test-only AMD keys,
// imports golang.org/x/sys/unix.

// Package sevsnptest signs AMD SEV-SNP attestation reports with test-only AMD
// keys, for tests of code that verifies them.
package sevsnptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	sevtest "github.com/google/go-sev-guest/testing"
)

// Signer signs SEV-SNP reports with test-only AMD keys.
type Signer struct {
	signer *sevtest.AmdSigner
	// Roots is the signer's ARK, ASK and ASVK as PEM, to configure as the
	// trusted roots.
	Roots []byte
	// CertTable is the signer's certificate table, as an extended report
	// returns it.
	CertTable []byte
}

// New returns a signer with go-sev-guest's fixed test keys, or, with otherVCEK,
// with a VCEK of its own under the same ARK and ASK.
func New(t testing.TB, otherVCEK bool) *Signer {
	t.Helper()
	keys := sevtest.DefaultAmdKeys()
	if otherVCEK {
		vcek, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys.Vcek = vcek
	}
	created := time.Now().Add(-time.Hour)
	b := &sevtest.AmdSignerBuilder{
		Keys:             keys,
		ProductName:      kds.ProductName(abi.DefaultSevProduct()),
		CSPID:            "go-sev-guest",
		ArkCreationTime:  created,
		AskCreationTime:  created,
		AsvkCreationTime: created,
		VcekCreationTime: created,
		VlekCreationTime: created,
	}
	signer, err := b.TestOnlyCertChain()
	if err != nil {
		t.Fatal(err)
	}
	certs, err := signer.CertTableBytes()
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{
		signer:    signer,
		Roots:     pemEncode(signer.Ark, signer.Ask, signer.Asvk),
		CertTable: certs,
	}
}

// Ark returns the signer's ARK.
func (s *Signer) Ark() *x509.Certificate { return s.signer.Ark }

// Ask returns the signer's ASK.
func (s *Signer) Ask() *x509.Certificate { return s.signer.Ask }

// Asvk returns the signer's ASVK.
func (s *Signer) Asvk() *x509.Certificate { return s.signer.Asvk }

// Report returns a signed version 3 report with the given report data, from a
// guest whose policy allows debugging if debug is set.
func (s *Signer) Report(t testing.TB, reportData []byte, debug bool) []byte {
	t.Helper()
	return s.EditedReport(t, reportData, debug, nil)
}

// EditedReport is Report with edit, if not nil, applied to the report's bytes
// before they are signed.
func (s *Signer) EditedReport(t testing.TB, reportData []byte, debug bool, edit func(report []byte)) []byte {
	t.Helper()
	raw := sevtest.CreateRawReport(&sevtest.TestReportOptions{
		ReportData: reportData,
		Version:    3,
		FMS:        abi.MaskedCpuid1EaxFromSevProduct(abi.DefaultSevProduct()),
	})
	// The report is the start of the response CreateRawReport fills.
	report := append([]byte(nil), raw[:abi.ReportSize]...)
	// CreateRawReport's policy allows debugging.
	binary.LittleEndian.PutUint64(report[0x08:0x10], abi.SnpPolicyToBytes(abi.SnpPolicy{Debug: debug, SMT: true}))
	if edit != nil {
		edit(report)
	}
	r, sig, err := s.signer.Sign(abi.SignedComponent(report))
	if err != nil {
		t.Fatal(err)
	}
	if err := abi.SetSignature(r, sig, report); err != nil {
		t.Fatal(err)
	}
	return report
}

// CRL returns a revocation list, signed by the signer's ARK, that revokes
// nothing, and the URL go-sev-guest fetches it from when it checks
// revocations.
func (s *Signer) CRL(t testing.TB) (url string, crl []byte) {
	t.Helper()
	if len(s.signer.Ask.CRLDistributionPoints) == 0 {
		t.Fatal("the test ASK has no CRL distribution point")
	}
	now := time.Now()
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:             big.NewInt(1),
		ThisUpdate:         now.Add(-time.Hour),
		NextUpdate:         now.Add(time.Hour),
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
	}, s.signer.Ark, s.signer.Keys.Ark)
	if err != nil {
		t.Fatal(err)
	}
	return s.signer.Ask.CRLDistributionPoints[0], crl
}

func pemEncode(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}
