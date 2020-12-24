package softcas

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/kms"
	kmsapi "github.com/smallstep/certificates/kms/apiv1"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
)

var (
	testIntermediatePem = `-----BEGIN CERTIFICATE-----
MIIBPjCB8aADAgECAhAk4aPIlsVvQg3gveApc3mIMAUGAytlcDAeMRwwGgYDVQQD
ExNTbWFsbHN0ZXAgVW5pdCBUZXN0MB4XDTIwMDkxNjAyMDgwMloXDTMwMDkxNDAy
MDgwMlowHjEcMBoGA1UEAxMTU21hbGxzdGVwIFVuaXQgVGVzdDAqMAUGAytlcAMh
ANLs3JCzECR29biut0NDsaLnh0BGij5eJx6VkdJPfS/ko0UwQzAOBgNVHQ8BAf8E
BAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUup5qpZFMAFdgK7RB
xNzmUaQM8YwwBQYDK2VwA0EAAwcW25E/6bchyKwp3RRK1GXiPMDCc+hsTJxuOLWy
YM7ga829dU8X4pRcEEAcBndqCED/502excjEK7U9vCkFCg==
-----END CERTIFICATE-----`

	testIntermediateKeyPem = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEII9ZckcrDKlbhZKR0jp820Uz6mOMLFsq2JhI+Tl7WJwH
-----END PRIVATE KEY-----`
)

var (
	errTest      = errors.New("test error")
	testIssuer   = mustIssuer()
	testSigner   = mustSigner()
	testTemplate = &x509.Certificate{
		Subject:      pkix.Name{CommonName: "test.smallstep.com"},
		DNSNames:     []string{"test.smallstep.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		PublicKey:    testSigner.Public(),
		SerialNumber: big.NewInt(1234),
	}
	testRootTemplate = &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		PublicKey:             testSigner.Public(),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SerialNumber:          big.NewInt(1234),
	}
	testIntermediateTemplate = &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		PublicKey:             testSigner.Public(),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SerialNumber:          big.NewInt(1234),
	}
	testNow                        = time.Now()
	testSignedTemplate             = mustSign(testTemplate, testIssuer, testNow, testNow.Add(24*time.Hour))
	testSignedRootTemplate         = mustSign(testRootTemplate, testRootTemplate, testNow, testNow.Add(24*time.Hour))
	testSignedIntermediateTemplate = mustSign(testIntermediateTemplate, testSignedRootTemplate, testNow, testNow.Add(24*time.Hour))
)

type mockKeyManager struct {
	signer          crypto.Signer
	errGetPublicKey error
	errCreateKey    error
	errCreatesigner error
	errClose        error
}

func (m *mockKeyManager) GetPublicKey(req *kmsapi.GetPublicKeyRequest) (crypto.PublicKey, error) {
	signer := testSigner
	if m.signer != nil {
		signer = m.signer
	}
	return signer.Public(), m.errGetPublicKey
}

func (m *mockKeyManager) CreateKey(req *kmsapi.CreateKeyRequest) (*kmsapi.CreateKeyResponse, error) {
	signer := testSigner
	if m.signer != nil {
		signer = m.signer
	}
	return &kmsapi.CreateKeyResponse{
		PrivateKey: signer,
		PublicKey:  signer.Public(),
	}, m.errCreateKey
}

func (m *mockKeyManager) CreateSigner(req *kmsapi.CreateSignerRequest) (crypto.Signer, error) {
	signer := testSigner
	if m.signer != nil {
		signer = m.signer
	}
	return signer, m.errCreatesigner
}

func (m *mockKeyManager) Close() error {
	return m.errClose
}

type badSigner struct{}

func (b *badSigner) Public() crypto.PublicKey {
	return testSigner.Public()
}

func (b *badSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("💥")
}

func mockNow(t *testing.T) {
	tmp := now
	now = func() time.Time {
		return testNow
	}
	t.Cleanup(func() {
		now = tmp
	})
}

func mustIssuer() *x509.Certificate {
	v, err := pemutil.Parse([]byte(testIntermediatePem))
	if err != nil {
		panic(err)
	}
	return v.(*x509.Certificate)
}

func mustSigner() crypto.Signer {
	v, err := pemutil.Parse([]byte(testIntermediateKeyPem))
	if err != nil {
		panic(err)
	}
	return v.(crypto.Signer)
}

func mustSign(template, parent *x509.Certificate, notBefore, notAfter time.Time) *x509.Certificate {
	tmpl := *template
	tmpl.NotBefore = notBefore
	tmpl.NotAfter = notAfter
	tmpl.Issuer = parent.Subject
	cert, err := x509util.CreateCertificate(&tmpl, parent, tmpl.PublicKey, testSigner)
	if err != nil {
		panic(err)
	}
	return cert
}

func setTeeReader(t *testing.T, w *bytes.Buffer) {
	t.Helper()
	reader := rand.Reader
	t.Cleanup(func() {
		rand.Reader = reader
	})
	rand.Reader = io.TeeReader(reader, w)
}

func TestNew(t *testing.T) {
	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    *SoftCAS
		wantErr bool
	}{
		{"ok", args{context.Background(), apiv1.Options{CertificateChain: []*x509.Certificate{testIssuer}, Signer: testSigner}}, &SoftCAS{CertificateChain: []*x509.Certificate{testIssuer}, Signer: testSigner}, false},
		{"fail no issuer", args{context.Background(), apiv1.Options{Signer: testSigner}}, nil, true},
		{"fail no signer", args{context.Background(), apiv1.Options{CertificateChain: []*x509.Certificate{testIssuer}}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNew_register(t *testing.T) {
	newFn, ok := apiv1.LoadCertificateAuthorityServiceNewFunc(apiv1.SoftCAS)
	if !ok {
		t.Error("apiv1.LoadCertificateAuthorityServiceNewFunc(apiv1.SoftCAS) was not found")
		return
	}

	want := &SoftCAS{
		CertificateChain: []*x509.Certificate{testIssuer},
		Signer:           testSigner,
	}

	got, err := newFn(context.Background(), apiv1.Options{CertificateChain: []*x509.Certificate{testIssuer}, Signer: testSigner})
	if err != nil {
		t.Errorf("New() error = %v", err)
		return
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("New() = %v, want %v", got, want)
	}
}

func TestSoftCAS_CreateCertificate(t *testing.T) {
	mockNow(t)
	// Set rand.Reader to EOF
	buf := new(bytes.Buffer)
	setTeeReader(t, buf)
	rand.Reader = buf

	tmplNotBefore := *testTemplate
	tmplNotBefore.NotBefore = testNow

	tmplNotAfter := *testTemplate
	tmplNotAfter.NotAfter = testNow.Add(24 * time.Hour)

	tmplWithLifetime := *testTemplate
	tmplWithLifetime.NotBefore = testNow
	tmplWithLifetime.NotAfter = testNow.Add(24 * time.Hour)

	tmplNoSerial := *testTemplate
	tmplNoSerial.SerialNumber = nil

	type fields struct {
		Issuer *x509.Certificate
		Signer crypto.Signer
	}
	type args struct {
		req *apiv1.CreateCertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.CreateCertificateResponse
		wantErr bool
	}{
		{"ok", fields{testIssuer, testSigner}, args{&apiv1.CreateCertificateRequest{
			Template: testTemplate, Lifetime: 24 * time.Hour,
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      testSignedTemplate,
			CertificateChain: []*x509.Certificate{testIssuer},
		}, false},
		{"ok with notBefore", fields{testIssuer, testSigner}, args{&apiv1.CreateCertificateRequest{
			Template: &tmplNotBefore, Lifetime: 24 * time.Hour,
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      testSignedTemplate,
			CertificateChain: []*x509.Certificate{testIssuer},
		}, false},
		{"ok with notBefore+notAfter", fields{testIssuer, testSigner}, args{&apiv1.CreateCertificateRequest{
			Template: &tmplWithLifetime, Lifetime: 24 * time.Hour,
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      testSignedTemplate,
			CertificateChain: []*x509.Certificate{testIssuer},
		}, false},
		{"fail template", fields{testIssuer, testSigner}, args{&apiv1.CreateCertificateRequest{Lifetime: 24 * time.Hour}}, nil, true},
		{"fail lifetime", fields{testIssuer, testSigner}, args{&apiv1.CreateCertificateRequest{Template: testTemplate}}, nil, true},
		{"fail CreateCertificate", fields{testIssuer, testSigner}, args{&apiv1.CreateCertificateRequest{
			Template: &tmplNoSerial,
			Lifetime: 24 * time.Hour,
		}}, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &SoftCAS{
				CertificateChain: []*x509.Certificate{tt.fields.Issuer},
				Signer:           tt.fields.Signer,
			}
			got, err := c.CreateCertificate(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SoftCAS.CreateCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SoftCAS.CreateCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSoftCAS_RenewCertificate(t *testing.T) {
	mockNow(t)

	// Set rand.Reader to EOF
	buf := new(bytes.Buffer)
	setTeeReader(t, buf)
	rand.Reader = buf

	tmplNoSerial := *testTemplate
	tmplNoSerial.SerialNumber = nil

	type fields struct {
		Issuer *x509.Certificate
		Signer crypto.Signer
	}
	type args struct {
		req *apiv1.RenewCertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.RenewCertificateResponse
		wantErr bool
	}{
		{"ok", fields{testIssuer, testSigner}, args{&apiv1.RenewCertificateRequest{
			Template: testTemplate, Lifetime: 24 * time.Hour,
		}}, &apiv1.RenewCertificateResponse{
			Certificate:      testSignedTemplate,
			CertificateChain: []*x509.Certificate{testIssuer},
		}, false},
		{"fail template", fields{testIssuer, testSigner}, args{&apiv1.RenewCertificateRequest{Lifetime: 24 * time.Hour}}, nil, true},
		{"fail lifetime", fields{testIssuer, testSigner}, args{&apiv1.RenewCertificateRequest{Template: testTemplate}}, nil, true},
		{"fail CreateCertificate", fields{testIssuer, testSigner}, args{&apiv1.RenewCertificateRequest{
			Template: &tmplNoSerial,
			Lifetime: 24 * time.Hour,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &SoftCAS{
				CertificateChain: []*x509.Certificate{tt.fields.Issuer},
				Signer:           tt.fields.Signer,
			}
			got, err := c.RenewCertificate(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SoftCAS.RenewCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SoftCAS.RenewCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSoftCAS_RevokeCertificate(t *testing.T) {
	type fields struct {
		Issuer *x509.Certificate
		Signer crypto.Signer
	}
	type args struct {
		req *apiv1.RevokeCertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.RevokeCertificateResponse
		wantErr bool
	}{
		{"ok", fields{testIssuer, testSigner}, args{&apiv1.RevokeCertificateRequest{
			Certificate: &x509.Certificate{Subject: pkix.Name{CommonName: "fake"}},
			Reason:      "test reason",
			ReasonCode:  1,
		}}, &apiv1.RevokeCertificateResponse{
			Certificate:      &x509.Certificate{Subject: pkix.Name{CommonName: "fake"}},
			CertificateChain: []*x509.Certificate{testIssuer},
		}, false},
		{"ok no cert", fields{testIssuer, testSigner}, args{&apiv1.RevokeCertificateRequest{
			Reason:     "test reason",
			ReasonCode: 1,
		}}, &apiv1.RevokeCertificateResponse{
			Certificate:      nil,
			CertificateChain: []*x509.Certificate{testIssuer},
		}, false},
		{"ok empty", fields{testIssuer, testSigner}, args{&apiv1.RevokeCertificateRequest{}}, &apiv1.RevokeCertificateResponse{
			Certificate:      nil,
			CertificateChain: []*x509.Certificate{testIssuer},
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &SoftCAS{
				CertificateChain: []*x509.Certificate{tt.fields.Issuer},
				Signer:           tt.fields.Signer,
			}
			got, err := c.RevokeCertificate(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SoftCAS.RevokeCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SoftCAS.RevokeCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_now(t *testing.T) {
	t0 := time.Now()
	t1 := now()
	if t1.Sub(t0) > time.Second {
		t.Errorf("now() = %s, want ~%s", t1, t0)
	}
}

func TestSoftCAS_CreateCertificateAuthority(t *testing.T) {
	mockNow(t)

	type fields struct {
		Issuer     *x509.Certificate
		Signer     crypto.Signer
		KeyManager kms.KeyManager
	}
	type args struct {
		req *apiv1.CreateCertificateAuthorityRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.CreateCertificateAuthorityResponse
		wantErr bool
	}{
		{"ok root", fields{nil, nil, &mockKeyManager{}}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: testRootTemplate,
			Lifetime: 24 * time.Hour,
		}}, &apiv1.CreateCertificateAuthorityResponse{
			Name:        "Test Root CA",
			Certificate: testSignedRootTemplate,
			PublicKey:   testSignedRootTemplate.PublicKey,
			PrivateKey:  testSigner,
			Signer:      testSigner,
		}, false},
		{"ok intermediate", fields{nil, nil, &mockKeyManager{}}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: testIntermediateTemplate,
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Certificate: testSignedRootTemplate,
				Signer:      testSigner,
			},
		}}, &apiv1.CreateCertificateAuthorityResponse{
			Name:             "Test Intermediate CA",
			Certificate:      testSignedIntermediateTemplate,
			CertificateChain: []*x509.Certificate{testSignedRootTemplate},
			PublicKey:        testSignedIntermediateTemplate.PublicKey,
			PrivateKey:       testSigner,
			Signer:           testSigner,
		}, false},
		{"fail template", fields{nil, nil, &mockKeyManager{}}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail lifetime", fields{nil, nil, &mockKeyManager{}}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: testIntermediateTemplate,
		}}, nil, true},
		{"fail type", fields{nil, nil, &mockKeyManager{}}, args{&apiv1.CreateCertificateAuthorityRequest{
			Template: testIntermediateTemplate,
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail parent", fields{nil, nil, &mockKeyManager{}}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: testIntermediateTemplate,
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail parent.certificate", fields{nil, nil, &mockKeyManager{}}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: testIntermediateTemplate,
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Signer: testSigner,
			},
		}}, nil, true},
		{"fail parent.signer", fields{nil, nil, &mockKeyManager{}}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: testIntermediateTemplate,
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Certificate: testSignedRootTemplate,
			},
		}}, nil, true},
		{"fail createKey", fields{nil, nil, &mockKeyManager{errCreateKey: errTest}}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: testIntermediateTemplate,
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail createSigner", fields{nil, nil, &mockKeyManager{errCreatesigner: errTest}}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: testIntermediateTemplate,
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail sign root", fields{nil, nil, &mockKeyManager{signer: &badSigner{}}}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: testIntermediateTemplate,
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail sign intermediate", fields{nil, nil, &mockKeyManager{}}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: testIntermediateTemplate,
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Certificate: testSignedRootTemplate,
				Signer:      &badSigner{},
			},
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &SoftCAS{
				CertificateChain: []*x509.Certificate{tt.fields.Issuer},
				Signer:           tt.fields.Signer,
				KeyManager:       tt.fields.KeyManager,
			}
			got, err := c.CreateCertificateAuthority(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SoftCAS.CreateCertificateAuthority() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SoftCAS.CreateCertificateAuthority() = \n%#v, want \n%#v", got, tt.want)
			}
		})
	}
}
