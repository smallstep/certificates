package cloudcas

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	lroauto "cloud.google.com/go/longrunning/autogen"
	privateca "cloud.google.com/go/security/privateca/apiv1beta1"
	gomock "github.com/golang/mock/gomock"
	"github.com/google/uuid"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/cas/apiv1"
	"google.golang.org/api/option"
	pb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	longrunningpb "google.golang.org/genproto/googleapis/longrunning"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
)

var (
	errTest             = errors.New("test error")
	testAuthorityName   = "projects/test-project/locations/us-west1/certificateAuthorities/test-ca"
	testCertificateName = "projects/test-project/locations/us-west1/certificateAuthorities/test-ca/certificates/test-certificate"
	testProject         = "test-project"
	testLocation        = "us-west1"
	testRootCertificate = `-----BEGIN CERTIFICATE-----
MIIBhjCCAS2gAwIBAgIQLbKTuXau4+t3KFbGpJJAADAKBggqhkjOPQQDAjAiMSAw
HgYDVQQDExdHb29nbGUgQ0FTIFRlc3QgUm9vdCBDQTAeFw0yMDA5MTQyMjQ4NDla
Fw0zMDA5MTIyMjQ4NDlaMCIxIDAeBgNVBAMTF0dvb2dsZSBDQVMgVGVzdCBSb290
IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYKGgQ3/0D7+oBTc0CXoYfSC6
M8hOqLsmzBapPZSYpfwjgEsjdNU84jdrYmW1zF1+p+MrL4c7qJv9NLo/picCuqNF
MEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYE
FFVn9V7Qymd7cUJh9KAhnUDAQL5YMAoGCCqGSM49BAMCA0cAMEQCIA4LzttYoT3u
8TYgSrvFT+Z+cklfi4UrPBU6aSbcUaW2AiAPfaqbyccQT3CxMVyHg+xZZjAirZp8
lAeA/T4FxAonHA==
-----END CERTIFICATE-----`
	testIntermediateCertificate = `-----BEGIN CERTIFICATE-----
MIIBsDCCAVagAwIBAgIQOb91kHxWKVzSJ9ESW1ViVzAKBggqhkjOPQQDAjAiMSAw
HgYDVQQDExdHb29nbGUgQ0FTIFRlc3QgUm9vdCBDQTAeFw0yMDA5MTQyMjQ4NDla
Fw0zMDA5MTIyMjQ4NDlaMCoxKDAmBgNVBAMTH0dvb2dsZSBDQVMgVGVzdCBJbnRl
cm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASUHN1cNyId4Ei/
4MxD5VrZFc51P50caMUdDZVrPveidChBYCU/9IM6vnRlZHx2HLjQ0qAvqHwY3rT0
xc7n+PfCo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAd
BgNVHQ4EFgQUSDlasiw0pRKyS7llhL0ZuVFNa9UwHwYDVR0jBBgwFoAUVWf1XtDK
Z3txQmH0oCGdQMBAvlgwCgYIKoZIzj0EAwIDSAAwRQIgMmsLcoC4KriXw+s+cZx2
bJMf6Mx/WESj31buJJhpzY0CIQCBUa/JtvS3nyce/4DF5tK2v49/NWHREgqAaZ57
DcYyHQ==
-----END CERTIFICATE-----`
	testLeafCertificate = `-----BEGIN CERTIFICATE-----
MIIB1jCCAX2gAwIBAgIQQfOn+COMeuD8VYF1TiDkEzAKBggqhkjOPQQDAjAqMSgw
JgYDVQQDEx9Hb29nbGUgQ0FTIFRlc3QgSW50ZXJtZWRpYXRlIENBMB4XDTIwMDkx
NDIyNTE1NVoXDTMwMDkxMjIyNTE1MlowHTEbMBkGA1UEAxMSdGVzdC5zbWFsbHN0
ZXAuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAdUSRBrpgHFilN4eaGlN
nX2+xfjXa1Iwk2/+AensjFTXJi1UAIB0e+4pqi7Sen5E2QVBhntEHCrA3xOf7czg
P6OBkTCBjjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG
AQUFBwMCMB0GA1UdDgQWBBSYPbu4Tmm7Zze/hCePeZH1Avoj+jAfBgNVHSMEGDAW
gBRIOVqyLDSlErJLuWWEvRm5UU1r1TAdBgNVHREEFjAUghJ0ZXN0LnNtYWxsc3Rl
cC5jb20wCgYIKoZIzj0EAwIDRwAwRAIgY+nTc+RHn31/BOhht4JpxCmJPHxqFT3S
ojnictBudV0CIB87ipY5HV3c8FLVEzTA0wFwdDZvQraQYsthwbg2kQFb
-----END CERTIFICATE-----`
	testSignedCertificate = `-----BEGIN CERTIFICATE-----
MIIB/DCCAaKgAwIBAgIQHHFuGMz0cClfde5kqP5prTAKBggqhkjOPQQDAjAqMSgw
JgYDVQQDEx9Hb29nbGUgQ0FTIFRlc3QgSW50ZXJtZWRpYXRlIENBMB4XDTIwMDkx
NTAwMDQ0M1oXDTMwMDkxMzAwMDQ0MFowHTEbMBkGA1UEAxMSdGVzdC5zbWFsbHN0
ZXAuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMqNCiXMvbn74LsHzRv+8
17m9vEzH6RHrg3m82e0uEc36+fZWV/zJ9SKuONmnl5VP79LsjL5SVH0RDj73U2XO
DKOBtjCBszAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG
AQUFBwMCMB0GA1UdDgQWBBRTA2cTs7PCNjnps/+T0dS8diqv0DAfBgNVHSMEGDAW
gBRIOVqyLDSlErJLuWWEvRm5UU1r1TBCBgwrBgEEAYKkZMYoQAIEMjAwEwhjbG91
ZGNhcxMkZDhkMThhNjgtNTI5Ni00YWYzLWFlNGItMmY4NzdkYTNmYmQ5MAoGCCqG
SM49BAMCA0gAMEUCIGxl+pqJ50WYWUqK2l4V1FHoXSi0Nht5kwTxFxnWZu1xAiEA
zemu3bhWLFaGg3s8i+HTEhw4RqkHP74vF7AVYp88bAw=
-----END CERTIFICATE-----`
	testIntermediateCsr = `-----BEGIN CERTIFICATE REQUEST-----
MIIBIjCByQIBADAqMSgwJgYDVQQDEx9Hb29nbGUgQ0FTIFRlc3QgSW50ZXJtZWRp
YXRlIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqoztio0c4XuaaGxHFiU7
UBk3YRGTae9GtlKwyZJDk740hg6ZIoKcaXrzJT5taUpPiQLi7rP1eRui0dhl/bHo
o6A9MDsGCSqGSIb3DQEJDjEuMCwwKgYDVR0RBCMwIYIfR29vZ2xlIENBUyBUZXN0
IEludGVybWVkaWF0ZSBDQTAKBggqhkjOPQQDAgNIADBFAiEAvRKBPE32scAvsMe8
R7ecx91q58ZmeLaRdSzL7stsnJYCIEBu+vQUSTbUpKL2YQNclT9kbilips5pEMr3
ojxK6mk3
-----END CERTIFICATE REQUEST-----`

// 	testIntermediateKey = `-----BEGIN EC PRIVATE KEY-----
// MHcCAQEEIMM+DSPChJgcYyqDWs0eRA5BctIo+VSNqRzCTL2ARYAqoAoGCCqGSM49
// AwEHoUQDQgAEqoztio0c4XuaaGxHFiU7UBk3YRGTae9GtlKwyZJDk740hg6ZIoKc
// aXrzJT5taUpPiQLi7rP1eRui0dhl/bHoow==
// -----END EC PRIVATE KEY-----`
)

type testClient struct {
	credentialsFile      string
	certificate          *pb.Certificate
	certificateAuthority *pb.CertificateAuthority
	err                  error
}

func newTestClient(credentialsFile string) (CertificateAuthorityClient, error) {
	if credentialsFile == "testdata/error.json" {
		return nil, errTest
	}
	return &testClient{
		credentialsFile: credentialsFile,
	}, nil
}

func okTestClient() *testClient {
	return &testClient{
		credentialsFile: "testdata/credentials.json",
		certificate: &pb.Certificate{
			Name:                testCertificateName,
			PemCertificate:      testSignedCertificate,
			PemCertificateChain: []string{testIntermediateCertificate, testRootCertificate},
		},
		certificateAuthority: &pb.CertificateAuthority{
			PemCaCertificates: []string{testIntermediateCertificate, testRootCertificate},
		},
	}
}

func failTestClient() *testClient {
	return &testClient{
		credentialsFile: "testdata/credentials.json",
		err:             errTest,
	}
}

func badTestClient() *testClient {
	return &testClient{
		credentialsFile: "testdata/credentials.json",
		certificate: &pb.Certificate{
			Name:                testCertificateName,
			PemCertificate:      "not a pem cert",
			PemCertificateChain: []string{testIntermediateCertificate, testRootCertificate},
		},
		certificateAuthority: &pb.CertificateAuthority{
			PemCaCertificates: []string{testIntermediateCertificate, "not a pem cert"},
		},
	}
}

func setTeeReader(t *testing.T, w *bytes.Buffer) {
	t.Helper()
	reader := rand.Reader
	t.Cleanup(func() {
		rand.Reader = reader
	})
	rand.Reader = io.TeeReader(reader, w)
}

func (c *testClient) CreateCertificate(ctx context.Context, req *pb.CreateCertificateRequest, opts ...gax.CallOption) (*pb.Certificate, error) {
	return c.certificate, c.err
}

func (c *testClient) RevokeCertificate(ctx context.Context, req *pb.RevokeCertificateRequest, opts ...gax.CallOption) (*pb.Certificate, error) {
	return c.certificate, c.err
}

func (c *testClient) GetCertificateAuthority(ctx context.Context, req *pb.GetCertificateAuthorityRequest, opts ...gax.CallOption) (*pb.CertificateAuthority, error) {
	return c.certificateAuthority, c.err
}

func (c *testClient) CreateCertificateAuthority(ctx context.Context, req *pb.CreateCertificateAuthorityRequest, opts ...gax.CallOption) (*privateca.CreateCertificateAuthorityOperation, error) {
	return nil, errors.New("use NewMockCertificateAuthorityClient")
}

func (c *testClient) FetchCertificateAuthorityCsr(ctx context.Context, req *pb.FetchCertificateAuthorityCsrRequest, opts ...gax.CallOption) (*pb.FetchCertificateAuthorityCsrResponse, error) {
	return nil, errors.New("use NewMockCertificateAuthorityClient")
}

func (c *testClient) ActivateCertificateAuthority(ctx context.Context, req *pb.ActivateCertificateAuthorityRequest, opts ...gax.CallOption) (*privateca.ActivateCertificateAuthorityOperation, error) {
	return nil, errors.New("use NewMockCertificateAuthorityClient")
}

func mustParseCertificate(t *testing.T, pemCert string) *x509.Certificate {
	t.Helper()
	crt, err := parseCertificate(pemCert)
	if err != nil {
		t.Fatal(err)
	}
	return crt
}

func TestNew(t *testing.T) {
	tmp := newCertificateAuthorityClient
	newCertificateAuthorityClient = func(ctx context.Context, credentialsFile string) (CertificateAuthorityClient, error) {
		return newTestClient(credentialsFile)
	}
	t.Cleanup(func() {
		newCertificateAuthorityClient = tmp
	})

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    *CloudCAS
		wantErr bool
	}{
		{"ok", args{context.Background(), apiv1.Options{
			CertificateAuthority: testAuthorityName,
		}}, &CloudCAS{
			client:               &testClient{},
			certificateAuthority: testAuthorityName,
			project:              testProject,
			location:             testLocation,
		}, false},
		{"ok with credentials", args{context.Background(), apiv1.Options{
			CertificateAuthority: testAuthorityName, CredentialsFile: "testdata/credentials.json",
		}}, &CloudCAS{
			client:               &testClient{credentialsFile: "testdata/credentials.json"},
			certificateAuthority: testAuthorityName,
			project:              testProject,
			location:             testLocation,
		}, false},
		{"ok creator", args{context.Background(), apiv1.Options{
			IsCreator: true, Project: testProject, Location: testLocation,
		}}, &CloudCAS{
			client:   &testClient{},
			project:  testProject,
			location: testLocation,
		}, false},
		{"fail certificate authority", args{context.Background(), apiv1.Options{}}, nil, true},
		{"fail with credentials", args{context.Background(), apiv1.Options{
			CertificateAuthority: testAuthorityName, CredentialsFile: "testdata/error.json",
		}}, nil, true},
		{"fail creator project", args{context.Background(), apiv1.Options{
			IsCreator: true, Project: "", Location: testLocation,
		}}, nil, true},
		{"fail creator location", args{context.Background(), apiv1.Options{
			IsCreator: true, Project: testProject, Location: "",
		}}, nil, true},
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
	tmp := newCertificateAuthorityClient
	newCertificateAuthorityClient = func(ctx context.Context, credentialsFile string) (CertificateAuthorityClient, error) {
		return newTestClient(credentialsFile)
	}
	t.Cleanup(func() {
		newCertificateAuthorityClient = tmp
	})

	want := &CloudCAS{
		client:               &testClient{credentialsFile: "testdata/credentials.json"},
		certificateAuthority: testAuthorityName,
		project:              testProject,
		location:             testLocation,
	}

	newFn, ok := apiv1.LoadCertificateAuthorityServiceNewFunc(apiv1.CloudCAS)
	if !ok {
		t.Error("apiv1.LoadCertificateAuthorityServiceNewFunc(apiv1.CloudCAS) was not found")
		return
	}

	got, err := newFn(context.Background(), apiv1.Options{
		CertificateAuthority: testAuthorityName, CredentialsFile: "testdata/credentials.json",
	})
	if err != nil {
		t.Errorf("New() error = %v", err)
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("New() = %v, want %v", got, want)
	}

}

func TestNew_real(t *testing.T) {
	if v, ok := os.LookupEnv("GOOGLE_APPLICATION_CREDENTIALS"); ok {
		os.Unsetenv("GOOGLE_APPLICATION_CREDENTIALS")
		t.Cleanup(func() {
			os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", v)
		})
	}

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name     string
		skipOnCI bool
		args     args
		wantErr  bool
	}{
		{"fail default credentials", true, args{context.Background(), apiv1.Options{CertificateAuthority: testAuthorityName}}, true},
		{"fail certificate authority", false, args{context.Background(), apiv1.Options{}}, true},
		{"fail with credentials", false, args{context.Background(), apiv1.Options{
			CertificateAuthority: testAuthorityName, CredentialsFile: "testdata/missing.json",
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnCI && os.Getenv("CI") == "true" {
				t.SkipNow()
			}
			_, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCloudCAS_GetCertificateAuthority(t *testing.T) {
	root := mustParseCertificate(t, testRootCertificate)
	type fields struct {
		client               CertificateAuthorityClient
		certificateAuthority string
	}
	type args struct {
		req *apiv1.GetCertificateAuthorityRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.GetCertificateAuthorityResponse
		wantErr bool
	}{
		{"ok", fields{okTestClient(), testCertificateName}, args{&apiv1.GetCertificateAuthorityRequest{}}, &apiv1.GetCertificateAuthorityResponse{
			RootCertificate: root,
		}, false},
		{"ok with name", fields{okTestClient(), testCertificateName}, args{&apiv1.GetCertificateAuthorityRequest{
			Name: testCertificateName,
		}}, &apiv1.GetCertificateAuthorityResponse{
			RootCertificate: root,
		}, false},
		{"fail GetCertificateAuthority", fields{failTestClient(), testCertificateName}, args{&apiv1.GetCertificateAuthorityRequest{}}, nil, true},
		{"fail bad root", fields{badTestClient(), testCertificateName}, args{&apiv1.GetCertificateAuthorityRequest{}}, nil, true},
		{"fail no pems", fields{&testClient{certificateAuthority: &pb.CertificateAuthority{}}, testCertificateName}, args{&apiv1.GetCertificateAuthorityRequest{}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CloudCAS{
				client:               tt.fields.client,
				certificateAuthority: tt.fields.certificateAuthority,
			}
			got, err := c.GetCertificateAuthority(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("CloudCAS.GetCertificateAuthority() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CloudCAS.GetCertificateAuthority() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloudCAS_CreateCertificate(t *testing.T) {
	type fields struct {
		client               CertificateAuthorityClient
		certificateAuthority string
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
		{"ok", fields{okTestClient(), testCertificateName}, args{&apiv1.CreateCertificateRequest{
			Template: mustParseCertificate(t, testLeafCertificate),
			Lifetime: 24 * time.Hour,
		}}, &apiv1.CreateCertificateResponse{
			Certificate:      mustParseCertificate(t, testSignedCertificate),
			CertificateChain: []*x509.Certificate{mustParseCertificate(t, testIntermediateCertificate)},
		}, false},
		{"fail Template", fields{okTestClient(), testCertificateName}, args{&apiv1.CreateCertificateRequest{
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail Lifetime", fields{okTestClient(), testCertificateName}, args{&apiv1.CreateCertificateRequest{
			Template: mustParseCertificate(t, testLeafCertificate),
		}}, nil, true},
		{"fail CreateCertificate", fields{failTestClient(), testCertificateName}, args{&apiv1.CreateCertificateRequest{
			Template: mustParseCertificate(t, testLeafCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail Certificate", fields{badTestClient(), testCertificateName}, args{&apiv1.CreateCertificateRequest{
			Template: mustParseCertificate(t, testLeafCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CloudCAS{
				client:               tt.fields.client,
				certificateAuthority: tt.fields.certificateAuthority,
			}
			got, err := c.CreateCertificate(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("CloudCAS.CreateCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CloudCAS.CreateCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloudCAS_createCertificate(t *testing.T) {
	leaf := mustParseCertificate(t, testLeafCertificate)
	signed := mustParseCertificate(t, testSignedCertificate)
	chain := []*x509.Certificate{mustParseCertificate(t, testIntermediateCertificate)}

	type fields struct {
		client               CertificateAuthorityClient
		certificateAuthority string
	}
	type args struct {
		tpl       *x509.Certificate
		lifetime  time.Duration
		requestID string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *x509.Certificate
		want1   []*x509.Certificate
		wantErr bool
	}{
		{"ok", fields{okTestClient(), testAuthorityName}, args{leaf, 24 * time.Hour, "request-id"}, signed, chain, false},
		{"fail CertificateConfig", fields{okTestClient(), testAuthorityName}, args{&x509.Certificate{}, 24 * time.Hour, "request-id"}, nil, nil, true},
		{"fail CreateCertificate", fields{failTestClient(), testAuthorityName}, args{leaf, 24 * time.Hour, "request-id"}, nil, nil, true},
		{"fail ParseCertificates", fields{badTestClient(), testAuthorityName}, args{leaf, 24 * time.Hour, "request-id"}, nil, nil, true},
		{"fail create id", fields{okTestClient(), testAuthorityName}, args{leaf, 24 * time.Hour, "request-id"}, nil, nil, true},
	}

	// Pre-calculate rand.Random
	buf := new(bytes.Buffer)
	setTeeReader(t, buf)
	for i := 0; i < len(tests)-1; i++ {
		_, err := uuid.NewRandomFromReader(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	rand.Reader = buf

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CloudCAS{
				client:               tt.fields.client,
				certificateAuthority: tt.fields.certificateAuthority,
			}
			got, got1, err := c.createCertificate(tt.args.tpl, tt.args.lifetime, tt.args.requestID)
			if (err != nil) != tt.wantErr {
				t.Errorf("CloudCAS.createCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CloudCAS.createCertificate() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("CloudCAS.createCertificate() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestCloudCAS_RenewCertificate(t *testing.T) {
	type fields struct {
		client               CertificateAuthorityClient
		certificateAuthority string
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
		{"ok", fields{okTestClient(), testCertificateName}, args{&apiv1.RenewCertificateRequest{
			Template: mustParseCertificate(t, testLeafCertificate),
			Lifetime: 24 * time.Hour,
		}}, &apiv1.RenewCertificateResponse{
			Certificate:      mustParseCertificate(t, testSignedCertificate),
			CertificateChain: []*x509.Certificate{mustParseCertificate(t, testIntermediateCertificate)},
		}, false},
		{"fail Template", fields{okTestClient(), testCertificateName}, args{&apiv1.RenewCertificateRequest{
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail Lifetime", fields{okTestClient(), testCertificateName}, args{&apiv1.RenewCertificateRequest{
			Template: mustParseCertificate(t, testLeafCertificate),
		}}, nil, true},
		{"fail CreateCertificate", fields{failTestClient(), testCertificateName}, args{&apiv1.RenewCertificateRequest{
			Template: mustParseCertificate(t, testLeafCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail Certificate", fields{badTestClient(), testCertificateName}, args{&apiv1.RenewCertificateRequest{
			Template: mustParseCertificate(t, testLeafCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CloudCAS{
				client:               tt.fields.client,
				certificateAuthority: tt.fields.certificateAuthority,
			}
			got, err := c.RenewCertificate(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("CloudCAS.RenewCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CloudCAS.RenewCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloudCAS_RevokeCertificate(t *testing.T) {
	badExtensionCert := mustParseCertificate(t, testSignedCertificate)
	for i, ext := range badExtensionCert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 2}) {
			badExtensionCert.Extensions[i].Value = []byte("bad-data")
		}
	}

	type fields struct {
		client               CertificateAuthorityClient
		certificateAuthority string
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
		{"ok", fields{okTestClient(), testCertificateName}, args{&apiv1.RevokeCertificateRequest{
			Certificate: mustParseCertificate(t, testSignedCertificate),
			ReasonCode:  1,
		}}, &apiv1.RevokeCertificateResponse{
			Certificate:      mustParseCertificate(t, testSignedCertificate),
			CertificateChain: []*x509.Certificate{mustParseCertificate(t, testIntermediateCertificate)},
		}, false},
		{"fail Extension", fields{okTestClient(), testCertificateName}, args{&apiv1.RevokeCertificateRequest{
			Certificate: mustParseCertificate(t, testLeafCertificate),
			ReasonCode:  1,
		}}, nil, true},
		{"fail Extension Value", fields{okTestClient(), testCertificateName}, args{&apiv1.RevokeCertificateRequest{
			Certificate: badExtensionCert,
			ReasonCode:  1,
		}}, nil, true},
		{"fail Certificate", fields{okTestClient(), testCertificateName}, args{&apiv1.RevokeCertificateRequest{
			ReasonCode: 2,
		}}, nil, true},
		{"fail ReasonCode", fields{okTestClient(), testCertificateName}, args{&apiv1.RevokeCertificateRequest{
			Certificate: mustParseCertificate(t, testSignedCertificate),
			ReasonCode:  100,
		}}, nil, true},
		{"fail ReasonCode 7", fields{okTestClient(), testCertificateName}, args{&apiv1.RevokeCertificateRequest{
			Certificate: mustParseCertificate(t, testSignedCertificate),
			ReasonCode:  7,
		}}, nil, true},
		{"fail ReasonCode 8", fields{okTestClient(), testCertificateName}, args{&apiv1.RevokeCertificateRequest{
			Certificate: mustParseCertificate(t, testSignedCertificate),
			ReasonCode:  8,
		}}, nil, true},
		{"fail RevokeCertificate", fields{failTestClient(), testCertificateName}, args{&apiv1.RevokeCertificateRequest{
			Certificate: mustParseCertificate(t, testSignedCertificate),
			ReasonCode:  1,
		}}, nil, true},
		{"fail ParseCertificate", fields{badTestClient(), testCertificateName}, args{&apiv1.RevokeCertificateRequest{
			Certificate: mustParseCertificate(t, testSignedCertificate),
			ReasonCode:  1,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CloudCAS{
				client:               tt.fields.client,
				certificateAuthority: tt.fields.certificateAuthority,
			}
			got, err := c.RevokeCertificate(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("CloudCAS.RevokeCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CloudCAS.RevokeCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_createCertificateID(t *testing.T) {
	buf := new(bytes.Buffer)
	setTeeReader(t, buf)
	uuid, err := uuid.NewRandomFromReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rand.Reader = buf

	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{"ok", uuid.String(), false},
		{"fail", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createCertificateID()
			if (err != nil) != tt.wantErr {
				t.Errorf("createCertificateID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("createCertificateID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseCertificate(t *testing.T) {
	type args struct {
		pemCert string
	}
	tests := []struct {
		name    string
		args    args
		want    *x509.Certificate
		wantErr bool
	}{
		{"ok", args{testLeafCertificate}, mustParseCertificate(t, testLeafCertificate), false},
		{"ok intermediate", args{testIntermediateCertificate}, mustParseCertificate(t, testIntermediateCertificate), false},
		{"fail pem", args{"not pem"}, nil, true},
		{"fail parseCertificate", args{"-----BEGIN CERTIFICATE-----\nZm9vYmFyCg==\n-----END CERTIFICATE-----\n"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCertificate(tt.args.pemCert)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getCertificateAndChain(t *testing.T) {
	type args struct {
		certpb *pb.Certificate
	}
	tests := []struct {
		name    string
		args    args
		want    *x509.Certificate
		want1   []*x509.Certificate
		wantErr bool
	}{
		{"ok", args{&pb.Certificate{
			Name:                testCertificateName,
			PemCertificate:      testSignedCertificate,
			PemCertificateChain: []string{testIntermediateCertificate, testRootCertificate},
		}}, mustParseCertificate(t, testSignedCertificate), []*x509.Certificate{mustParseCertificate(t, testIntermediateCertificate)}, false},
		{"fail PemCertificate", args{&pb.Certificate{
			Name:                testCertificateName,
			PemCertificate:      "foobar",
			PemCertificateChain: []string{testIntermediateCertificate, testRootCertificate},
		}}, nil, nil, true},
		{"fail PemCertificateChain", args{&pb.Certificate{
			Name:                testCertificateName,
			PemCertificate:      testSignedCertificate,
			PemCertificateChain: []string{"foobar", testRootCertificate},
		}}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := getCertificateAndChain(tt.args.certpb)
			if (err != nil) != tt.wantErr {
				t.Errorf("getCertificateAndChain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCertificateAndChain() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("getCertificateAndChain() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestCloudCAS_CreateCertificateAuthority(t *testing.T) {
	must := func(a, b interface{}) interface{} {
		return a
	}

	// client, close := mockTestClient()
	// defer close()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mosCtrl := gomock.NewController(t)
	defer mosCtrl.Finish()

	m := NewMockCertificateAuthorityClient(ctrl)
	mos := NewMockOperationsServer(mosCtrl)

	// Create operation server
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := grpc.NewServer()
	longrunningpb.RegisterOperationsServer(srv, mos)

	go srv.Serve(lis)
	defer srv.Stop()

	// Create fake privateca client
	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}

	client, err := lroauto.NewOperationsClient(context.Background(), option.WithGRPCConn(conn))
	if err != nil {
		t.Fatal(err)
	}
	fake := &privateca.CertificateAuthorityClient{
		LROClient: client,
	}

	// Configure mocks
	any := gomock.Any()

	// ok root
	m.EXPECT().CreateCertificateAuthority(any, any).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(any, any).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)

	// ok intermediate
	m.EXPECT().CreateCertificateAuthority(any, any).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(any, any).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name: testAuthorityName,
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().FetchCertificateAuthorityCsr(any, any).Return(&pb.FetchCertificateAuthorityCsrResponse{
		PemCsr: testIntermediateCsr,
	}, nil)
	m.EXPECT().CreateCertificate(any, any).Return(&pb.Certificate{
		PemCertificate:      testIntermediateCertificate,
		PemCertificateChain: []string{testRootCertificate},
	}, nil)
	m.EXPECT().ActivateCertificateAuthority(any, any).Return(fake.ActivateCertificateAuthorityOperation("ActivateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(any, any).Return(&longrunningpb.Operation{
		Name: "ActivateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testIntermediateCertificate, testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)

	rootCrt := mustParseCertificate(t, testRootCertificate)
	intCrt := mustParseCertificate(t, testIntermediateCertificate)

	type fields struct {
		client               CertificateAuthorityClient
		certificateAuthority string
		project              string
		location             string
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
		{"ok root", fields{m, "", testProject, testLocation}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, &apiv1.CreateCertificateAuthorityResponse{
			Name:        testAuthorityName,
			Certificate: rootCrt,
		}, false},
		{"ok intermediate", fields{m, "", testProject, testLocation}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: mustParseCertificate(t, testIntermediateCertificate),
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Name:        testAuthorityName,
				Certificate: rootCrt,
			},
		}}, &apiv1.CreateCertificateAuthorityResponse{
			Name:             testAuthorityName,
			Certificate:      intCrt,
			CertificateChain: []*x509.Certificate{rootCrt},
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CloudCAS{
				client:               tt.fields.client,
				certificateAuthority: tt.fields.certificateAuthority,
				project:              tt.fields.project,
				location:             tt.fields.location,
			}
			got, err := c.CreateCertificateAuthority(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("CloudCAS.CreateCertificateAuthority() error = %+v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CloudCAS.CreateCertificateAuthority() = %v, want %v", got, tt.want)
			}
		})
	}
}
