//go:generate mockgen -package cloudcas -mock_names=CertificateAuthorityClient=MockCertificateAuthorityClient -destination mock_client_test.go github.com/smallstep/certificates/cas/cloudcas CertificateAuthorityClient
//go:generate mockgen -package cloudcas -mock_names=OperationsServer=MockOperationsServer -destination mock_operation_server_test.go cloud.google.com/go/longrunning/autogen/longrunningpb OperationsServer

package cloudcas

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	lroauto "cloud.google.com/go/longrunning/autogen"
	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	privateca "cloud.google.com/go/security/privateca/apiv1"
	pb "cloud.google.com/go/security/privateca/apiv1/privatecapb"
	gomock "github.com/golang/mock/gomock"
	"github.com/google/uuid"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/cas/apiv1"
	kmsapi "go.step.sm/crypto/kms/apiv1"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/anypb"
)

var (
	errTest             = errors.New("test error")
	testCaPoolName      = "projects/test-project/locations/us-west1/caPools/test-capool"
	testAuthorityName   = "projects/test-project/locations/us-west1/caPools/test-capool/certificateAuthorities/test-ca"
	testCertificateName = "projects/test-project/locations/us-west1/caPools/test-capool/certificateAuthorities/test-ca/certificates/test-certificate"
	testProject         = "test-project"
	testLocation        = "us-west1"
	testCaPool          = "test-capool"
	testRootCertificate = `-----BEGIN CERTIFICATE-----
MIIBeDCCAR+gAwIBAgIQcXWWjtSZ/PAyH8D1Ou4L9jAKBggqhkjOPQQDAjAbMRkw
FwYDVQQDExBDbG91ZENBUyBSb290IENBMB4XDTIwMTAyNzIyNTM1NFoXDTMwMTAy
NzIyNTM1NFowGzEZMBcGA1UEAxMQQ2xvdWRDQVMgUm9vdCBDQTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABIySHA4b78Yu4LuGhZIlv/PhNwXz4ZoV1OUZQ0LrK3vj
B13O12DLZC5uj1z3kxdQzXUttSbtRv49clMpBiTpsZKjRTBDMA4GA1UdDwEB/wQE
AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSZ+t9RMHbFTl5BatM3
5bJlHPOu3DAKBggqhkjOPQQDAgNHADBEAiASah6gg0tVM3WI0meCQ4SEKk7Mjhbv
+SmhuZHWV1QlXQIgRXNyWcpVUrAoG6Uy1KQg07LDpF5dFeK9InrDxSJAkVo=
-----END CERTIFICATE-----`
	testIntermediateCertificate = `-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIRALLKxnxyl0GBeKevIcbx02wwCgYIKoZIzj0EAwIwGzEZ
MBcGA1UEAxMQQ2xvdWRDQVMgUm9vdCBDQTAeFw0yMDEwMjcyMjUzNTRaFw0zMDEw
MjcyMjUzNTRaMCMxITAfBgNVBAMTGENsb3VkQ0FTIEludGVybWVkaWF0ZSBDQTBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABPLuqxgBY+QmaXc8zKIC8FMgjJ6dF/cL
b+Dig0XKc5GH/T1ORrhgOkRayrQcjPMu+jkjg25qn6vvp43LRtUKPXOjZjBkMA4G
A1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBQ8RVQI
VgXAmRNDX8qItalVpSBEGjAfBgNVHSMEGDAWgBSZ+t9RMHbFTl5BatM35bJlHPOu
3DAKBggqhkjOPQQDAgNJADBGAiEA70MVYVqjm8SBHJf5cOlWfiXXOfHUsctTJ+/F
pLsKBogCIQDJJkoQqYl9B59Dq3zydl8bpJevQxsoaa4Wqg+ZBMkvbQ==
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
MIHeMIGFAgEAMCMxITAfBgNVBAMTGENsb3VkQ0FTIEludGVybWVkaWF0ZSBDQTBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABPLuqxgBY+QmaXc8zKIC8FMgjJ6dF/cL
b+Dig0XKc5GH/T1ORrhgOkRayrQcjPMu+jkjg25qn6vvp43LRtUKPXOgADAKBggq
hkjOPQQDAgNIADBFAiEAn3pkYXb2OzoQZ+AExFqd7qZ7pg2nyP2kBZZ01Pl8KfcC
IHKplBXDR79/i7kjOtv1iWfgf5S/XQHrz178gXA0YQe7
-----END CERTIFICATE REQUEST-----`
	testRootKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIN51Rgg6YcQVLeCRzumdw4pjM3VWqFIdCbnsV3Up1e/goAoGCCqGSM49
AwEHoUQDQgAEjJIcDhvvxi7gu4aFkiW/8+E3BfPhmhXU5RlDQusre+MHXc7XYMtk
Lm6PXPeTF1DNdS21Ju1G/j1yUykGJOmxkg==
-----END EC PRIVATE KEY-----`
	//nolint:unused,gocritic,varcheck
	testIntermediateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMMX/XkXGnRDD4fYu7Z4rHACdJn/iyOy2UTwsv+oZ0C+oAoGCCqGSM49
AwEHoUQDQgAE8u6rGAFj5CZpdzzMogLwUyCMnp0X9wtv4OKDRcpzkYf9PU5GuGA6
RFrKtByM8y76OSODbmqfq++njctG1Qo9cw==
-----END EC PRIVATE KEY-----`
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

type badSigner struct {
	pub crypto.PublicKey
}

func createBadSigner(t *testing.T) *badSigner {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &badSigner{
		pub: pub,
	}
}

func (b *badSigner) Public() crypto.PublicKey {
	return b.pub
}

func (b *badSigner) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("💥")
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

func (c *testClient) EnableCertificateAuthority(ctx context.Context, req *pb.EnableCertificateAuthorityRequest, opts ...gax.CallOption) (*privateca.EnableCertificateAuthorityOperation, error) {
	return nil, errors.New("use NewMockCertificateAuthorityClient")
}

func (c *testClient) GetCaPool(ctx context.Context, req *pb.GetCaPoolRequest, opts ...gax.CallOption) (*pb.CaPool, error) {
	return nil, errors.New("use NewMockCertificateAuthorityClient")
}

func (c *testClient) CreateCaPool(ctx context.Context, req *pb.CreateCaPoolRequest, opts ...gax.CallOption) (*privateca.CreateCaPoolOperation, error) {
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

func mustParseECKey(t *testing.T, pemKey string) *ecdsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		t.Fatal("failed to parse key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
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
			caPool:               testCaPool,
			caPoolTier:           0,
		}, false},
		{"ok authority and creator", args{context.Background(), apiv1.Options{
			CertificateAuthority: testAuthorityName, IsCreator: true,
		}}, &CloudCAS{
			client:               &testClient{},
			certificateAuthority: testAuthorityName,
			project:              testProject,
			location:             testLocation,
			caPool:               testCaPool,
			caPoolTier:           0,
		}, false},
		{"ok with credentials", args{context.Background(), apiv1.Options{
			CertificateAuthority: testAuthorityName, CredentialsFile: "testdata/credentials.json",
		}}, &CloudCAS{
			client:               &testClient{credentialsFile: "testdata/credentials.json"},
			certificateAuthority: testAuthorityName,
			project:              testProject,
			location:             testLocation,
			caPool:               testCaPool,
			caPoolTier:           0,
		}, false},
		{"ok creator", args{context.Background(), apiv1.Options{
			IsCreator: true, Project: testProject, Location: testLocation, CaPool: testCaPool,
		}}, &CloudCAS{
			client:     &testClient{},
			project:    testProject,
			location:   testLocation,
			caPool:     testCaPool,
			caPoolTier: pb.CaPool_DEVOPS,
		}, false},
		{"ok creator devops", args{context.Background(), apiv1.Options{
			IsCreator: true, Project: testProject, Location: testLocation, CaPool: testCaPool, CaPoolTier: "DevOps",
		}}, &CloudCAS{
			client:     &testClient{},
			project:    testProject,
			location:   testLocation,
			caPool:     testCaPool,
			caPoolTier: pb.CaPool_DEVOPS,
		}, false},
		{"ok creator enterprise", args{context.Background(), apiv1.Options{
			IsCreator: true, Project: testProject, Location: testLocation, CaPool: testCaPool, CaPoolTier: "ENTERPRISE",
		}}, &CloudCAS{
			client:     &testClient{},
			project:    testProject,
			location:   testLocation,
			caPool:     testCaPool,
			caPoolTier: pb.CaPool_ENTERPRISE,
		}, false},
		{"fail certificate authority", args{context.Background(), apiv1.Options{
			CertificateAuthority: "projects/ok1234/locations/ok1234/caPools/ok1234/certificateAuthorities/ok1234/bad",
		}}, nil, true},
		{"fail certificate authority regex", args{context.Background(), apiv1.Options{}}, nil, true},
		{"fail with credentials", args{context.Background(), apiv1.Options{
			CertificateAuthority: testAuthorityName, CredentialsFile: "testdata/error.json",
		}}, nil, true},
		{"fail creator project", args{context.Background(), apiv1.Options{
			IsCreator: true, Project: "", Location: testLocation,
		}}, nil, true},
		{"fail creator location", args{context.Background(), apiv1.Options{
			IsCreator: true, Project: testProject, Location: "",
		}}, nil, true},
		{"fail caPool", args{context.Background(), apiv1.Options{
			IsCreator: true, Project: testProject, Location: testLocation, CaPool: "",
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
		caPool:               testCaPool,
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
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", v)
		})
	}

	failDefaultCredentials := true
	if home, err := os.UserHomeDir(); err == nil {
		file := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
		if _, err := os.Stat(file); err == nil {
			failDefaultCredentials = false
		}
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
		{"fail default credentials", true, args{context.Background(), apiv1.Options{CertificateAuthority: testAuthorityName}}, failDefaultCredentials},
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
	id, err := uuid.NewRandomFromReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rand.Reader = buf

	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{"ok", id.String(), false},
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

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mosCtrl := gomock.NewController(t)
	defer mosCtrl.Finish()

	m := NewMockCertificateAuthorityClient(ctrl)
	mos := NewMockOperationsServer(mosCtrl)

	// Create operation server
	srv := grpc.NewServer()
	longrunningpb.RegisterOperationsServer(srv, mos)

	lis := bufconn.Listen(2)
	go srv.Serve(lis)
	defer srv.Stop()

	// Create fake privateca client
	conn, err := grpc.DialContext(context.Background(), "", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}))
	if err != nil {
		t.Fatal(err)
	}

	client, err := lroauto.NewOperationsClient(context.Background(), option.WithGRPCConn(conn))
	if err != nil {
		t.Fatal(err)
	}
	fake, err := privateca.NewCertificateAuthorityClient(context.Background(), option.WithGRPCConn(conn))
	if err != nil {
		t.Fatal(err)
	}
	fake.LROClient = client

	// Configure mocks
	anee := gomock.Any()

	// ok root
	m.EXPECT().GetCaPool(anee, anee).Return(nil, status.Error(codes.NotFound, "not found"))
	m.EXPECT().CreateCaPool(anee, anee).Return(fake.CreateCaPoolOperation("CreateCaPool"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCaPool",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CaPool{
				Name: testCaPoolName,
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().EnableCertificateAuthority(anee, anee).Return(fake.EnableCertificateAuthorityOperation("EnableCertificateAuthorityOperation"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "EnableCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)

	// ok intermediate
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name: testAuthorityName,
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().FetchCertificateAuthorityCsr(anee, anee).Return(&pb.FetchCertificateAuthorityCsrResponse{
		PemCsr: testIntermediateCsr,
	}, nil)
	m.EXPECT().CreateCertificate(anee, anee).Return(&pb.Certificate{
		PemCertificate:      testIntermediateCertificate,
		PemCertificateChain: []string{testRootCertificate},
	}, nil)
	m.EXPECT().ActivateCertificateAuthority(anee, anee).Return(fake.ActivateCertificateAuthorityOperation("ActivateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "ActivateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testIntermediateCertificate, testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().EnableCertificateAuthority(anee, anee).Return(fake.EnableCertificateAuthorityOperation("EnableCertificateAuthorityOperation"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "EnableCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testIntermediateCertificate, testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)

	// ok intermediate local signer
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name: testAuthorityName,
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().FetchCertificateAuthorityCsr(anee, anee).Return(&pb.FetchCertificateAuthorityCsrResponse{
		PemCsr: testIntermediateCsr,
	}, nil)
	m.EXPECT().ActivateCertificateAuthority(anee, anee).Return(fake.ActivateCertificateAuthorityOperation("ActivateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "ActivateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testIntermediateCertificate, testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().EnableCertificateAuthority(anee, anee).Return(fake.EnableCertificateAuthorityOperation("EnableCertificateAuthorityOperation"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "EnableCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testIntermediateCertificate, testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)

	// ok create key
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().EnableCertificateAuthority(anee, anee).Return(fake.EnableCertificateAuthorityOperation("EnableCertificateAuthorityOperation"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "EnableCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)

	// fail GetCaPool
	m.EXPECT().GetCaPool(anee, anee).Return(nil, errTest)

	// fail CreateCaPool
	m.EXPECT().GetCaPool(anee, anee).Return(nil, status.Error(codes.NotFound, "not found"))
	m.EXPECT().CreateCaPool(anee, anee).Return(nil, errTest)

	// fail CreateCaPool.Wait
	m.EXPECT().GetCaPool(anee, anee).Return(nil, status.Error(codes.NotFound, "not found"))
	m.EXPECT().CreateCaPool(anee, anee).Return(fake.CreateCaPoolOperation("CreateCaPool"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(nil, errTest)

	// fail CreateCertificateAuthority
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(nil, errTest)

	// fail CreateCertificateAuthority.Wait
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(nil, errTest)

	// fail EnableCertificateAuthority
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().EnableCertificateAuthority(anee, anee).Return(nil, errTest)

	// fail EnableCertificateAuthority.Wait
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().EnableCertificateAuthority(anee, anee).Return(fake.EnableCertificateAuthorityOperation("EnableCertificateAuthorityOperation"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(nil, errTest)

	// fail EnableCertificateAuthority intermediate
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name: testAuthorityName,
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().FetchCertificateAuthorityCsr(anee, anee).Return(&pb.FetchCertificateAuthorityCsrResponse{
		PemCsr: testIntermediateCsr,
	}, nil)
	m.EXPECT().CreateCertificate(anee, anee).Return(&pb.Certificate{
		PemCertificate:      testIntermediateCertificate,
		PemCertificateChain: []string{testRootCertificate},
	}, nil)
	m.EXPECT().ActivateCertificateAuthority(anee, anee).Return(fake.ActivateCertificateAuthorityOperation("ActivateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "ActivateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testIntermediateCertificate, testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().EnableCertificateAuthority(anee, anee).Return(nil, errTest)

	// fail EnableCertificateAuthority.Wait intermediate
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name: testAuthorityName,
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().FetchCertificateAuthorityCsr(anee, anee).Return(&pb.FetchCertificateAuthorityCsrResponse{
		PemCsr: testIntermediateCsr,
	}, nil)
	m.EXPECT().CreateCertificate(anee, anee).Return(&pb.Certificate{
		PemCertificate:      testIntermediateCertificate,
		PemCertificateChain: []string{testRootCertificate},
	}, nil)
	m.EXPECT().ActivateCertificateAuthority(anee, anee).Return(fake.ActivateCertificateAuthorityOperation("ActivateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "ActivateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name:              testAuthorityName,
				PemCaCertificates: []string{testIntermediateCertificate, testRootCertificate},
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().EnableCertificateAuthority(anee, anee).Return(fake.EnableCertificateAuthorityOperation("EnableCertificateAuthorityOperation"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(nil, errTest)

	// fail FetchCertificateAuthorityCsr
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name: testAuthorityName,
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().FetchCertificateAuthorityCsr(anee, anee).Return(nil, errTest)

	// fail CreateCertificate
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name: testAuthorityName,
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().FetchCertificateAuthorityCsr(anee, anee).Return(&pb.FetchCertificateAuthorityCsrResponse{
		PemCsr: testIntermediateCsr,
	}, nil)
	m.EXPECT().CreateCertificate(anee, anee).Return(nil, errTest)

	// fail ActivateCertificateAuthority
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name: testAuthorityName,
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().FetchCertificateAuthorityCsr(anee, anee).Return(&pb.FetchCertificateAuthorityCsrResponse{
		PemCsr: testIntermediateCsr,
	}, nil)
	m.EXPECT().CreateCertificate(anee, anee).Return(&pb.Certificate{
		PemCertificate:      testIntermediateCertificate,
		PemCertificateChain: []string{testRootCertificate},
	}, nil)
	m.EXPECT().ActivateCertificateAuthority(anee, anee).Return(nil, errTest)

	// fail ActivateCertificateAuthority.Wait
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name: testAuthorityName,
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().FetchCertificateAuthorityCsr(anee, anee).Return(&pb.FetchCertificateAuthorityCsrResponse{
		PemCsr: testIntermediateCsr,
	}, nil)
	m.EXPECT().CreateCertificate(anee, anee).Return(&pb.Certificate{
		PemCertificate:      testIntermediateCertificate,
		PemCertificateChain: []string{testRootCertificate},
	}, nil)
	m.EXPECT().ActivateCertificateAuthority(anee, anee).Return(fake.ActivateCertificateAuthorityOperation("ActivateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(nil, errTest)

	// fail x509util.CreateCertificate
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name: testAuthorityName,
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().FetchCertificateAuthorityCsr(anee, anee).Return(&pb.FetchCertificateAuthorityCsrResponse{
		PemCsr: testIntermediateCsr,
	}, nil)

	// fail parseCertificateRequest
	m.EXPECT().GetCaPool(anee, anee).Return(&pb.CaPool{Name: testCaPoolName}, nil)
	m.EXPECT().CreateCertificateAuthority(anee, anee).Return(fake.CreateCertificateAuthorityOperation("CreateCertificateAuthority"), nil)
	mos.EXPECT().GetOperation(anee, anee).Return(&longrunningpb.Operation{
		Name: "CreateCertificateAuthority",
		Done: true,
		Result: &longrunningpb.Operation_Response{
			Response: must(anypb.New(&pb.CertificateAuthority{
				Name: testAuthorityName,
			})).(*anypb.Any),
		},
	}, nil)
	m.EXPECT().FetchCertificateAuthorityCsr(anee, anee).Return(&pb.FetchCertificateAuthorityCsrResponse{
		PemCsr: "Not a CSR",
	}, nil)

	rootCrt := mustParseCertificate(t, testRootCertificate)
	intCrt := mustParseCertificate(t, testIntermediateCertificate)

	type fields struct {
		client               CertificateAuthorityClient
		certificateAuthority string
		project              string
		location             string
		caPool               string
		caPoolTier           pb.CaPool_Tier
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
		{"ok root", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_ENTERPRISE}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, &apiv1.CreateCertificateAuthorityResponse{
			Name:        testAuthorityName,
			Certificate: rootCrt,
		}, false},
		{"ok intermediate", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
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
		{"ok intermediate local signer", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_ENTERPRISE}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: mustParseCertificate(t, testIntermediateCertificate),
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Certificate: rootCrt,
				Signer:      mustParseECKey(t, testRootKey),
			},
		}}, &apiv1.CreateCertificateAuthorityResponse{
			Name:             testAuthorityName,
			Certificate:      intCrt,
			CertificateChain: []*x509.Certificate{rootCrt},
		}, false},
		{"ok create key", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
			CreateKey: &kmsapi.CreateKeyRequest{
				SignatureAlgorithm: kmsapi.ECDSAWithSHA256,
			},
		}}, &apiv1.CreateCertificateAuthorityResponse{
			Name:        testAuthorityName,
			Certificate: rootCrt,
		}, false},
		{"fail project", fields{m, "", "", testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail location", fields{m, "", testProject, "", testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail caPool", fields{m, "", testProject, testLocation, "", pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail template", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail lifetime", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
		}}, nil, true},
		{"fail parent", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail parent name", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
			Parent:   &apiv1.CreateCertificateAuthorityResponse{},
		}}, nil, true},
		{"fail type", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     0,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail create key", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
			CreateKey: &kmsapi.CreateKeyRequest{
				SignatureAlgorithm: kmsapi.PureEd25519,
			},
		}}, nil, true},
		{"fail GetCaPool", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail CreateCaPool", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail CreateCaPool.Wait", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail CreateCertificateAuthority", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail CreateCertificateAuthority.Wait", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail EnableCertificateAuthority", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},
		{"fail EnableCertificateAuthority.Wait", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.RootCA,
			Template: mustParseCertificate(t, testRootCertificate),
			Lifetime: 24 * time.Hour,
		}}, nil, true},

		{"fail EnableCertificateAuthority intermediate", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: mustParseCertificate(t, testIntermediateCertificate),
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Name:        testAuthorityName,
				Certificate: rootCrt,
			},
		}}, nil, true},
		{"fail EnableCertificateAuthority.Wait intermediate", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: mustParseCertificate(t, testIntermediateCertificate),
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Name:        testAuthorityName,
				Certificate: rootCrt,
			},
		}}, nil, true},

		{"fail FetchCertificateAuthorityCsr", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: mustParseCertificate(t, testIntermediateCertificate),
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Name:        testAuthorityName,
				Certificate: rootCrt,
			},
		}}, nil, true},
		{"fail CreateCertificate", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: mustParseCertificate(t, testIntermediateCertificate),
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Name:        testAuthorityName,
				Certificate: rootCrt,
			},
		}}, nil, true},
		{"fail ActivateCertificateAuthority", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: mustParseCertificate(t, testIntermediateCertificate),
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Name:        testAuthorityName,
				Certificate: rootCrt,
			},
		}}, nil, true},
		{"fail ActivateCertificateAuthority.Wait", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: mustParseCertificate(t, testIntermediateCertificate),
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Name:        testAuthorityName,
				Certificate: rootCrt,
			},
		}}, nil, true},
		{"fail x509util.CreateCertificate", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: mustParseCertificate(t, testIntermediateCertificate),
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Certificate: rootCrt,
				Signer:      createBadSigner(t),
			},
		}}, nil, true},
		{"fail parseCertificateRequest", fields{m, "", testProject, testLocation, testCaPool, pb.CaPool_DEVOPS}, args{&apiv1.CreateCertificateAuthorityRequest{
			Type:     apiv1.IntermediateCA,
			Template: mustParseCertificate(t, testIntermediateCertificate),
			Lifetime: 24 * time.Hour,
			Parent: &apiv1.CreateCertificateAuthorityResponse{
				Certificate: rootCrt,
				Signer:      createBadSigner(t),
			},
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CloudCAS{
				client:               tt.fields.client,
				certificateAuthority: tt.fields.certificateAuthority,
				project:              tt.fields.project,
				location:             tt.fields.location,
				caPool:               tt.fields.caPool,
				caPoolTier:           tt.fields.caPoolTier,
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

func Test_normalizeCertificateAuthorityName(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"ok", args{"Test-CA-Name_1234"}, "Test-CA-Name_1234"},
		{"change", args{"💥 CA"}, "--CA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeCertificateAuthorityName(tt.args.name); got != tt.want {
				t.Errorf("normalizeCertificateAuthorityName() = %v, want %v", got, tt.want)
			}
		})
	}
}
