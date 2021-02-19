package awskms

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/smallstep/certificates/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

func TestNew(t *testing.T) {
	ctx := context.Background()

	sess, err := session.NewSessionWithOptions(session.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expected := &KMS{
		session: sess,
		service: kms.New(sess),
	}

	// This will force an error in the session creation.
	// It does not fail with missing credentials.
	forceError := func(t *testing.T) {
		key := "AWS_CA_BUNDLE"
		value := os.Getenv(key)
		os.Setenv(key, filepath.Join(os.TempDir(), "missing-ca.crt"))
		t.Cleanup(func() {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		})
	}

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    *KMS
		wantErr bool
	}{
		{"ok", args{ctx, apiv1.Options{}}, expected, false},
		{"ok with options", args{ctx, apiv1.Options{
			Region:          "us-east-1",
			Profile:         "smallstep",
			CredentialsFile: "~/aws/credentials",
		}}, expected, false},
		{"ok with uri", args{ctx, apiv1.Options{
			URI: "awskms:region=us-east-1;profile=smallstep;credentials-file=/var/run/aws/credentials",
		}}, expected, false},
		{"fail", args{ctx, apiv1.Options{}}, nil, true},
		{"fail uri", args{ctx, apiv1.Options{
			URI: "pkcs11:region=us-east-1;profile=smallstep;credentials-file=/var/run/aws/credentials",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Force an error in the session loading
			if tt.wantErr {
				forceError(t)
			}

			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("New() = %#v, want %#v", got, tt.want)
				}
			} else {
				if got.session == nil || got.service == nil {
					t.Errorf("New() = %#v, want %#v", got, tt.want)
				}
			}
		})
	}
}

func TestKMS_GetPublicKey(t *testing.T) {
	okClient := getOKClient()
	key, err := pemutil.ParseKey([]byte(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		session *session.Session
		service KeyManagementClient
	}
	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"ok", fields{nil, okClient}, args{&apiv1.GetPublicKeyRequest{
			Name: "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
		}}, key, false},
		{"fail empty", fields{nil, okClient}, args{&apiv1.GetPublicKeyRequest{}}, nil, true},
		{"fail name", fields{nil, okClient}, args{&apiv1.GetPublicKeyRequest{
			Name: "awskms:key-id=",
		}}, nil, true},
		{"fail getPublicKey", fields{nil, &MockClient{
			getPublicKeyWithContext: func(ctx aws.Context, input *kms.GetPublicKeyInput, opts ...request.Option) (*kms.GetPublicKeyOutput, error) {
				return nil, fmt.Errorf("an error")
			},
		}}, args{&apiv1.GetPublicKeyRequest{
			Name: "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
		}}, nil, true},
		{"fail not der", fields{nil, &MockClient{
			getPublicKeyWithContext: func(ctx aws.Context, input *kms.GetPublicKeyInput, opts ...request.Option) (*kms.GetPublicKeyOutput, error) {
				return &kms.GetPublicKeyOutput{
					KeyId:     input.KeyId,
					PublicKey: []byte(publicKey),
				}, nil
			},
		}}, args{&apiv1.GetPublicKeyRequest{
			Name: "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KMS{
				session: tt.fields.session,
				service: tt.fields.service,
			}
			got, err := k.GetPublicKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("KMS.GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KMS.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKMS_CreateKey(t *testing.T) {
	okClient := getOKClient()
	key, err := pemutil.ParseKey([]byte(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		session *session.Session
		service KeyManagementClient
	}
	type args struct {
		req *apiv1.CreateKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.CreateKeyResponse
		wantErr bool
	}{
		{"ok", fields{nil, okClient}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, &apiv1.CreateKeyResponse{
			Name:      "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
			PublicKey: key,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
			},
		}, false},
		{"ok rsa", fields{nil, okClient}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               2048,
		}}, &apiv1.CreateKeyResponse{
			Name:      "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
			PublicKey: key,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
			},
		}, false},
		{"fail empty", fields{nil, okClient}, args{&apiv1.CreateKeyRequest{}}, nil, true},
		{"fail unsupported alg", fields{nil, okClient}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.PureEd25519,
		}}, nil, true},
		{"fail unsupported bits", fields{nil, okClient}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               1234,
		}}, nil, true},
		{"fail createKey", fields{nil, &MockClient{
			createKeyWithContext: func(ctx aws.Context, input *kms.CreateKeyInput, opts ...request.Option) (*kms.CreateKeyOutput, error) {
				return nil, fmt.Errorf("an error")
			},
			createAliasWithContext:  okClient.createAliasWithContext,
			getPublicKeyWithContext: okClient.getPublicKeyWithContext,
		}}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, nil, true},
		{"fail createAlias", fields{nil, &MockClient{
			createKeyWithContext: okClient.createKeyWithContext,
			createAliasWithContext: func(ctx aws.Context, input *kms.CreateAliasInput, opts ...request.Option) (*kms.CreateAliasOutput, error) {
				return nil, fmt.Errorf("an error")
			},
			getPublicKeyWithContext: okClient.getPublicKeyWithContext,
		}}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, nil, true},
		{"fail getPublicKey", fields{nil, &MockClient{
			createKeyWithContext:   okClient.createKeyWithContext,
			createAliasWithContext: okClient.createAliasWithContext,
			getPublicKeyWithContext: func(ctx aws.Context, input *kms.GetPublicKeyInput, opts ...request.Option) (*kms.GetPublicKeyOutput, error) {
				return nil, fmt.Errorf("an error")
			},
		}}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KMS{
				session: tt.fields.session,
				service: tt.fields.service,
			}
			got, err := k.CreateKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("KMS.CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KMS.CreateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKMS_CreateSigner(t *testing.T) {
	client := getOKClient()
	key, err := pemutil.ParseKey([]byte(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		session *session.Session
		service KeyManagementClient
	}
	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.Signer
		wantErr bool
	}{
		{"ok", fields{nil, client}, args{&apiv1.CreateSignerRequest{
			SigningKey: "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
		}}, &Signer{
			service:   client,
			keyID:     "be468355-ca7a-40d9-a28b-8ae1c4c7f936",
			publicKey: key,
		}, false},
		{"fail empty", fields{nil, client}, args{&apiv1.CreateSignerRequest{}}, nil, true},
		{"fail preload", fields{nil, client}, args{&apiv1.CreateSignerRequest{}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KMS{
				session: tt.fields.session,
				service: tt.fields.service,
			}
			got, err := k.CreateSigner(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("KMS.CreateSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KMS.CreateSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKMS_Close(t *testing.T) {
	type fields struct {
		session *session.Session
		service KeyManagementClient
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{nil, getOKClient()}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KMS{
				session: tt.fields.session,
				service: tt.fields.service,
			}
			if err := k.Close(); (err != nil) != tt.wantErr {
				t.Errorf("KMS.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_parseKeyID(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok uri", args{"awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936"}, "be468355-ca7a-40d9-a28b-8ae1c4c7f936", false},
		{"ok key id", args{"be468355-ca7a-40d9-a28b-8ae1c4c7f936"}, "be468355-ca7a-40d9-a28b-8ae1c4c7f936", false},
		{"ok arn", args{"arn:aws:kms:us-east-1:123456789:key/be468355-ca7a-40d9-a28b-8ae1c4c7f936"}, "arn:aws:kms:us-east-1:123456789:key/be468355-ca7a-40d9-a28b-8ae1c4c7f936", false},
		{"fail parse", args{"awskms:key-id=%ZZ"}, "", true},
		{"fail empty key", args{"awskms:key-id="}, "", true},
		{"fail missing", args{"awskms:foo=bar"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseKeyID(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseKeyID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseKeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}
