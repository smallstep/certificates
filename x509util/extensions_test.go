package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"testing"
)

func Test_convertName(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"lowerCase", args{"FooBAR"}, "foobar"},
		{"underscore", args{"foo_bar"}, "foobar"},
		{"mixed", args{"FOO_Bar"}, "foobar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := convertName(tt.args.s); got != tt.want {
				t.Errorf("convertName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newExtension(t *testing.T) {
	type args struct {
		e pkix.Extension
	}
	tests := []struct {
		name string
		args args
		want Extension
	}{
		{"ok", args{pkix.Extension{Id: []int{1, 2, 3, 4}, Value: []byte("foo")}}, Extension{ID: []int{1, 2, 3, 4}, Critical: false, Value: []byte("foo")}},
		{"critical", args{pkix.Extension{Id: []int{1, 2, 3, 4}, Critical: true, Value: []byte("foo")}}, Extension{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("foo")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newExtension(tt.args.e); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newExtension() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newExtensions(t *testing.T) {
	ext1 := pkix.Extension{Id: []int{1, 2, 3, 4}, Value: []byte("foo")}
	ext2 := pkix.Extension{Id: []int{4, 3, 2, 1}, Critical: true, Value: []byte("bar")}

	type args struct {
		extensions []pkix.Extension
	}
	tests := []struct {
		name string
		args args
		want []Extension
	}{
		{"ok", args{[]pkix.Extension{ext1, ext2}}, []Extension{
			{ID: []int{1, 2, 3, 4}, Critical: false, Value: []byte("foo")},
			{ID: []int{4, 3, 2, 1}, Critical: true, Value: []byte("bar")},
		}},
		{"nil", args{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newExtensions(tt.args.extensions); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newExtensions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtension_Set(t *testing.T) {
	type fields struct {
		ID       ObjectIdentifier
		Critical bool
		Value    []byte
	}
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *x509.Certificate
	}{
		{"ok", fields{[]int{1, 2, 3, 4}, true, []byte("foo")}, args{&x509.Certificate{}}, &x509.Certificate{
			ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}, Critical: true, Value: []byte("foo")}},
		}},
		{"existing", fields{[]int{1, 2, 3, 4}, true, []byte("foo")}, args{&x509.Certificate{
			ExtraExtensions: []pkix.Extension{
				{Id: []int{1, 1, 1, 1}, Critical: false, Value: []byte("foo")},
			},
		}}, &x509.Certificate{
			ExtraExtensions: []pkix.Extension{
				{Id: []int{1, 1, 1, 1}, Critical: false, Value: []byte("foo")},
				{Id: []int{1, 2, 3, 4}, Critical: true, Value: []byte("foo")},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := Extension{
				ID:       tt.fields.ID,
				Critical: tt.fields.Critical,
				Value:    tt.fields.Value,
			}
			e.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("Extension.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestObjectIdentifier_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		o       ObjectIdentifier
		want    []byte
		wantErr bool
	}{
		{"ok", []int{1, 2, 3, 4}, []byte(`"1.2.3.4"`), false},
		{"empty", []int{}, []byte(`""`), false},
		{"nil", nil, []byte(`""`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.o.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("ObjectIdentifier.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ObjectIdentifier.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestObjectIdentifier_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    ObjectIdentifier
		wantErr bool
	}{
		{"ok", args{[]byte(`"1.2.3.4"`)}, []int{1, 2, 3, 4}, false},
		{"empty", args{[]byte(`""`)}, []int{}, false},
		{"null", args{[]byte(`null`)}, []int{}, false},
		{"number", args{[]byte(`123`)}, nil, true},
		{"badFormat", args{[]byte(`"1.2.foo.4"`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ObjectIdentifier
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("ObjectIdentifier.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ObjectIdentifier.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubjectAlternativeName_Set(t *testing.T) {
	panicCount := 0
	type fields struct {
		Type  string
		Value string
	}
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *x509.Certificate
	}{
		{"dns", fields{"dns", "foo.com"}, args{&x509.Certificate{}}, &x509.Certificate{DNSNames: []string{"foo.com"}}},
		{"dnsAdd", fields{"DNS", "bar.com"}, args{&x509.Certificate{DNSNames: []string{"foo.com"}}}, &x509.Certificate{DNSNames: []string{"foo.com", "bar.com"}}},
		{"email", fields{"email", "john@doe.com"}, args{&x509.Certificate{}}, &x509.Certificate{EmailAddresses: []string{"john@doe.com"}}},
		{"emailAdd", fields{"EMAIL", "jane@doe.com"}, args{&x509.Certificate{EmailAddresses: []string{"john@doe.com"}}}, &x509.Certificate{EmailAddresses: []string{"john@doe.com", "jane@doe.com"}}},
		{"ip", fields{"ip", "127.0.0.1"}, args{&x509.Certificate{}}, &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}},
		{"ipAdd", fields{"IP", "::1"}, args{&x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}}, &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}},
		{"ipBad", fields{"IP", "fooo"}, args{&x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}}, &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}},
		{"uri", fields{"uri", "https://foo.com"}, args{&x509.Certificate{}}, &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "foo.com"}}}},
		{"uriAdd", fields{"URI", "uri:foo:bar"}, args{&x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "foo.com"}}}}, &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "foo.com"}, {Scheme: "uri", Opaque: "foo:bar"}}}},
		{"uriBad", fields{"URI", "::1"}, args{&x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "foo.com"}}}}, &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "foo.com"}}}},
		{"AutoDNS", fields{"", "foo.com"}, args{&x509.Certificate{}}, &x509.Certificate{DNSNames: []string{"foo.com"}}},
		{"AutoDNSAdd", fields{"auto", "bar.com"}, args{&x509.Certificate{DNSNames: []string{"foo.com"}}}, &x509.Certificate{DNSNames: []string{"foo.com", "bar.com"}}},
		{"AutoEmail", fields{"AUTO", "john@doe.com"}, args{&x509.Certificate{}}, &x509.Certificate{EmailAddresses: []string{"john@doe.com"}}},
		{"AutoEmailAdd", fields{"", "jane@doe.com"}, args{&x509.Certificate{EmailAddresses: []string{"john@doe.com"}}}, &x509.Certificate{EmailAddresses: []string{"john@doe.com", "jane@doe.com"}}},
		{"IPAutoIP", fields{"AutO", "127.0.0.1"}, args{&x509.Certificate{}}, &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}},
		{"AutoIPAdd", fields{"", "::1"}, args{&x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}}, &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}},
		{"AutoURI", fields{"Auto", "https://foo.com"}, args{&x509.Certificate{}}, &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "foo.com"}}}},
		{"AutoURIAdd", fields{"", "uri:foo:bar"}, args{&x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "foo.com"}}}}, &x509.Certificate{URIs: []*url.URL{{Scheme: "https", Host: "foo.com"}, {Scheme: "uri", Opaque: "foo:bar"}}}},
		{"panic", fields{"panic", "foo.com"}, args{&x509.Certificate{}}, &x509.Certificate{DNSNames: []string{"foo.com"}}},
		{"panicAdd", fields{"panic", "bar.com"}, args{&x509.Certificate{DNSNames: []string{"foo.com"}}}, &x509.Certificate{DNSNames: []string{"foo.com"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					panicCount++
				}
			}()
			s := SubjectAlternativeName{
				Type:  tt.fields.Type,
				Value: tt.fields.Value,
			}
			s.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("SubjectAlternativeName.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}

	if panicCount != 2 {
		t.Errorf("SubjectAlternativeName.Set() number of panics = %d, want 2", panicCount)
	}
}

func TestKeyUsage_Set(t *testing.T) {
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name string
		k    KeyUsage
		args args
		want *x509.Certificate
	}{
		{"ok", KeyUsage(x509.KeyUsageDigitalSignature), args{&x509.Certificate{}}, &x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature}},
		{"overwrite", KeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageCertSign), args{&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature}}, &x509.Certificate{KeyUsage: x509.KeyUsageCRLSign | x509.KeyUsageCertSign}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.k.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("KeyUsage.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestKeyUsage_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    KeyUsage
		wantErr bool
	}{
		// Normalized
		{"DigitalSignature", args{[]byte(`"DigitalSignature"`)}, KeyUsage(x509.KeyUsageDigitalSignature), false},
		{"ContentCommitment", args{[]byte(`"ContentCommitment"`)}, KeyUsage(x509.KeyUsageContentCommitment), false},
		{"KeyEncipherment", args{[]byte(`"KeyEncipherment"`)}, KeyUsage(x509.KeyUsageKeyEncipherment), false},
		{"DataEncipherment", args{[]byte(`"DataEncipherment"`)}, KeyUsage(x509.KeyUsageDataEncipherment), false},
		{"KeyAgreement", args{[]byte(`"KeyAgreement"`)}, KeyUsage(x509.KeyUsageKeyAgreement), false},
		{"CertSign", args{[]byte(`"CertSign"`)}, KeyUsage(x509.KeyUsageCertSign), false},
		{"CRLSign", args{[]byte(`"CRLSign"`)}, KeyUsage(x509.KeyUsageCRLSign), false},
		{"EncipherOnly", args{[]byte(`"EncipherOnly"`)}, KeyUsage(x509.KeyUsageEncipherOnly), false},
		{"DecipherOnly", args{[]byte(`"DecipherOnly"`)}, KeyUsage(x509.KeyUsageDecipherOnly), false},
		// Snake case
		{"digital_signature", args{[]byte(`"digital_signature"`)}, KeyUsage(x509.KeyUsageDigitalSignature), false},
		{"content_commitment", args{[]byte(`"content_commitment"`)}, KeyUsage(x509.KeyUsageContentCommitment), false},
		{"key_encipherment", args{[]byte(`"key_encipherment"`)}, KeyUsage(x509.KeyUsageKeyEncipherment), false},
		{"data_encipherment", args{[]byte(`"data_encipherment"`)}, KeyUsage(x509.KeyUsageDataEncipherment), false},
		{"key_agreement", args{[]byte(`"key_agreement"`)}, KeyUsage(x509.KeyUsageKeyAgreement), false},
		{"cert_sign", args{[]byte(`"cert_sign"`)}, KeyUsage(x509.KeyUsageCertSign), false},
		{"crl_sign", args{[]byte(`"crl_sign"`)}, KeyUsage(x509.KeyUsageCRLSign), false},
		{"encipher_only", args{[]byte(`"encipher_only"`)}, KeyUsage(x509.KeyUsageEncipherOnly), false},
		{"decipher_only", args{[]byte(`"decipher_only"`)}, KeyUsage(x509.KeyUsageDecipherOnly), false},
		// MultiString
		{"DigitalSignatureAsArray", args{[]byte(`["digital_signature"]`)}, KeyUsage(x509.KeyUsageDigitalSignature), false},
		{"DigitalSignature|KeyEncipherment", args{[]byte(`["DigitalSignature", "key_encipherment"]`)}, KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment), false},
		// Errors
		{"invalid", args{[]byte(`"invalid"`)}, KeyUsage(0), true},
		{"number", args{[]byte(`123`)}, KeyUsage(0), true},
		{"object", args{[]byte(`{}`)}, KeyUsage(0), true},
		{"badJSON", args{[]byte(`{`)}, KeyUsage(0), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got KeyUsage
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("KeyUsage.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyUsage.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtKeyUsage_Set(t *testing.T) {
	eku1 := []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageServerAuth,
	}
	eku2 := []x509.ExtKeyUsage{
		x509.ExtKeyUsageCodeSigning,
	}
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name string
		k    ExtKeyUsage
		args args
		want *x509.Certificate
	}{
		{"ok", ExtKeyUsage(eku1), args{&x509.Certificate{}}, &x509.Certificate{ExtKeyUsage: eku1}},
		{"overwrite", ExtKeyUsage(eku2), args{&x509.Certificate{ExtKeyUsage: eku1}}, &x509.Certificate{ExtKeyUsage: eku2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.k.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("ExtKeyUsage.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestExtKeyUsage_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    ExtKeyUsage
		wantErr bool
	}{
		// Normalized
		{"Any", args{[]byte(`"Any"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageAny}), false},
		{"ServerAuth", args{[]byte(`"ServerAuth"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}), false},
		{"ClientAuth", args{[]byte(`"ClientAuth"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}), false},
		{"CodeSigning", args{[]byte(`"CodeSigning"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}), false},
		{"EmailProtection", args{[]byte(`"EmailProtection"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}), false},
		{"IPSECEndSystem", args{[]byte(`"IPSECEndSystem"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECEndSystem}), false},
		{"IPSECTunnel", args{[]byte(`"IPSECTunnel"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECTunnel}), false},
		{"IPSECUser", args{[]byte(`"IPSECUser"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECUser}), false},
		{"TimeStamping", args{[]byte(`"TimeStamping"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}), false},
		{"OCSPSigning", args{[]byte(`"OCSPSigning"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}), false},
		{"MicrosoftServerGatedCrypto", args{[]byte(`"MicrosoftServerGatedCrypto"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageMicrosoftServerGatedCrypto}), false},
		{"NetscapeServerGatedCrypto", args{[]byte(`"NetscapeServerGatedCrypto"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageNetscapeServerGatedCrypto}), false},
		{"MicrosoftCommercialCodeSigning", args{[]byte(`"MicrosoftCommercialCodeSigning"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageMicrosoftCommercialCodeSigning}), false},
		{"MicrosoftKernelCodeSigning", args{[]byte(`"MicrosoftKernelCodeSigning"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageMicrosoftKernelCodeSigning}), false},
		// Snake case
		{"any", args{[]byte(`"any"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageAny}), false},
		{"server_auth", args{[]byte(`"server_auth"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}), false},
		{"client_auth", args{[]byte(`"client_auth"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}), false},
		{"code_signing", args{[]byte(`"code_signing"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}), false},
		{"email_protection", args{[]byte(`"email_protection"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}), false},
		{"ipsec_end_system", args{[]byte(`"ipsec_end_system"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECEndSystem}), false},
		{"ipsec_tunnel", args{[]byte(`"ipsec_tunnel"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECTunnel}), false},
		{"ipsec_user", args{[]byte(`"ipsec_user"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECUser}), false},
		{"time_stamping", args{[]byte(`"time_stamping"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}), false},
		{"ocsp_signing", args{[]byte(`"ocsp_signing"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}), false},
		{"microsoft_server_gated_crypto", args{[]byte(`"microsoft_server_gated_crypto"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageMicrosoftServerGatedCrypto}), false},
		{"netscape_server_gated_crypto", args{[]byte(`"netscape_server_gated_crypto"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageNetscapeServerGatedCrypto}), false},
		{"microsoft_commercial_code_signing", args{[]byte(`"microsoft_commercial_code_signing"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageMicrosoftCommercialCodeSigning}), false},
		{"microsoft_kernel_code_signing", args{[]byte(`"microsoft_kernel_code_signing"`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageMicrosoftKernelCodeSigning}), false},
		// Multistring
		{"CodeSigningAsArray", args{[]byte(`["code_signing"]`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}), false},
		{"ServerAuth+ClientAuth", args{[]byte(`["ServerAuth","client_auth"]`)}, ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}), false},
		// Errors
		{"invalid", args{[]byte(`"invalid"`)}, nil, true},
		{"number", args{[]byte(`123`)}, nil, true},
		{"object", args{[]byte(`{}`)}, nil, true},
		{"badJSON", args{[]byte(`{`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ExtKeyUsage
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("ExtKeyUsage.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtKeyUsage.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubjectKeyID_Set(t *testing.T) {
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name string
		id   SubjectKeyID
		args args
		want *x509.Certificate
	}{
		{"ok", []byte("subjectKeyID"), args{&x509.Certificate{}}, &x509.Certificate{SubjectKeyId: []byte("subjectKeyID")}},
		{"overwrite", []byte("newSubjectKeyID"), args{&x509.Certificate{SubjectKeyId: []byte("subjectKeyID")}}, &x509.Certificate{SubjectKeyId: []byte("newSubjectKeyID")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.id.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("SubjectKeyID.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestAuthorityKeyID_Set(t *testing.T) {
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name string
		id   AuthorityKeyID
		args args
		want *x509.Certificate
	}{
		{"ok", []byte("authorityKeyID"), args{&x509.Certificate{}}, &x509.Certificate{AuthorityKeyId: []byte("authorityKeyID")}},
		{"overwrite", []byte("newAuthorityKeyID"), args{&x509.Certificate{AuthorityKeyId: []byte("authorityKeyID")}}, &x509.Certificate{AuthorityKeyId: []byte("newAuthorityKeyID")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.id.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("AuthorityKeyID.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestOCSPServer_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    OCSPServer
		wantErr bool
	}{
		{"string", args{[]byte(`"foo"`)}, []string{"foo"}, false},
		{"array", args{[]byte(`["foo", "bar", "zar"]`)}, []string{"foo", "bar", "zar"}, false},
		{"empty", args{[]byte(`[]`)}, []string{}, false},
		{"null", args{[]byte(`null`)}, nil, false},
		{"fail", args{[]byte(`["foo"`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got OCSPServer
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("OCSPServer.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("OCSPServer.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOCSPServer_Set(t *testing.T) {
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name string
		o    OCSPServer
		args args
		want *x509.Certificate
	}{
		{"ok", []string{"oscp.server"}, args{&x509.Certificate{}}, &x509.Certificate{OCSPServer: []string{"oscp.server"}}},
		{"overwrite", []string{"oscp.server", "oscp.com"}, args{&x509.Certificate{OCSPServer: []string{"oscp.server"}}}, &x509.Certificate{OCSPServer: []string{"oscp.server", "oscp.com"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.o.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("OCSPServer.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestIssuingCertificateURL_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    IssuingCertificateURL
		wantErr bool
	}{
		{"string", args{[]byte(`"foo"`)}, []string{"foo"}, false},
		{"array", args{[]byte(`["foo", "bar", "zar"]`)}, []string{"foo", "bar", "zar"}, false},
		{"empty", args{[]byte(`[]`)}, []string{}, false},
		{"null", args{[]byte(`null`)}, nil, false},
		{"fail", args{[]byte(`["foo"`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got IssuingCertificateURL
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("IssuingCertificateURL.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IssuingCertificateURL.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIssuingCertificateURL_Set(t *testing.T) {
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name string
		o    IssuingCertificateURL
		args args
		want *x509.Certificate
	}{
		{"ok", []string{"issuing.server"}, args{&x509.Certificate{}}, &x509.Certificate{IssuingCertificateURL: []string{"issuing.server"}}},
		{"overwrite", []string{"issuing.server", "issuing.com"}, args{&x509.Certificate{IssuingCertificateURL: []string{"issuing.server"}}}, &x509.Certificate{IssuingCertificateURL: []string{"issuing.server", "issuing.com"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.o.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("IssuingCertificateURL.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestCRLDistributionPoints_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    CRLDistributionPoints
		wantErr bool
	}{
		{"string", args{[]byte(`"foo"`)}, []string{"foo"}, false},
		{"array", args{[]byte(`["foo", "bar", "zar"]`)}, []string{"foo", "bar", "zar"}, false},
		{"empty", args{[]byte(`[]`)}, []string{}, false},
		{"null", args{[]byte(`null`)}, nil, false},
		{"fail", args{[]byte(`["foo"`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got CRLDistributionPoints
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("CRLDistributionPoints.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CRLDistributionPoints.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCRLDistributionPoints_Set(t *testing.T) {
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name string
		o    CRLDistributionPoints
		args args
		want *x509.Certificate
	}{
		{"ok", []string{"crl.server"}, args{&x509.Certificate{}}, &x509.Certificate{CRLDistributionPoints: []string{"crl.server"}}},
		{"overwrite", []string{"crl.server", "crl.com"}, args{&x509.Certificate{CRLDistributionPoints: []string{"crl.server"}}}, &x509.Certificate{CRLDistributionPoints: []string{"crl.server", "crl.com"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.o.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("CRLDistributionPoints.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestPolicyIdentifiers_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		m       PolicyIdentifiers
		want    []byte
		wantErr bool
	}{
		{"ok", []asn1.ObjectIdentifier{[]int{1, 2, 3, 4}, []int{5, 6, 7, 8, 9, 0}}, []byte(`["1.2.3.4","5.6.7.8.9.0"]`), false},
		{"empty", []asn1.ObjectIdentifier{}, []byte(`[]`), false},
		{"nil", nil, []byte(`null`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.m)
			if (err != nil) != tt.wantErr {
				t.Errorf("PolicyIdentifiers.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PolicyIdentifiers.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyIdentifiers_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    PolicyIdentifiers
		wantErr bool
	}{
		{"string", args{[]byte(`"1.2.3.4"`)}, []asn1.ObjectIdentifier{[]int{1, 2, 3, 4}}, false},
		{"array", args{[]byte(`["1.2.3.4", "5.6.7.8.9.0"]`)}, []asn1.ObjectIdentifier{[]int{1, 2, 3, 4}, []int{5, 6, 7, 8, 9, 0}}, false},
		{"empty", args{[]byte(`[]`)}, []asn1.ObjectIdentifier{}, false},
		{"null", args{[]byte(`null`)}, nil, false},
		{"fail", args{[]byte(`":foo:bar"`)}, nil, true},
		{"failJSON", args{[]byte(`["https://iss#sub"`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got PolicyIdentifiers
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("PolicyIdentifiers.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PolicyIdentifiers.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyIdentifiers_Set(t *testing.T) {
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name string
		o    PolicyIdentifiers
		args args
		want *x509.Certificate
	}{
		{"ok", []asn1.ObjectIdentifier{{1, 2, 3, 4}}, args{&x509.Certificate{}}, &x509.Certificate{PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}}}},
		{"overwrite", []asn1.ObjectIdentifier{{1, 2, 3, 4}, {4, 3, 2, 1}}, args{&x509.Certificate{PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}}}}, &x509.Certificate{PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}, {4, 3, 2, 1}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.o.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("PolicyIdentifiers.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestBasicConstraints_Set(t *testing.T) {
	type fields struct {
		IsCA       bool
		MaxPathLen int
	}
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *x509.Certificate
	}{
		{"IsCAFalse", fields{false, 0}, args{&x509.Certificate{}}, &x509.Certificate{}},
		{"IsCAFalseWithPathLen", fields{false, 1}, args{&x509.Certificate{}}, &x509.Certificate{}},
		{"IsCAFalseWithAnyPathLen", fields{false, -1}, args{&x509.Certificate{}}, &x509.Certificate{}},
		{"IsCATrue", fields{true, 0}, args{&x509.Certificate{}}, &x509.Certificate{IsCA: true, MaxPathLen: 0, MaxPathLenZero: true, BasicConstraintsValid: true}},
		{"IsCATrueWithPathLen", fields{true, 1}, args{&x509.Certificate{}}, &x509.Certificate{IsCA: true, MaxPathLen: 1, MaxPathLenZero: false, BasicConstraintsValid: true}},
		{"IsCATrueWithAnyPathLen", fields{true, -1}, args{&x509.Certificate{}}, &x509.Certificate{IsCA: true, MaxPathLen: -1, MaxPathLenZero: false, BasicConstraintsValid: true}},
		{"overwriteToFalse", fields{false, 0}, args{&x509.Certificate{IsCA: true, MaxPathLen: 0, MaxPathLenZero: true, BasicConstraintsValid: true}}, &x509.Certificate{}},
		{"overwriteToTrue", fields{true, -100}, args{&x509.Certificate{IsCA: true, MaxPathLen: 0, MaxPathLenZero: true, BasicConstraintsValid: true}}, &x509.Certificate{IsCA: true, MaxPathLen: -1, MaxPathLenZero: false, BasicConstraintsValid: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BasicConstraints{
				IsCA:       tt.fields.IsCA,
				MaxPathLen: tt.fields.MaxPathLen,
			}
			b.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("BasicConstraints.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestNameConstraints_Set(t *testing.T) {
	ipNet := func(s string) *net.IPNet {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return ipNet
	}
	type fields struct {
		Critical                bool
		PermittedDNSDomains     MultiString
		ExcludedDNSDomains      MultiString
		PermittedIPRanges       MultiIPNet
		ExcludedIPRanges        MultiIPNet
		PermittedEmailAddresses MultiString
		ExcludedEmailAddresses  MultiString
		PermittedURIDomains     MultiString
		ExcludedURIDomains      MultiString
	}
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *x509.Certificate
	}{
		{"ok", fields{
			Critical:                true,
			PermittedDNSDomains:     []string{"foo.com", "bar.com"},
			ExcludedDNSDomains:      []string{"zar.com"},
			PermittedIPRanges:       []*net.IPNet{ipNet("1.2.0.0/16"), ipNet("2.3.4.0/8")},
			ExcludedIPRanges:        []*net.IPNet{ipNet("3.0.0.0/24")},
			PermittedEmailAddresses: []string{"root@foo.com"},
			ExcludedEmailAddresses:  []string{"admin@foo.com", "root@bar.com", "admin@bar.com"},
			PermittedURIDomains:     []string{".foo.com", ".bar.com"},
			ExcludedURIDomains:      []string{".zar.com"},
		}, args{&x509.Certificate{}}, &x509.Certificate{
			PermittedDNSDomainsCritical: true,
			PermittedDNSDomains:         []string{"foo.com", "bar.com"},
			ExcludedDNSDomains:          []string{"zar.com"},
			PermittedIPRanges:           []*net.IPNet{ipNet("1.2.0.0/16"), ipNet("2.3.4.0/8")},
			ExcludedIPRanges:            []*net.IPNet{ipNet("3.0.0.0/24")},
			PermittedEmailAddresses:     []string{"root@foo.com"},
			ExcludedEmailAddresses:      []string{"admin@foo.com", "root@bar.com", "admin@bar.com"},
			PermittedURIDomains:         []string{".foo.com", ".bar.com"},
			ExcludedURIDomains:          []string{".zar.com"},
		}},
		{"overwrite", fields{}, args{&x509.Certificate{
			PermittedDNSDomainsCritical: true,
			PermittedDNSDomains:         []string{"foo.com", "bar.com"},
			ExcludedDNSDomains:          []string{"zar.com"},
			PermittedIPRanges:           []*net.IPNet{ipNet("1.2.0.0/16"), ipNet("2.3.4.0/8")},
			ExcludedIPRanges:            []*net.IPNet{ipNet("3.0.0.0/24")},
			PermittedEmailAddresses:     []string{"root@foo.com"},
			ExcludedEmailAddresses:      []string{"admin@foo.com", "root@bar.com", "admin@bar.com"},
			PermittedURIDomains:         []string{".foo.com", ".bar.com"},
			ExcludedURIDomains:          []string{".zar.com"},
		}}, &x509.Certificate{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NameConstraints{
				Critical:                tt.fields.Critical,
				PermittedDNSDomains:     tt.fields.PermittedDNSDomains,
				ExcludedDNSDomains:      tt.fields.ExcludedDNSDomains,
				PermittedIPRanges:       tt.fields.PermittedIPRanges,
				ExcludedIPRanges:        tt.fields.ExcludedIPRanges,
				PermittedEmailAddresses: tt.fields.PermittedEmailAddresses,
				ExcludedEmailAddresses:  tt.fields.ExcludedEmailAddresses,
				PermittedURIDomains:     tt.fields.PermittedURIDomains,
				ExcludedURIDomains:      tt.fields.ExcludedURIDomains,
			}
			n.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("NameConstraints.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestSerialNumber_Set(t *testing.T) {
	type fields struct {
		Int *big.Int
	}
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *x509.Certificate
	}{
		{"ok", fields{big.NewInt(1234)}, args{&x509.Certificate{}}, &x509.Certificate{SerialNumber: big.NewInt(1234)}},
		{"overwrite", fields{big.NewInt(4321)}, args{&x509.Certificate{SerialNumber: big.NewInt(1234)}}, &x509.Certificate{SerialNumber: big.NewInt(4321)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := SerialNumber{
				Int: tt.fields.Int,
			}
			s.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("SerialNumber.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestSerialNumber_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		sn      *SerialNumber
		want    []byte
		wantErr bool
	}{
		{"ok", &SerialNumber{big.NewInt(1234)}, []byte("1234"), false},
		{"nilStruct", nil, []byte("null"), false},
		{"nilBigInt", &SerialNumber{}, []byte("null"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sn.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("SerialNumber.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SerialNumber.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSerialNumber_UnmarshalJSON(t *testing.T) {
	expected := SerialNumber{big.NewInt(12345)}

	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    SerialNumber
		wantErr bool
	}{
		{"string", args{[]byte(`"12345"`)}, expected, false},
		{"stringHex", args{[]byte(`"0x3039"`)}, expected, false},
		{"number", args{[]byte(`12345`)}, expected, false},
		{"badString", args{[]byte(`"123s"`)}, SerialNumber{}, true},
		{"object", args{[]byte(`{}`)}, SerialNumber{}, true},
		{"badJSON", args{[]byte(`{`)}, SerialNumber{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s SerialNumber
			if err := s.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("SerialNumber.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(s, tt.want) {
				t.Errorf("SerialNumber.UnmarshalJSON() = %v, want %v", s, tt.want)
			}
		})
	}
}
