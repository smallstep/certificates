package cloudcas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"net/url"
	"reflect"
	"testing"

	pb "cloud.google.com/go/security/privateca/apiv1/privatecapb"
	kmsapi "go.step.sm/crypto/kms/apiv1"
)

var (
	testLeafPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAdUSRBrpgHFilN4eaGlNnX2+xfjX
a1Iwk2/+AensjFTXJi1UAIB0e+4pqi7Sen5E2QVBhntEHCrA3xOf7czgPw==
-----END PUBLIC KEY-----
`
	testRSACertificate = `-----BEGIN CERTIFICATE-----
MIICozCCAkmgAwIBAgIRANNhMpODj7ThgviZCoF6kj8wCgYIKoZIzj0EAwIwKjEo
MCYGA1UEAxMfR29vZ2xlIENBUyBUZXN0IEludGVybWVkaWF0ZSBDQTAeFw0yMDA5
MTUwMTUxMDdaFw0zMDA5MTMwMTUxMDNaMB0xGzAZBgNVBAMTEnRlc3Quc21hbGxz
dGVwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANPRjuIlsP5Z
672syAsHlbILFabG/xmrlsO0UdcLo4Yjf9WPAFA+7q+CsVDFh4dQbMv96fsHtdYP
E9wlWyMqYG+5E8QT2i0WNFEoYcXOGZuXdyD/TA5Aucu1RuYLrZXQrXWDnvaWOgvr
EZ6s9VsPCzzkL8KBejIMQIMY0KXEJfB/HgXZNn8V2trZkWT5CzxbcOF3s3UC1Z6F
Ja6zjpxhSyRkqgknJxv6yK4t7HEwdhrDI8uyxJYHPQWKNRjWecHWE9E+MtoS7D08
mTh8qlAKoBbkGolR2nJSXffU09F3vSg+MIfjPiRqjf6394cQ3T9D5yZK//rCrxWU
8KKBQMEmdKcCAwEAAaOBkTCBjjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQffuoYvH1+IF1cipl35gXJxSJE
SjAfBgNVHSMEGDAWgBRIOVqyLDSlErJLuWWEvRm5UU1r1TAdBgNVHREEFjAUghJ0
ZXN0LnNtYWxsc3RlcC5jb20wCgYIKoZIzj0EAwIDSAAwRQIhAL9AAw/LVLvvxBkM
sJnHd+RIk7ZblkgcArwpIS2+Z5xNAiBtUED4zyimz9b4aQiXdw4IMd2CKxVyW8eE
6x1vSZMvzQ==
-----END CERTIFICATE-----`
	testRSAPublicKey = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA09GO4iWw/lnrvazICweVsgsVpsb/GauWw7RR1wujhiN/1Y8AUD7u
r4KxUMWHh1Bsy/3p+we11g8T3CVbIypgb7kTxBPaLRY0UShhxc4Zm5d3IP9MDkC5
y7VG5gutldCtdYOe9pY6C+sRnqz1Ww8LPOQvwoF6MgxAgxjQpcQl8H8eBdk2fxXa
2tmRZPkLPFtw4XezdQLVnoUlrrOOnGFLJGSqCScnG/rIri3scTB2GsMjy7LElgc9
BYo1GNZ5wdYT0T4y2hLsPTyZOHyqUAqgFuQaiVHaclJd99TT0Xe9KD4wh+M+JGqN
/rf3hxDdP0PnJkr/+sKvFZTwooFAwSZ0pwIDAQAB
-----END RSA PUBLIC KEY-----
`
)

func Test_createCertificateConfig(t *testing.T) {
	cert := mustParseCertificate(t, testLeafCertificate)
	type args struct {
		tpl *x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		want    *pb.Certificate_Config
		wantErr bool
	}{
		{"ok", args{cert}, &pb.Certificate_Config{
			Config: &pb.CertificateConfig{
				SubjectConfig: &pb.CertificateConfig_SubjectConfig{
					Subject: &pb.Subject{
						CommonName: "test.smallstep.com",
					},
					SubjectAltName: &pb.SubjectAltNames{
						DnsNames: []string{"test.smallstep.com"},
					},
				},
				X509Config: &pb.X509Parameters{
					KeyUsage: &pb.KeyUsage{
						BaseKeyUsage: &pb.KeyUsage_KeyUsageOptions{
							DigitalSignature: true,
						},
						ExtendedKeyUsage: &pb.KeyUsage_ExtendedKeyUsageOptions{
							ClientAuth: true,
							ServerAuth: true,
						},
					},
				},
				PublicKey: &pb.PublicKey{
					Key:    []byte(testLeafPublicKey),
					Format: pb.PublicKey_PEM,
				},
			},
		}, false},
		{"fail", args{&x509.Certificate{}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createCertificateConfig(tt.args.tpl)
			if (err != nil) != tt.wantErr {
				t.Errorf("createCertificateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createCertificateConfig() = %v, want %v", got.Config, tt.want.Config)
			}
		})
	}
}

func Test_createPublicKey(t *testing.T) {
	edpub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecCert := mustParseCertificate(t, testLeafCertificate)
	ecCertPublicKey := ecCert.PublicKey.(*ecdsa.PublicKey)
	rsaCert := mustParseCertificate(t, testRSACertificate)
	type args struct {
		key crypto.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    *pb.PublicKey
		wantErr bool
	}{
		{"ok ec", args{ecCert.PublicKey}, &pb.PublicKey{
			Format: pb.PublicKey_PEM,
			Key:    []byte(testLeafPublicKey),
		}, false},
		{"ok rsa", args{rsaCert.PublicKey}, &pb.PublicKey{
			Format: pb.PublicKey_PEM,
			Key:    []byte(testRSAPublicKey),
		}, false},
		{"fail ed25519", args{edpub}, nil, true},
		{"fail ec marshal", args{&ecdsa.PublicKey{
			Curve: &elliptic.CurveParams{
				Name:    "FOO",
				BitSize: 256,
				P:       ecCertPublicKey.Params().P,
				B:       ecCertPublicKey.Params().B,
			},
			X: ecCertPublicKey.X,
			Y: ecCertPublicKey.Y,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createPublicKey(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("createPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_createSubject(t *testing.T) {
	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want *pb.Subject
	}{
		{"ok empty", args{&x509.Certificate{}}, &pb.Subject{}},
		{"ok all", args{&x509.Certificate{
			Subject: pkix.Name{
				Country:            []string{"US"},
				Organization:       []string{"Smallstep Labs"},
				OrganizationalUnit: []string{"Engineering"},
				Locality:           []string{"San Francisco"},
				Province:           []string{"California"},
				StreetAddress:      []string{"1 A St."},
				PostalCode:         []string{"12345"},
				SerialNumber:       "1234567890",
				CommonName:         "test.smallstep.com",
			},
		}}, &pb.Subject{
			CountryCode:        "US",
			Organization:       "Smallstep Labs",
			OrganizationalUnit: "Engineering",
			Locality:           "San Francisco",
			Province:           "California",
			StreetAddress:      "1 A St.",
			PostalCode:         "12345",
			CommonName:         "test.smallstep.com",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createSubject(tt.args.cert); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createSubject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_createSubjectAlternativeNames(t *testing.T) {
	marshalRawValues := func(rawValues []asn1.RawValue) []byte {
		b, err := asn1.Marshal(rawValues)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	uri := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want *pb.SubjectAltNames
	}{
		{"ok empty", args{&x509.Certificate{}}, &pb.SubjectAltNames{}},
		{"ok dns", args{&x509.Certificate{DNSNames: []string{
			"doe.com", "doe.org",
		}}}, &pb.SubjectAltNames{DnsNames: []string{"doe.com", "doe.org"}}},
		{"ok emails", args{&x509.Certificate{EmailAddresses: []string{
			"john@doe.com", "jane@doe.com",
		}}}, &pb.SubjectAltNames{EmailAddresses: []string{"john@doe.com", "jane@doe.com"}}},
		{"ok ips", args{&x509.Certificate{IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"), net.ParseIP("1.2.3.4"),
			net.ParseIP("::1"), net.ParseIP("2001:0db8:85a3:a0b:12f0:8a2e:0370:7334"), net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
		}}}, &pb.SubjectAltNames{IpAddresses: []string{"127.0.0.1", "1.2.3.4", "::1", "2001:db8:85a3:a0b:12f0:8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334"}}},
		{"ok uris", args{&x509.Certificate{URIs: []*url.URL{
			uri("mailto:john@doe.com"), uri("https://john@doe.com/hello"),
		}}}, &pb.SubjectAltNames{Uris: []string{"mailto:john@doe.com", "https://john@doe.com/hello"}}},
		{"ok extensions", args{&x509.Certificate{
			ExtraExtensions: []pkix.Extension{{
				Id: []int{2, 5, 29, 17}, Critical: true, Value: []byte{
					0x30, 0x48, 0x82, 0x0b, 0x77, 0x77, 0x77, 0x2e, 0x64, 0x6f, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x81,
					0x0c, 0x6a, 0x61, 0x6e, 0x65, 0x40, 0x64, 0x6f, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x87, 0x04, 0x01,
					0x02, 0x03, 0x04, 0x87, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x0a, 0x0b, 0x12, 0xf0, 0x8a,
					0x2e, 0x03, 0x70, 0x73, 0x34, 0x86, 0x13, 0x6d, 0x61, 0x69, 0x6c, 0x74, 0x6f, 0x3a, 0x6a, 0x61,
					0x6e, 0x65, 0x40, 0x64, 0x6f, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
				},
			}},
		}}, &pb.SubjectAltNames{
			CustomSans: []*pb.X509Extension{{
				ObjectId: &pb.ObjectId{ObjectIdPath: []int32{2, 5, 29, 17}},
				Critical: true,
				Value: []byte{
					0x30, 0x48, 0x82, 0x0b, 0x77, 0x77, 0x77, 0x2e, 0x64, 0x6f, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x81,
					0x0c, 0x6a, 0x61, 0x6e, 0x65, 0x40, 0x64, 0x6f, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x87, 0x04, 0x01,
					0x02, 0x03, 0x04, 0x87, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x0a, 0x0b, 0x12, 0xf0, 0x8a,
					0x2e, 0x03, 0x70, 0x73, 0x34, 0x86, 0x13, 0x6d, 0x61, 0x69, 0x6c, 0x74, 0x6f, 0x3a, 0x6a, 0x61,
					0x6e, 0x65, 0x40, 0x64, 0x6f, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
				},
			}},
		}},
		{"ok extra extensions", args{&x509.Certificate{
			DNSNames: []string{"doe.com"},
			ExtraExtensions: []pkix.Extension{{
				Id: []int{2, 5, 29, 17}, Critical: true, Value: marshalRawValues([]asn1.RawValue{
					{Class: asn1.ClassApplication, Tag: 2, IsCompound: true, Bytes: []byte{}},
					{Class: asn1.ClassContextSpecific, Tag: nameTypeDNS, Bytes: []byte("doe.com")},
					{Class: asn1.ClassContextSpecific, Tag: nameTypeEmail, Bytes: []byte("jane@doe.com")},
					{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: []byte("foo.bar")},
				}),
			}},
		}}, &pb.SubjectAltNames{
			DnsNames: []string{"doe.com"},
			CustomSans: []*pb.X509Extension{{
				ObjectId: &pb.ObjectId{ObjectIdPath: []int32{2, 5, 29, 17}},
				Critical: true,
				Value: marshalRawValues([]asn1.RawValue{
					{Class: asn1.ClassApplication, Tag: 2, IsCompound: true, Bytes: []byte{}},
					{Class: asn1.ClassContextSpecific, Tag: nameTypeEmail, Bytes: []byte("jane@doe.com")},
					{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: []byte("foo.bar")},
				}),
			}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createSubjectAlternativeNames(tt.args.cert); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createSubjectAlternativeNames() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_createX509Parameters(t *testing.T) {
	withKU := func(ku *pb.KeyUsage) *pb.X509Parameters {
		if ku.BaseKeyUsage == nil {
			ku.BaseKeyUsage = &pb.KeyUsage_KeyUsageOptions{}
		}
		if ku.ExtendedKeyUsage == nil {
			ku.ExtendedKeyUsage = &pb.KeyUsage_ExtendedKeyUsageOptions{}
		}
		return &pb.X509Parameters{
			KeyUsage: ku,
		}
	}
	withRCV := func(rcv *pb.X509Parameters) *pb.X509Parameters {
		if rcv.KeyUsage == nil {
			rcv.KeyUsage = &pb.KeyUsage{
				BaseKeyUsage:     &pb.KeyUsage_KeyUsageOptions{},
				ExtendedKeyUsage: &pb.KeyUsage_ExtendedKeyUsageOptions{},
			}
		}
		return rcv
	}

	vTrue := true
	vFalse := false
	vZero := int32(0)
	vOne := int32(1)

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want *pb.X509Parameters
	}{
		{"keyUsageDigitalSignature", args{&x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature,
		}}, &pb.X509Parameters{
			KeyUsage: &pb.KeyUsage{
				BaseKeyUsage: &pb.KeyUsage_KeyUsageOptions{
					DigitalSignature: true,
				},
				ExtendedKeyUsage:         &pb.KeyUsage_ExtendedKeyUsageOptions{},
				UnknownExtendedKeyUsages: nil,
			},
			CaOptions:            nil,
			PolicyIds:            nil,
			AiaOcspServers:       nil,
			AdditionalExtensions: nil,
		}},
		// KeyUsage
		{"KeyUsageDigitalSignature", args{&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature}}, withKU(&pb.KeyUsage{
			BaseKeyUsage: &pb.KeyUsage_KeyUsageOptions{
				DigitalSignature: true,
			},
		})},
		{"KeyUsageContentCommitment", args{&x509.Certificate{KeyUsage: x509.KeyUsageContentCommitment}}, withKU(&pb.KeyUsage{
			BaseKeyUsage: &pb.KeyUsage_KeyUsageOptions{
				ContentCommitment: true,
			},
		})},
		{"KeyUsageKeyEncipherment", args{&x509.Certificate{KeyUsage: x509.KeyUsageKeyEncipherment}}, withKU(&pb.KeyUsage{
			BaseKeyUsage: &pb.KeyUsage_KeyUsageOptions{
				KeyEncipherment: true,
			},
		})},
		{"KeyUsageDataEncipherment", args{&x509.Certificate{KeyUsage: x509.KeyUsageDataEncipherment}}, withKU(&pb.KeyUsage{
			BaseKeyUsage: &pb.KeyUsage_KeyUsageOptions{
				DataEncipherment: true,
			},
		})},
		{"KeyUsageKeyAgreement", args{&x509.Certificate{KeyUsage: x509.KeyUsageKeyAgreement}}, withKU(&pb.KeyUsage{
			BaseKeyUsage: &pb.KeyUsage_KeyUsageOptions{
				KeyAgreement: true,
			},
		})},
		{"KeyUsageCertSign", args{&x509.Certificate{KeyUsage: x509.KeyUsageCertSign}}, withKU(&pb.KeyUsage{
			BaseKeyUsage: &pb.KeyUsage_KeyUsageOptions{
				CertSign: true,
			},
		})},
		{"KeyUsageCRLSign", args{&x509.Certificate{KeyUsage: x509.KeyUsageCRLSign}}, withKU(&pb.KeyUsage{
			BaseKeyUsage: &pb.KeyUsage_KeyUsageOptions{
				CrlSign: true,
			},
		})},
		{"KeyUsageEncipherOnly", args{&x509.Certificate{KeyUsage: x509.KeyUsageEncipherOnly}}, withKU(&pb.KeyUsage{
			BaseKeyUsage: &pb.KeyUsage_KeyUsageOptions{
				EncipherOnly: true,
			},
		})},
		{"KeyUsageDecipherOnly", args{&x509.Certificate{KeyUsage: x509.KeyUsageDecipherOnly}}, withKU(&pb.KeyUsage{
			BaseKeyUsage: &pb.KeyUsage_KeyUsageOptions{
				DecipherOnly: true,
			},
		})},
		// ExtKeyUsage
		{"ExtKeyUsageAny", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}}, withKU(&pb.KeyUsage{
			UnknownExtendedKeyUsages: []*pb.ObjectId{{ObjectIdPath: []int32{2, 5, 29, 37, 0}}},
		})},
		{"ExtKeyUsageServerAuth", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}}, withKU(&pb.KeyUsage{
			ExtendedKeyUsage: &pb.KeyUsage_ExtendedKeyUsageOptions{
				ServerAuth: true,
			},
		})},
		{"ExtKeyUsageClientAuth", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}}, withKU(&pb.KeyUsage{
			ExtendedKeyUsage: &pb.KeyUsage_ExtendedKeyUsageOptions{
				ClientAuth: true,
			},
		})},
		{"ExtKeyUsageCodeSigning", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}}, withKU(&pb.KeyUsage{
			ExtendedKeyUsage: &pb.KeyUsage_ExtendedKeyUsageOptions{
				CodeSigning: true,
			},
		})},
		{"ExtKeyUsageEmailProtection", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}}}, withKU(&pb.KeyUsage{
			ExtendedKeyUsage: &pb.KeyUsage_ExtendedKeyUsageOptions{
				EmailProtection: true,
			},
		})},
		{"ExtKeyUsageIPSECEndSystem", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageIPSECEndSystem}}}, withKU(&pb.KeyUsage{
			UnknownExtendedKeyUsages: []*pb.ObjectId{{ObjectIdPath: []int32{1, 3, 6, 1, 5, 5, 7, 3, 5}}},
		})},
		{"ExtKeyUsageIPSECTunnel", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageIPSECTunnel}}}, withKU(&pb.KeyUsage{
			UnknownExtendedKeyUsages: []*pb.ObjectId{{ObjectIdPath: []int32{1, 3, 6, 1, 5, 5, 7, 3, 6}}},
		})},
		{"ExtKeyUsageIPSECUser", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageIPSECUser}}}, withKU(&pb.KeyUsage{
			UnknownExtendedKeyUsages: []*pb.ObjectId{{ObjectIdPath: []int32{1, 3, 6, 1, 5, 5, 7, 3, 7}}},
		})},
		{"ExtKeyUsageTimeStamping", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}}, withKU(&pb.KeyUsage{
			ExtendedKeyUsage: &pb.KeyUsage_ExtendedKeyUsageOptions{
				TimeStamping: true,
			},
		})},
		{"ExtKeyUsageOCSPSigning", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}}, withKU(&pb.KeyUsage{
			ExtendedKeyUsage: &pb.KeyUsage_ExtendedKeyUsageOptions{
				OcspSigning: true,
			},
		})},
		{"ExtKeyUsageMicrosoftServerGatedCrypto", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageMicrosoftServerGatedCrypto}}}, withKU(&pb.KeyUsage{
			UnknownExtendedKeyUsages: []*pb.ObjectId{{ObjectIdPath: []int32{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}}},
		})},
		{"ExtKeyUsageNetscapeServerGatedCrypto", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageNetscapeServerGatedCrypto}}}, withKU(&pb.KeyUsage{
			UnknownExtendedKeyUsages: []*pb.ObjectId{{ObjectIdPath: []int32{2, 16, 840, 1, 113730, 4, 1}}},
		})},
		{"ExtKeyUsageMicrosoftCommercialCodeSigning", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageMicrosoftCommercialCodeSigning}}}, withKU(&pb.KeyUsage{
			UnknownExtendedKeyUsages: []*pb.ObjectId{{ObjectIdPath: []int32{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}}},
		})},
		{"ExtKeyUsageMicrosoftKernelCodeSigning", args{&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageMicrosoftKernelCodeSigning}}}, withKU(&pb.KeyUsage{
			UnknownExtendedKeyUsages: []*pb.ObjectId{{ObjectIdPath: []int32{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}}},
		})},
		// UnknownExtendedKeyUsages
		{"UnknownExtKeyUsage", args{&x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 2, 3, 4}, {4, 3, 2, 1}}}}, withKU(&pb.KeyUsage{
			UnknownExtendedKeyUsages: []*pb.ObjectId{
				{ObjectIdPath: []int32{1, 2, 3, 4}},
				{ObjectIdPath: []int32{4, 3, 2, 1}},
			},
		})},
		// BasicCre
		{"BasicConstraintsCAMax0", args{&x509.Certificate{BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true}}, withRCV(&pb.X509Parameters{
			CaOptions: &pb.X509Parameters_CaOptions{
				IsCa:                &vTrue,
				MaxIssuerPathLength: &vZero,
			},
		})},
		{"BasicConstraintsCAMax1", args{&x509.Certificate{BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1, MaxPathLenZero: false}}, withRCV(&pb.X509Parameters{
			CaOptions: &pb.X509Parameters_CaOptions{
				IsCa:                &vTrue,
				MaxIssuerPathLength: &vOne,
			},
		})},
		{"BasicConstraintsCANoMax", args{&x509.Certificate{BasicConstraintsValid: true, IsCA: true, MaxPathLen: -1, MaxPathLenZero: false}}, withRCV(&pb.X509Parameters{
			CaOptions: &pb.X509Parameters_CaOptions{
				IsCa:                &vTrue,
				MaxIssuerPathLength: nil,
			},
		})},
		{"BasicConstraintsCANoMax0", args{&x509.Certificate{BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: false}}, withRCV(&pb.X509Parameters{
			CaOptions: &pb.X509Parameters_CaOptions{
				IsCa:                &vTrue,
				MaxIssuerPathLength: nil,
			},
		})},
		{"BasicConstraintsNoCA", args{&x509.Certificate{BasicConstraintsValid: true, IsCA: false, MaxPathLen: 0, MaxPathLenZero: false}}, withRCV(&pb.X509Parameters{
			CaOptions: &pb.X509Parameters_CaOptions{
				IsCa:                &vFalse,
				MaxIssuerPathLength: nil,
			},
		})},
		{"BasicConstraintsNoValid", args{&x509.Certificate{BasicConstraintsValid: false, IsCA: false, MaxPathLen: 0, MaxPathLenZero: false}}, withRCV(&pb.X509Parameters{
			CaOptions: nil,
		})},
		// PolicyIdentifiers
		{"PolicyIdentifiers", args{&x509.Certificate{PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}, {4, 3, 2, 1}}}}, withRCV(&pb.X509Parameters{
			PolicyIds: []*pb.ObjectId{
				{ObjectIdPath: []int32{1, 2, 3, 4}},
				{ObjectIdPath: []int32{4, 3, 2, 1}},
			},
		})},
		// OCSPServer
		{"OCPServers", args{&x509.Certificate{OCSPServer: []string{"https://oscp.doe.com", "https://doe.com/ocsp"}}}, withRCV(&pb.X509Parameters{
			AiaOcspServers: []string{"https://oscp.doe.com", "https://doe.com/ocsp"},
		})},
		// Extensions
		{"Extensions", args{&x509.Certificate{ExtraExtensions: []pkix.Extension{
			{Id: []int{1, 2, 3, 4}, Critical: true, Value: []byte("foobar")},
			{Id: []int{2, 5, 29, 17}, Critical: true, Value: []byte("SANs")}, //
			{Id: []int{4, 3, 2, 1}, Critical: false, Value: []byte("zoobar")},
			{Id: []int{2, 5, 29, 31}, Critical: false, Value: []byte("CRL Distribution points")},
		}}}, withRCV(&pb.X509Parameters{
			AdditionalExtensions: []*pb.X509Extension{
				{ObjectId: &pb.ObjectId{ObjectIdPath: []int32{1, 2, 3, 4}}, Critical: true, Value: []byte("foobar")},
				{ObjectId: &pb.ObjectId{ObjectIdPath: []int32{4, 3, 2, 1}}, Critical: false, Value: []byte("zoobar")},
			},
		})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createX509Parameters(tt.args.cert); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createX509Parameters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isExtraExtension(t *testing.T) {
	type args struct {
		oid asn1.ObjectIdentifier
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"oidExtensionSubjectKeyID", args{oidExtensionSubjectKeyID}, false},
		{"oidExtensionKeyUsage", args{oidExtensionKeyUsage}, false},
		{"oidExtensionExtendedKeyUsage", args{oidExtensionExtendedKeyUsage}, false},
		{"oidExtensionAuthorityKeyID", args{oidExtensionAuthorityKeyID}, false},
		{"oidExtensionBasicConstraints", args{oidExtensionBasicConstraints}, false},
		{"oidExtensionSubjectAltName", args{oidExtensionSubjectAltName}, false},
		{"oidExtensionCRLDistributionPoints", args{oidExtensionCRLDistributionPoints}, false},
		{"oidExtensionCertificatePolicies", args{oidExtensionCertificatePolicies}, false},
		{"oidExtensionAuthorityInfoAccess", args{oidExtensionAuthorityInfoAccess}, false},
		{"other", args{[]int{1, 2, 3, 4}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExtraExtension(tt.args.oid); got != tt.want {
				t.Errorf("isExtraExtension() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_createKeyVersionSpec(t *testing.T) {
	type args struct {
		alg  kmsapi.SignatureAlgorithm
		bits int
	}
	tests := []struct {
		name    string
		args    args
		want    *pb.CertificateAuthority_KeyVersionSpec
		wantErr bool
	}{
		{"ok P256", args{0, 0}, &pb.CertificateAuthority_KeyVersionSpec{
			KeyVersion: &pb.CertificateAuthority_KeyVersionSpec_Algorithm{
				Algorithm: pb.CertificateAuthority_EC_P256_SHA256,
			}}, false},
		{"ok P256", args{kmsapi.ECDSAWithSHA256, 0}, &pb.CertificateAuthority_KeyVersionSpec{
			KeyVersion: &pb.CertificateAuthority_KeyVersionSpec_Algorithm{
				Algorithm: pb.CertificateAuthority_EC_P256_SHA256,
			}}, false},
		{"ok P384", args{kmsapi.ECDSAWithSHA384, 0}, &pb.CertificateAuthority_KeyVersionSpec{
			KeyVersion: &pb.CertificateAuthority_KeyVersionSpec_Algorithm{
				Algorithm: pb.CertificateAuthority_EC_P384_SHA384,
			}}, false},
		{"ok RSA default", args{kmsapi.SHA256WithRSA, 0}, &pb.CertificateAuthority_KeyVersionSpec{
			KeyVersion: &pb.CertificateAuthority_KeyVersionSpec_Algorithm{
				Algorithm: pb.CertificateAuthority_RSA_PKCS1_3072_SHA256,
			}}, false},
		{"ok RSA 2048", args{kmsapi.SHA256WithRSA, 2048}, &pb.CertificateAuthority_KeyVersionSpec{
			KeyVersion: &pb.CertificateAuthority_KeyVersionSpec_Algorithm{
				Algorithm: pb.CertificateAuthority_RSA_PKCS1_2048_SHA256,
			}}, false},
		{"ok RSA 3072", args{kmsapi.SHA256WithRSA, 3072}, &pb.CertificateAuthority_KeyVersionSpec{
			KeyVersion: &pb.CertificateAuthority_KeyVersionSpec_Algorithm{
				Algorithm: pb.CertificateAuthority_RSA_PKCS1_3072_SHA256,
			}}, false},
		{"ok RSA 4096", args{kmsapi.SHA256WithRSA, 4096}, &pb.CertificateAuthority_KeyVersionSpec{
			KeyVersion: &pb.CertificateAuthority_KeyVersionSpec_Algorithm{
				Algorithm: pb.CertificateAuthority_RSA_PKCS1_4096_SHA256,
			}}, false},
		{"ok RSA-PSS default", args{kmsapi.SHA256WithRSAPSS, 0}, &pb.CertificateAuthority_KeyVersionSpec{
			KeyVersion: &pb.CertificateAuthority_KeyVersionSpec_Algorithm{
				Algorithm: pb.CertificateAuthority_RSA_PSS_3072_SHA256,
			}}, false},
		{"ok RSA-PSS 2048", args{kmsapi.SHA256WithRSAPSS, 2048}, &pb.CertificateAuthority_KeyVersionSpec{
			KeyVersion: &pb.CertificateAuthority_KeyVersionSpec_Algorithm{
				Algorithm: pb.CertificateAuthority_RSA_PSS_2048_SHA256,
			}}, false},
		{"ok RSA-PSS 3072", args{kmsapi.SHA256WithRSAPSS, 3072}, &pb.CertificateAuthority_KeyVersionSpec{
			KeyVersion: &pb.CertificateAuthority_KeyVersionSpec_Algorithm{
				Algorithm: pb.CertificateAuthority_RSA_PSS_3072_SHA256,
			}}, false},
		{"ok RSA-PSS 4096", args{kmsapi.SHA256WithRSAPSS, 4096}, &pb.CertificateAuthority_KeyVersionSpec{
			KeyVersion: &pb.CertificateAuthority_KeyVersionSpec_Algorithm{
				Algorithm: pb.CertificateAuthority_RSA_PSS_4096_SHA256,
			}}, false},
		{"fail Ed25519", args{kmsapi.PureEd25519, 0}, nil, true},
		{"fail RSA size", args{kmsapi.SHA256WithRSA, 1024}, nil, true},
		{"fail RSA-PSS size", args{kmsapi.SHA256WithRSAPSS, 1024}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createKeyVersionSpec(tt.args.alg, tt.args.bits)
			if (err != nil) != tt.wantErr {
				t.Errorf("createKeyVersionSpec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createKeyVersionSpec() = %v, want %v", got, tt.want)
			}
		})
	}
}
