package cloudcas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"

	pb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
)

var (
	testLeafPrivateKey = `-----BEGIN PUBLIC KEY-----
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
					Subject:    &pb.Subject{},
					CommonName: "test.smallstep.com",
					SubjectAltName: &pb.SubjectAltNames{
						DnsNames: []string{"test.smallstep.com"},
					},
				},
				ReusableConfig: &pb.ReusableConfigWrapper{
					ConfigValues: &pb.ReusableConfigWrapper_ReusableConfigValues{
						ReusableConfigValues: &pb.ReusableConfigValues{
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
					},
				},
				PublicKey: &pb.PublicKey{
					Type: pb.PublicKey_PEM_EC_KEY,
					Key:  []byte(testLeafPrivateKey),
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
				t.Errorf("createCertificateConfig() = %v, want %v", got.Config.ReusableConfig, tt.want.Config.ReusableConfig)
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
			Type: pb.PublicKey_PEM_EC_KEY,
			Key:  []byte(testLeafPrivateKey),
		}, false},
		{"ok rsa", args{rsaCert.PublicKey}, &pb.PublicKey{
			Type: pb.PublicKey_PEM_RSA_KEY,
			Key:  []byte(testRSAPublicKey),
		}, false},
		{"fail ed25519", args{edpub}, nil, true},
		{"fail ec marshal", args{&ecdsa.PublicKey{
			Curve: &elliptic.CurveParams{Name: "FOO", BitSize: 256},
			X:     ecCert.PublicKey.(*ecdsa.PublicKey).X,
			Y:     ecCert.PublicKey.(*ecdsa.PublicKey).Y,
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
	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want *pb.SubjectAltNames
	}{
		{"ok empty", args{&x509.Certificate{}}, &pb.SubjectAltNames{}},
		// TODO
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createSubjectAlternativeNames(tt.args.cert); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createSubjectAlternativeNames() = %v, want %v", got, tt.want)
			}
		})
	}
}
