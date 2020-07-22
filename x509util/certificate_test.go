package x509util

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"
)

func createCertificateRequest(t *testing.T, commonName string, sans []string) (*x509.CertificateRequest, crypto.Signer) {
	dnsNames, ips, emails, uris := SplitSANs(sans)
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	asn1Data, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		EmailAddresses:     emails,
		URIs:               uris,
		SignatureAlgorithm: x509.PureEd25519,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		t.Fatal(err)
	}
	return cr, priv
}

func createIssuerCertificate(t *testing.T, commonName string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	now := time.Now()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subjectKeyID, err := generateSubjectKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	sn, err := generateSerialNumber()
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		Issuer:                pkix.Name{CommonName: "issuer"},
		Subject:               pkix.Name{CommonName: "issuer"},
		SerialNumber:          sn,
		SubjectKeyId:          subjectKeyID,
	}
	asn1Data, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		t.Fatal(err)
	}
	return crt, priv
}

type badSigner struct {
	pub crypto.PublicKey
}

func createBadSigner(t *testing.T) *badSigner {
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

func (b *badSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("💥")
}

func TestNewCertificate(t *testing.T) {
	cr, priv := createCertificateRequest(t, "commonName", []string{"foo.com", "root@foo.com"})
	crBadSignateure, _ := createCertificateRequest(t, "fail", []string{"foo.com"})
	crBadSignateure.PublicKey = priv.Public()

	ipNet := func(s string) *net.IPNet {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return ipNet
	}

	type args struct {
		cr   *x509.CertificateRequest
		opts []Option
	}
	tests := []struct {
		name    string
		args    args
		want    *Certificate
		wantErr bool
	}{
		{"okSimple", args{cr, nil}, &Certificate{
			Subject:        Subject{CommonName: "commonName"},
			DNSNames:       []string{"foo.com"},
			EmailAddresses: []string{"root@foo.com"},
			KeyUsage:       KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			Extensions:         newExtensions(cr.Extensions),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.Ed25519,
		}, false},
		{"okDefaultTemplate", args{cr, []Option{WithTemplate(DefaultLeafTemplate, CreateTemplateData("commonName", []string{"foo.com"}))}}, &Certificate{
			Subject:  Subject{CommonName: "commonName"},
			SANs:     []SubjectAlternativeName{{Type: DNSType, Value: "foo.com"}},
			KeyUsage: KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.Ed25519,
		}, false},
		{"okExample", args{cr, []Option{WithTemplateFile("./testdata/example.tpl", TemplateData{
			SANsKey: []SubjectAlternativeName{
				{Type: "dns", Value: "foo.com"},
			},
			TokenKey: map[string]interface{}{
				"iss": "https://iss",
				"sub": "sub",
			},
		})}}, &Certificate{
			Subject:        Subject{CommonName: "commonName"},
			SANs:           []SubjectAlternativeName{{Type: DNSType, Value: "foo.com"}},
			EmailAddresses: []string{"root@foo.com"},
			URIs:           []*url.URL{{Scheme: "https", Host: "iss", Fragment: "sub"}},
			KeyUsage:       KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.Ed25519,
		}, false},
		{"okFullSimple", args{cr, []Option{WithTemplateFile("./testdata/fullsimple.tpl", TemplateData{})}}, &Certificate{
			Version:               3,
			Subject:               Subject{CommonName: "subjectCommonName"},
			SerialNumber:          SerialNumber{big.NewInt(78187493520)},
			Issuer:                Issuer{CommonName: "issuerCommonName"},
			DNSNames:              []string{"doe.com"},
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
			EmailAddresses:        []string{"jane@doe.com"},
			URIs:                  []*url.URL{{Scheme: "https", Host: "doe.com"}},
			SANs:                  []SubjectAlternativeName{{Type: DNSType, Value: "www.doe.com"}},
			Extensions:            []Extension{{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("extension")}},
			KeyUsage:              KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage:           ExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}),
			SubjectKeyID:          []byte("subjectKeyId"),
			AuthorityKeyID:        []byte("authorityKeyId"),
			OCSPServer:            []string{"https://ocsp.server"},
			IssuingCertificateURL: []string{"https://ca.com"},
			CRLDistributionPoints: []string{"https://ca.com/ca.crl"},
			PolicyIdentifiers:     PolicyIdentifiers{[]int{5, 6, 7, 8, 9, 0}},
			BasicConstraints: &BasicConstraints{
				IsCA:       false,
				MaxPathLen: 0,
			},
			NameConstraints: &NameConstraints{
				Critical:                true,
				PermittedDNSDomains:     []string{"jane.doe.com"},
				ExcludedDNSDomains:      []string{"john.doe.com"},
				PermittedIPRanges:       []*net.IPNet{ipNet("127.0.0.1/32")},
				ExcludedIPRanges:        []*net.IPNet{ipNet("0.0.0.0/0")},
				PermittedEmailAddresses: []string{"jane@doe.com"},
				ExcludedEmailAddresses:  []string{"john@doe.com"},
				PermittedURIDomains:     []string{"https://jane.doe.com"},
				ExcludedURIDomains:      []string{"https://john.doe.com"},
			},
			SignatureAlgorithm: SignatureAlgorithm(x509.PureEd25519),
			PublicKey:          priv.Public(),
			PublicKeyAlgorithm: x509.Ed25519,
		},
			false},
		{"badSignature", args{crBadSignateure, nil}, nil, true},
		{"failTemplate", args{cr, []Option{WithTemplate(`{{ fail "fatal error }}`, CreateTemplateData("commonName", []string{"foo.com"}))}}, nil, true},
		{"missingTemplate", args{cr, []Option{WithTemplateFile("./testdata/missing.tpl", CreateTemplateData("commonName", []string{"foo.com"}))}}, nil, true},
		{"badJson", args{cr, []Option{WithTemplate(`"this is not a json object"`, CreateTemplateData("commonName", []string{"foo.com"}))}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCertificate(tt.args.cr, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertificate_GetCertificate(t *testing.T) {
	type fields struct {
		Version               int
		Subject               Subject
		Issuer                Issuer
		SerialNumber          SerialNumber
		DNSNames              MultiString
		EmailAddresses        MultiString
		IPAddresses           MultiIP
		URIs                  MultiURL
		SANs                  []SubjectAlternativeName
		Extensions            []Extension
		KeyUsage              KeyUsage
		ExtKeyUsage           ExtKeyUsage
		SubjectKeyID          SubjectKeyID
		AuthorityKeyID        AuthorityKeyID
		OCSPServer            OCSPServer
		IssuingCertificateURL IssuingCertificateURL
		CRLDistributionPoints CRLDistributionPoints
		PolicyIdentifiers     PolicyIdentifiers
		BasicConstraints      *BasicConstraints
		NameConstraints       *NameConstraints
		SignatureAlgorithm    SignatureAlgorithm
		PublicKeyAlgorithm    x509.PublicKeyAlgorithm
		PublicKey             interface{}
	}
	tests := []struct {
		name   string
		fields fields
		want   *x509.Certificate
	}{
		{"ok", fields{
			Version:        3,
			Subject:        Subject{CommonName: "commonName", Organization: []string{"smallstep"}},
			Issuer:         Issuer{CommonName: "issuer", Organization: []string{"smallstep"}},
			SerialNumber:   SerialNumber{big.NewInt(123)},
			DNSNames:       []string{"foo.bar"},
			EmailAddresses: []string{"root@foo.com"},
			IPAddresses:    []net.IP{net.ParseIP("::1")},
			URIs:           []*url.URL{{Scheme: "mailto", Opaque: "root@foo.com"}},
			SANs: []SubjectAlternativeName{
				{Type: DNSType, Value: "www.foo.bar"},
				{Type: IPType, Value: "127.0.0.1"},
				{Type: EmailType, Value: "admin@foo.com"},
				{Type: URIType, Value: "mailto:admin@foo.com"},
			},
			Extensions: []Extension{{ID: []int{1, 2, 3, 4}, Critical: true, Value: []byte("custom extension")}},
			KeyUsage:   KeyUsage(x509.KeyUsageDigitalSignature),
			ExtKeyUsage: ExtKeyUsage([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			}),
			SubjectKeyID:          []byte("subject-key-id"),
			AuthorityKeyID:        []byte("authority-key-id"),
			OCSPServer:            []string{"https://oscp.server"},
			IssuingCertificateURL: []string{"https://ca.com"},
			CRLDistributionPoints: []string{"https://ca.com/crl"},
			PolicyIdentifiers:     []asn1.ObjectIdentifier{[]int{1, 2, 3, 4}},
			BasicConstraints:      &BasicConstraints{IsCA: true, MaxPathLen: 0},
			NameConstraints:       &NameConstraints{PermittedDNSDomains: []string{"foo.bar"}},
			SignatureAlgorithm:    SignatureAlgorithm(x509.PureEd25519),
			PublicKeyAlgorithm:    x509.Ed25519,
			PublicKey:             ed25519.PublicKey("public key"),
		}, &x509.Certificate{
			Version:         0,
			Subject:         pkix.Name{CommonName: "commonName", Organization: []string{"smallstep"}},
			Issuer:          pkix.Name{},
			SerialNumber:    big.NewInt(123),
			DNSNames:        []string{"foo.bar", "www.foo.bar"},
			EmailAddresses:  []string{"root@foo.com", "admin@foo.com"},
			IPAddresses:     []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")},
			URIs:            []*url.URL{{Scheme: "mailto", Opaque: "root@foo.com"}, {Scheme: "mailto", Opaque: "admin@foo.com"}},
			ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}, Critical: true, Value: []byte("custom extension")}},
			KeyUsage:        x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			},
			SubjectKeyId:          []byte("subject-key-id"),
			AuthorityKeyId:        []byte("authority-key-id"),
			OCSPServer:            []string{"https://oscp.server"},
			IssuingCertificateURL: []string{"https://ca.com"},
			CRLDistributionPoints: []string{"https://ca.com/crl"},
			PolicyIdentifiers:     []asn1.ObjectIdentifier{[]int{1, 2, 3, 4}},
			IsCA:                  true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
			BasicConstraintsValid: true,
			PermittedDNSDomains:   []string{"foo.bar"},
			SignatureAlgorithm:    x509.PureEd25519,
			PublicKeyAlgorithm:    x509.Ed25519,
			PublicKey:             ed25519.PublicKey("public key"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Certificate{
				Version:               tt.fields.Version,
				Subject:               tt.fields.Subject,
				Issuer:                tt.fields.Issuer,
				SerialNumber:          tt.fields.SerialNumber,
				DNSNames:              tt.fields.DNSNames,
				EmailAddresses:        tt.fields.EmailAddresses,
				IPAddresses:           tt.fields.IPAddresses,
				URIs:                  tt.fields.URIs,
				SANs:                  tt.fields.SANs,
				Extensions:            tt.fields.Extensions,
				KeyUsage:              tt.fields.KeyUsage,
				ExtKeyUsage:           tt.fields.ExtKeyUsage,
				SubjectKeyID:          tt.fields.SubjectKeyID,
				AuthorityKeyID:        tt.fields.AuthorityKeyID,
				OCSPServer:            tt.fields.OCSPServer,
				IssuingCertificateURL: tt.fields.IssuingCertificateURL,
				CRLDistributionPoints: tt.fields.CRLDistributionPoints,
				PolicyIdentifiers:     tt.fields.PolicyIdentifiers,
				BasicConstraints:      tt.fields.BasicConstraints,
				NameConstraints:       tt.fields.NameConstraints,
				SignatureAlgorithm:    tt.fields.SignatureAlgorithm,
				PublicKeyAlgorithm:    tt.fields.PublicKeyAlgorithm,
				PublicKey:             tt.fields.PublicKey,
			}
			if got := c.GetCertificate(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Certificate.GetCertificate() = \n%+v, want \n%+v", got, tt.want)
			}
		})
	}
}

func TestCreateCertificate(t *testing.T) {
	iss, issPriv := createIssuerCertificate(t, "issuer")

	mustSerialNumber := func() *big.Int {
		sn, err := generateSerialNumber()
		if err != nil {
			t.Fatal(err)
		}
		return sn
	}
	mustSubjectKeyID := func(pub crypto.PublicKey) []byte {
		b, err := generateSubjectKeyID(pub)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	cr1, priv1 := createCertificateRequest(t, "commonName", []string{"foo.com"})
	crt1 := newCertificateRequest(cr1).GetLeafCertificate().GetCertificate()
	crt1.SerialNumber = mustSerialNumber()
	crt1.SubjectKeyId = mustSubjectKeyID(priv1.Public())

	cr2, priv2 := createCertificateRequest(t, "commonName", []string{"foo.com"})
	crt2 := newCertificateRequest(cr2).GetLeafCertificate().GetCertificate()
	crt2.SerialNumber = mustSerialNumber()

	cr3, priv3 := createCertificateRequest(t, "commonName", []string{"foo.com"})
	crt3 := newCertificateRequest(cr3).GetLeafCertificate().GetCertificate()
	crt3.SubjectKeyId = mustSubjectKeyID(priv1.Public())

	cr4, priv4 := createCertificateRequest(t, "commonName", []string{"foo.com"})
	crt4 := newCertificateRequest(cr4).GetLeafCertificate().GetCertificate()

	cr5, _ := createCertificateRequest(t, "commonName", []string{"foo.com"})
	crt5 := newCertificateRequest(cr5).GetLeafCertificate().GetCertificate()

	badSigner := createBadSigner(t)

	type args struct {
		template *x509.Certificate
		parent   *x509.Certificate
		pub      crypto.PublicKey
		signer   crypto.Signer
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{crt1, iss, priv1.Public(), issPriv}, false},
		{"okNoSubjectKeyID", args{crt2, iss, priv2.Public(), issPriv}, false},
		{"okNoSerialNumber", args{crt3, iss, priv3.Public(), issPriv}, false},
		{"okNothing", args{crt4, iss, priv4.Public(), issPriv}, false},
		{"failSubjectKeyID", args{crt5, iss, []byte("foo"), issPriv}, true},
		{"failSign", args{crt1, iss, priv1.Public(), badSigner}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateCertificate(tt.args.template, tt.args.parent, tt.args.pub, tt.args.signer)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if err := got.CheckSignatureFrom(iss); err != nil {
					t.Errorf("Certificate.CheckSignatureFrom() error = %v", err)
				}
			}
		})
	}
}
