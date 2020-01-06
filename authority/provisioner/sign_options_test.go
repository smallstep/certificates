package provisioner

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
	stepx509 "github.com/smallstep/cli/pkg/x509"
)

func Test_emailOnlyIdentity_Valid(t *testing.T) {
	uri, err := url.Parse("https://example.com/1.0/getUser")
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		req *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		e       emailOnlyIdentity
		args    args
		wantErr bool
	}{
		{"ok", "name@smallstep.com", args{&x509.CertificateRequest{EmailAddresses: []string{"name@smallstep.com"}}}, false},
		{"DNSNames", "name@smallstep.com", args{&x509.CertificateRequest{DNSNames: []string{"foo.bar.zar"}}}, true},
		{"IPAddresses", "name@smallstep.com", args{&x509.CertificateRequest{IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}}, true},
		{"URIs", "name@smallstep.com", args{&x509.CertificateRequest{URIs: []*url.URL{uri}}}, true},
		{"no-emails", "name@smallstep.com", args{&x509.CertificateRequest{EmailAddresses: []string{}}}, true},
		{"empty-email", "", args{&x509.CertificateRequest{EmailAddresses: []string{""}}}, true},
		{"multiple-emails", "name@smallstep.com", args{&x509.CertificateRequest{EmailAddresses: []string{"name@smallstep.com", "foo@smallstep.com"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.e.Valid(tt.args.req); (err != nil) != tt.wantErr {
				t.Errorf("emailOnlyIdentity.Valid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_defaultPublicKeyValidator_Valid(t *testing.T) {
	_shortRSA, err := pemutil.Read("./testdata/short-rsa.csr")
	assert.FatalError(t, err)
	shortRSA, ok := _shortRSA.(*x509.CertificateRequest)
	assert.Fatal(t, ok)

	_rsa, err := pemutil.Read("./testdata/rsa.csr")
	assert.FatalError(t, err)
	rsaCSR, ok := _rsa.(*x509.CertificateRequest)
	assert.Fatal(t, ok)

	_ecdsa, err := pemutil.Read("./testdata/ecdsa.csr")
	assert.FatalError(t, err)
	ecdsaCSR, ok := _ecdsa.(*x509.CertificateRequest)
	assert.Fatal(t, ok)

	_ed25519, err := pemutil.Read("./testdata/ed25519.csr", pemutil.WithStepCrypto())
	assert.FatalError(t, err)
	ed25519CSR, ok := _ed25519.(*stepx509.CertificateRequest)
	assert.Fatal(t, ok)

	v := defaultPublicKeyValidator{}
	tests := []struct {
		name string
		csr  *x509.CertificateRequest
		err  error
	}{
		{
			"fail/unrecognized-key-type",
			&x509.CertificateRequest{PublicKey: "foo"},
			errors.New("unrecognized public key of type 'string' in CSR"),
		},
		{
			"fail/rsa/too-short",
			shortRSA,
			errors.New("rsa key in CSR must be at least 2048 bits (256 bytes)"),
		},
		{
			"ok/rsa",
			rsaCSR,
			nil,
		},
		{
			"ok/ecdsa",
			ecdsaCSR,
			nil,
		},
		{
			"ok/ed25519",
			x509util.ToX509CertificateRequest(ed25519CSR),
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := v.Valid(tt.csr); err != nil {
				if assert.NotNil(t, tt.err) {
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			} else {
				assert.Nil(t, tt.err)
			}
		})
	}
}

func Test_commonNameValidator_Valid(t *testing.T) {
	type args struct {
		req *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		v       commonNameValidator
		args    args
		wantErr bool
	}{
		{"ok", "foo.bar.zar", args{&x509.CertificateRequest{Subject: pkix.Name{CommonName: "foo.bar.zar"}}}, false},
		{"empty", "", args{&x509.CertificateRequest{Subject: pkix.Name{CommonName: ""}}}, true},
		{"wrong", "foo.bar.zar", args{&x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.v.Valid(tt.args.req); (err != nil) != tt.wantErr {
				t.Errorf("commonNameValidator.Valid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_commonNameSliceValidator_Valid(t *testing.T) {
	type args struct {
		req *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		v       commonNameSliceValidator
		args    args
		wantErr bool
	}{
		{"ok", []string{"foo.bar.zar"}, args{&x509.CertificateRequest{Subject: pkix.Name{CommonName: "foo.bar.zar"}}}, false},
		{"ok", []string{"example.com", "foo.bar.zar"}, args{&x509.CertificateRequest{Subject: pkix.Name{CommonName: "foo.bar.zar"}}}, false},
		{"empty", []string{""}, args{&x509.CertificateRequest{Subject: pkix.Name{CommonName: ""}}}, true},
		{"wrong", []string{"foo.bar.zar"}, args{&x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.v.Valid(tt.args.req); (err != nil) != tt.wantErr {
				t.Errorf("commonNameSliceValidator.Valid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_emailAddressesValidator_Valid(t *testing.T) {
	type args struct {
		req *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		v       emailAddressesValidator
		args    args
		wantErr bool
	}{
		{"ok0", []string{}, args{&x509.CertificateRequest{EmailAddresses: []string{}}}, false},
		{"ok1", []string{"max@smallstep.com"}, args{&x509.CertificateRequest{EmailAddresses: []string{"max@smallstep.com"}}}, false},
		{"ok2", []string{"max@step.com", "mike@step.com"}, args{&x509.CertificateRequest{EmailAddresses: []string{"max@step.com", "mike@step.com"}}}, false},
		{"ok3", []string{"max@step.com", "mike@step.com"}, args{&x509.CertificateRequest{EmailAddresses: []string{"mike@step.com", "max@step.com"}}}, false},
		{"fail1", []string{"max@step.com"}, args{&x509.CertificateRequest{EmailAddresses: []string{"mike@step.com"}}}, true},
		{"fail2", []string{"mike@step.com"}, args{&x509.CertificateRequest{EmailAddresses: []string{"max@step.com", "mike@step.com"}}}, true},
		{"fail3", []string{"mike@step.com", "max@step.com"}, args{&x509.CertificateRequest{DNSNames: []string{"mike@step.com", "mex@step.com"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.v.Valid(tt.args.req); (err != nil) != tt.wantErr {
				t.Errorf("dnsNamesValidator.Valid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_dnsNamesValidator_Valid(t *testing.T) {
	type args struct {
		req *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		v       dnsNamesValidator
		args    args
		wantErr bool
	}{
		{"ok0", []string{}, args{&x509.CertificateRequest{DNSNames: []string{}}}, false},
		{"ok1", []string{"foo.bar.zar"}, args{&x509.CertificateRequest{DNSNames: []string{"foo.bar.zar"}}}, false},
		{"ok2", []string{"foo.bar.zar", "bar.zar"}, args{&x509.CertificateRequest{DNSNames: []string{"foo.bar.zar", "bar.zar"}}}, false},
		{"ok3", []string{"foo.bar.zar", "bar.zar"}, args{&x509.CertificateRequest{DNSNames: []string{"bar.zar", "foo.bar.zar"}}}, false},
		{"fail1", []string{"foo.bar.zar"}, args{&x509.CertificateRequest{DNSNames: []string{"bar.zar"}}}, true},
		{"fail2", []string{"foo.bar.zar"}, args{&x509.CertificateRequest{DNSNames: []string{"bar.zar", "foo.bar.zar"}}}, true},
		{"fail3", []string{"foo.bar.zar", "bar.zar"}, args{&x509.CertificateRequest{DNSNames: []string{"foo.bar.zar", "zar.bar"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.v.Valid(tt.args.req); (err != nil) != tt.wantErr {
				t.Errorf("dnsNamesValidator.Valid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_ipAddressesValidator_Valid(t *testing.T) {
	ip1 := net.IPv4(10, 3, 2, 1)
	ip2 := net.IPv4(10, 3, 2, 2)
	ip3 := net.IPv4(10, 3, 2, 3)

	type args struct {
		req *x509.CertificateRequest
	}
	tests := []struct {
		name    string
		v       ipAddressesValidator
		args    args
		wantErr bool
	}{
		{"ok0", []net.IP{}, args{&x509.CertificateRequest{IPAddresses: []net.IP{}}}, false},
		{"ok1", []net.IP{ip1}, args{&x509.CertificateRequest{IPAddresses: []net.IP{ip1}}}, false},
		{"ok2", []net.IP{ip1, ip2}, args{&x509.CertificateRequest{IPAddresses: []net.IP{ip1, ip2}}}, false},
		{"ok3", []net.IP{ip1, ip2}, args{&x509.CertificateRequest{IPAddresses: []net.IP{ip2, ip1}}}, false},
		{"fail1", []net.IP{ip1}, args{&x509.CertificateRequest{IPAddresses: []net.IP{ip2}}}, true},
		{"fail2", []net.IP{ip1}, args{&x509.CertificateRequest{IPAddresses: []net.IP{ip2, ip1}}}, true},
		{"fail3", []net.IP{ip1, ip2}, args{&x509.CertificateRequest{IPAddresses: []net.IP{ip1, ip3}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.v.Valid(tt.args.req); (err != nil) != tt.wantErr {
				t.Errorf("ipAddressesValidator.Valid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validityValidator_Valid(t *testing.T) {
	type fields struct {
		min time.Duration
		max time.Duration
	}
	type args struct {
		crt *x509.Certificate
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &validityValidator{
				min: tt.fields.min,
				max: tt.fields.max,
			}
			if err := v.Valid(tt.args.crt); (err != nil) != tt.wantErr {
				t.Errorf("validityValidator.Valid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_profileLimitDuration_Option(t *testing.T) {
	n := now()
	type test struct {
		pld   profileLimitDuration
		so    Options
		cert  *x509.Certificate
		valid func(*x509.Certificate)
		err   error
	}
	tests := map[string]func() test{
		"fail/notBefore-after-limit": func() test {
			d, err := ParseTimeDuration("8h")
			assert.FatalError(t, err)
			return test{
				pld:  profileLimitDuration{def: 4 * time.Hour, notAfter: n.Add(6 * time.Hour)},
				so:   Options{NotBefore: d},
				cert: new(x509.Certificate),
				err:  errors.New("provisioning credential expiration ("),
			}
		},
		"fail/requested-notAfter-after-limit": func() test {
			d, err := ParseTimeDuration("4h")
			assert.FatalError(t, err)
			return test{
				pld:  profileLimitDuration{def: 4 * time.Hour, notAfter: n.Add(6 * time.Hour)},
				so:   Options{NotBefore: NewTimeDuration(n.Add(3 * time.Hour)), NotAfter: d},
				cert: new(x509.Certificate),
				err:  errors.New("provisioning credential expiration ("),
			}
		},
		"ok/valid-notAfter-requested": func() test {
			d, err := ParseTimeDuration("2h")
			assert.FatalError(t, err)
			return test{
				pld:  profileLimitDuration{def: 4 * time.Hour, notAfter: n.Add(6 * time.Hour)},
				so:   Options{NotBefore: NewTimeDuration(n.Add(3 * time.Hour)), NotAfter: d},
				cert: new(x509.Certificate),
				valid: func(cert *x509.Certificate) {
					assert.Equals(t, cert.NotBefore, n.Add(3*time.Hour))
					assert.Equals(t, cert.NotAfter, n.Add(5*time.Hour))
				},
			}
		},
		"ok/valid-notAfter-nil-limit-over-default": func() test {
			return test{
				pld:  profileLimitDuration{def: 1 * time.Hour, notAfter: n.Add(6 * time.Hour)},
				so:   Options{NotBefore: NewTimeDuration(n.Add(3 * time.Hour))},
				cert: new(x509.Certificate),
				valid: func(cert *x509.Certificate) {
					assert.Equals(t, cert.NotBefore, n.Add(3*time.Hour))
					assert.Equals(t, cert.NotAfter, n.Add(4*time.Hour))
				},
			}
		},
		"ok/valid-notAfter-nil-limit-under-default": func() test {
			return test{
				pld:  profileLimitDuration{def: 4 * time.Hour, notAfter: n.Add(6 * time.Hour)},
				so:   Options{NotBefore: NewTimeDuration(n.Add(3 * time.Hour))},
				cert: new(x509.Certificate),
				valid: func(cert *x509.Certificate) {
					assert.Equals(t, cert.NotBefore, n.Add(3*time.Hour))
					assert.Equals(t, cert.NotAfter, n.Add(6*time.Hour))
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tt := run()
			prof := &x509util.Leaf{}
			prof.SetSubject(tt.cert)
			if err := tt.pld.Option(tt.so)(prof); err != nil {
				if assert.NotNil(t, tt.err) {
					assert.HasPrefix(t, err.Error(), tt.err.Error())
				}
			} else {
				if assert.Nil(t, tt.err) {
					tt.valid(prof.Subject())
				}
			}
		})
	}
}

func Test_profileDefaultDuration_Option(t *testing.T) {
	tm, fn := mockNow()
	defer fn()

	v := profileDefaultDuration(24 * time.Hour)
	type args struct {
		so Options
	}
	tests := []struct {
		name string
		v    profileDefaultDuration
		args args
		want *x509.Certificate
	}{
		{"default", v, args{Options{}}, &x509.Certificate{NotBefore: tm, NotAfter: tm.Add(24 * time.Hour)}},
		{"backdate", v, args{Options{Backdate: 1 * time.Minute}}, &x509.Certificate{NotBefore: tm.Add(-1 * time.Minute), NotAfter: tm.Add(24 * time.Hour)}},
		{"notBefore", v, args{Options{NotBefore: NewTimeDuration(tm.Add(10 * time.Second))}}, &x509.Certificate{NotBefore: tm.Add(10 * time.Second), NotAfter: tm.Add(24*time.Hour + 10*time.Second)}},
		{"notAfter", v, args{Options{NotAfter: NewTimeDuration(tm.Add(1 * time.Hour))}}, &x509.Certificate{NotBefore: tm, NotAfter: tm.Add(1 * time.Hour)}},
		{"notBefore and notAfter", v, args{Options{NotBefore: NewTimeDuration(tm.Add(10 * time.Second)), NotAfter: NewTimeDuration(tm.Add(1 * time.Hour))}},
			&x509.Certificate{NotBefore: tm.Add(10 * time.Second), NotAfter: tm.Add(1 * time.Hour)}},
		{"notBefore and backdate", v, args{Options{Backdate: 1 * time.Minute, NotBefore: NewTimeDuration(tm.Add(10 * time.Second))}},
			&x509.Certificate{NotBefore: tm.Add(10 * time.Second), NotAfter: tm.Add(24*time.Hour + 10*time.Second)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{}
			profile := &x509util.Leaf{}
			profile.SetSubject(cert)

			fn := tt.v.Option(tt.args.so)
			if err := fn(profile); err != nil {
				t.Errorf("profileDefaultDuration.Option() error %v", err)
			}
			if !reflect.DeepEqual(cert, tt.want) {
				t.Errorf("profileDefaultDuration.Option() = %v, \nwant %v", cert, tt.want)
			}
		})
	}
}
