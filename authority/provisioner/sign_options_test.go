package provisioner

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
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
	_shortRSA, err := pemutil.Read("./testdata/certs/short-rsa.csr")
	assert.FatalError(t, err)
	shortRSA, ok := _shortRSA.(*x509.CertificateRequest)
	assert.Fatal(t, ok)

	_rsa, err := pemutil.Read("./testdata/certs/rsa.csr")
	assert.FatalError(t, err)
	rsaCSR, ok := _rsa.(*x509.CertificateRequest)
	assert.Fatal(t, ok)

	_ecdsa, err := pemutil.Read("./testdata/certs/ecdsa.csr")
	assert.FatalError(t, err)
	ecdsaCSR, ok := _ecdsa.(*x509.CertificateRequest)
	assert.Fatal(t, ok)

	_ed25519, err := pemutil.Read("./testdata/certs/ed25519.csr")
	assert.FatalError(t, err)
	ed25519CSR, ok := _ed25519.(*x509.CertificateRequest)
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
			ed25519CSR,
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
	type test struct {
		cert *x509.Certificate
		opts Options
		vv   *validityValidator
		err  error
	}
	tests := map[string]func() test{
		"fail/notAfter-past": func() test {
			return test{
				vv:   &validityValidator{5 * time.Minute, 24 * time.Hour},
				cert: &x509.Certificate{NotAfter: time.Now().Add(-5 * time.Minute)},
				opts: Options{},
				err:  errors.New("notAfter cannot be in the past"),
			}
		},
		"fail/notBefore-after-notAfter": func() test {
			return test{
				vv: &validityValidator{5 * time.Minute, 24 * time.Hour},
				cert: &x509.Certificate{NotBefore: time.Now().Add(10 * time.Minute),
					NotAfter: time.Now().Add(5 * time.Minute)},
				opts: Options{},
				err:  errors.New("notAfter cannot be before notBefore"),
			}
		},
		"fail/duration-too-short": func() test {
			n := now()
			return test{
				vv: &validityValidator{5 * time.Minute, 24 * time.Hour},
				cert: &x509.Certificate{NotBefore: n,
					NotAfter: n.Add(3 * time.Minute)},
				opts: Options{},
				err:  errors.New("is less than the authorized minimum certificate duration of "),
			}
		},
		"ok/duration-exactly-min": func() test {
			n := now()
			return test{
				vv: &validityValidator{5 * time.Minute, 24 * time.Hour},
				cert: &x509.Certificate{NotBefore: n,
					NotAfter: n.Add(5 * time.Minute)},
				opts: Options{},
			}
		},
		"fail/duration-too-great": func() test {
			n := now()
			return test{
				vv: &validityValidator{5 * time.Minute, 24 * time.Hour},
				cert: &x509.Certificate{NotBefore: n,
					NotAfter: n.Add(24*time.Hour + time.Second)},
				err: errors.New("is more than the authorized maximum certificate duration of "),
			}
		},
		"ok/duration-exactly-max": func() test {
			n := time.Now()
			return test{
				vv: &validityValidator{5 * time.Minute, 24 * time.Hour},
				cert: &x509.Certificate{NotBefore: n,
					NotAfter: n.Add(24 * time.Hour)},
			}
		},
		"ok/duration-exact-min-with-backdate": func() test {
			now := time.Now()
			cert := &x509.Certificate{NotBefore: now, NotAfter: now.Add(5 * time.Minute)}
			time.Sleep(time.Second)
			return test{
				vv:   &validityValidator{5 * time.Minute, 24 * time.Hour},
				cert: cert,
				opts: Options{Backdate: time.Second},
			}
		},
		"ok/duration-exact-max-with-backdate": func() test {
			backdate := time.Second
			now := time.Now()
			cert := &x509.Certificate{NotBefore: now, NotAfter: now.Add(24*time.Hour + backdate)}
			time.Sleep(backdate)
			return test{
				vv:   &validityValidator{5 * time.Minute, 24 * time.Hour},
				cert: cert,
				opts: Options{Backdate: backdate},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tt := run()
			if err := tt.vv.Valid(tt.cert, tt.opts); err != nil {
				if assert.NotNil(t, tt.err, fmt.Sprintf("expected no error, but got err = %s", err.Error())) {
					assert.True(t, strings.Contains(err.Error(), tt.err.Error()),
						fmt.Sprintf("want err = %s, but got err = %s", tt.err.Error(), err.Error()))
				}
			} else {
				assert.Nil(t, tt.err, fmt.Sprintf("expected err = %s, but not <nil>", tt.err))
			}
		})
	}
}

func Test_profileDefaultDuration_Option(t *testing.T) {
	type test struct {
		so    Options
		pdd   profileDefaultDuration
		cert  *x509.Certificate
		valid func(*x509.Certificate)
	}
	tests := map[string]func() test{
		"ok/notBefore-notAfter-duration-empty": func() test {
			return test{
				pdd:  profileDefaultDuration(0),
				so:   Options{},
				cert: new(x509.Certificate),
				valid: func(cert *x509.Certificate) {
					n := now()
					assert.True(t, n.After(cert.NotBefore))
					assert.True(t, n.Add(-1*time.Minute).Before(cert.NotBefore))

					assert.True(t, n.Add(24*time.Hour).After(cert.NotAfter))
					assert.True(t, n.Add(24*time.Hour).Add(-1*time.Minute).Before(cert.NotAfter))
				},
			}
		},
		"ok/notBefore-set": func() test {
			nb := time.Now().Add(5 * time.Minute).UTC()
			return test{
				pdd:  profileDefaultDuration(0),
				so:   Options{NotBefore: NewTimeDuration(nb)},
				cert: new(x509.Certificate),
				valid: func(cert *x509.Certificate) {
					assert.Equals(t, cert.NotBefore, nb)
					assert.Equals(t, cert.NotAfter, nb.Add(24*time.Hour))
				},
			}
		},
		"ok/duration-set": func() test {
			d := 4 * time.Hour
			return test{
				pdd:  profileDefaultDuration(d),
				so:   Options{Backdate: time.Second},
				cert: new(x509.Certificate),
				valid: func(cert *x509.Certificate) {
					n := now()
					assert.True(t, n.After(cert.NotBefore), fmt.Sprintf("expected now = %s to be after cert.NotBefore = %s", n, cert.NotBefore))
					assert.True(t, n.Add(-1*time.Minute).Before(cert.NotBefore))

					assert.True(t, n.Add(d).After(cert.NotAfter))
					assert.True(t, n.Add(d).Add(-1*time.Minute).Before(cert.NotAfter))
				},
			}
		},
		"ok/notAfter-set": func() test {
			na := now().Add(10 * time.Minute).UTC()
			return test{
				pdd:  profileDefaultDuration(0),
				so:   Options{NotAfter: NewTimeDuration(na)},
				cert: new(x509.Certificate),
				valid: func(cert *x509.Certificate) {
					n := now()
					assert.True(t, n.After(cert.NotBefore), fmt.Sprintf("expected now = %s to be after cert.NotBefore = %s", n, cert.NotBefore))
					assert.True(t, n.Add(-1*time.Minute).Before(cert.NotBefore))

					assert.Equals(t, cert.NotAfter, na)
				},
			}
		},
		"ok/notBefore-and-notAfter-set": func() test {
			nb := time.Now().Add(5 * time.Minute).UTC()
			na := time.Now().Add(10 * time.Minute).UTC()
			d := 4 * time.Hour
			return test{
				pdd:  profileDefaultDuration(d),
				so:   Options{NotBefore: NewTimeDuration(nb), NotAfter: NewTimeDuration(na)},
				cert: new(x509.Certificate),
				valid: func(cert *x509.Certificate) {
					assert.Equals(t, cert.NotBefore, nb)
					assert.Equals(t, cert.NotAfter, na)
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tt := run()
			prof := &x509util.Leaf{}
			prof.SetSubject(tt.cert)
			assert.FatalError(t, tt.pdd.Option(tt.so)(prof), "unexpected error")
			tt.valid(prof.Subject())
		})
	}
}

func Test_profileLimitDuration_Option(t *testing.T) {
	n, fn := mockNow()
	defer fn()

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
				so:   Options{NotBefore: NewTimeDuration(n.Add(3 * time.Hour)), NotAfter: d, Backdate: 1 * time.Minute},
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
				so:   Options{NotBefore: NewTimeDuration(n.Add(3 * time.Hour)), Backdate: 1 * time.Minute},
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
				so:   Options{NotBefore: NewTimeDuration(n.Add(3 * time.Hour)), Backdate: 1 * time.Minute},
				cert: new(x509.Certificate),
				valid: func(cert *x509.Certificate) {
					assert.Equals(t, cert.NotBefore, n.Add(3*time.Hour))
					assert.Equals(t, cert.NotAfter, n.Add(6*time.Hour))
				},
			}
		},
		"ok/over-limit-with-backdate": func() test {
			return test{
				pld:  profileLimitDuration{def: 24 * time.Hour, notAfter: n.Add(6 * time.Hour)},
				so:   Options{Backdate: 1 * time.Minute},
				cert: new(x509.Certificate),
				valid: func(cert *x509.Certificate) {
					assert.Equals(t, cert.NotBefore, n.Add(-time.Minute))
					assert.Equals(t, cert.NotAfter, n.Add(6*time.Hour))
				},
			}
		},
		"ok/under-limit-with-backdate": func() test {
			return test{
				pld:  profileLimitDuration{def: 24 * time.Hour, notAfter: n.Add(30 * time.Hour)},
				so:   Options{Backdate: 1 * time.Minute},
				cert: new(x509.Certificate),
				valid: func(cert *x509.Certificate) {
					assert.Equals(t, cert.NotBefore, n.Add(-time.Minute))
					assert.Equals(t, cert.NotAfter, n.Add(24*time.Hour))
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
