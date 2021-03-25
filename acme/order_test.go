package acme

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
)

func TestOrder_UpdateStatus(t *testing.T) {
	type test struct {
		o   *Order
		err *Error
		db  DB
	}
	tests := map[string]func(t *testing.T) test{
		"ok/already-invalid": func(t *testing.T) test {
			o := &Order{
				Status: StatusInvalid,
			}
			return test{
				o: o,
			}
		},
		"ok/already-valid": func(t *testing.T) test {
			o := &Order{
				Status: StatusInvalid,
			}
			return test{
				o: o,
			}
		},
		"fail/error-unexpected-status": func(t *testing.T) test {
			o := &Order{
				Status: "foo",
			}
			return test{
				o:   o,
				err: NewErrorISE("unrecognized order status: %s", o.Status),
			}
		},
		"ok/ready-expired": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:        "oID",
				AccountID: "accID",
				Status:    StatusReady,
				ExpiresAt: now.Add(-5 * time.Minute),
			}
			return test{
				o: o,
				db: &MockDB{
					MockUpdateOrder: func(ctx context.Context, updo *Order) error {
						assert.Equals(t, updo.ID, o.ID)
						assert.Equals(t, updo.AccountID, o.AccountID)
						assert.Equals(t, updo.Status, StatusInvalid)
						assert.Equals(t, updo.ExpiresAt, o.ExpiresAt)
						return nil
					},
				},
			}
		},
		"fail/ready-expired-db.UpdateOrder-error": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:        "oID",
				AccountID: "accID",
				Status:    StatusReady,
				ExpiresAt: now.Add(-5 * time.Minute),
			}
			return test{
				o: o,
				db: &MockDB{
					MockUpdateOrder: func(ctx context.Context, updo *Order) error {
						assert.Equals(t, updo.ID, o.ID)
						assert.Equals(t, updo.AccountID, o.AccountID)
						assert.Equals(t, updo.Status, StatusInvalid)
						assert.Equals(t, updo.ExpiresAt, o.ExpiresAt)
						return errors.New("force")
					},
				},
				err: NewErrorISE("error updating order: force"),
			}
		},
		"ok/pending-expired": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:        "oID",
				AccountID: "accID",
				Status:    StatusPending,
				ExpiresAt: now.Add(-5 * time.Minute),
			}
			return test{
				o: o,
				db: &MockDB{
					MockUpdateOrder: func(ctx context.Context, updo *Order) error {
						assert.Equals(t, updo.ID, o.ID)
						assert.Equals(t, updo.AccountID, o.AccountID)
						assert.Equals(t, updo.Status, StatusInvalid)
						assert.Equals(t, updo.ExpiresAt, o.ExpiresAt)

						err := NewError(ErrorMalformedType, "order has expired")
						assert.HasPrefix(t, updo.Error.Err.Error(), err.Err.Error())
						assert.Equals(t, updo.Error.Type, err.Type)
						assert.Equals(t, updo.Error.Detail, err.Detail)
						assert.Equals(t, updo.Error.Status, err.Status)
						assert.Equals(t, updo.Error.Detail, err.Detail)
						return nil
					},
				},
			}
		},
		"ok/invalid": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusPending,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
			}
			az1 := &Authorization{
				ID:     "a",
				Status: StatusValid,
			}
			az2 := &Authorization{
				ID:     "b",
				Status: StatusInvalid,
			}

			return test{
				o: o,
				db: &MockDB{
					MockUpdateOrder: func(ctx context.Context, updo *Order) error {
						assert.Equals(t, updo.ID, o.ID)
						assert.Equals(t, updo.AccountID, o.AccountID)
						assert.Equals(t, updo.Status, StatusInvalid)
						assert.Equals(t, updo.ExpiresAt, o.ExpiresAt)
						return nil
					},
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						switch id {
						case az1.ID:
							return az1, nil
						case az2.ID:
							return az2, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected authz key %s", id))
							return nil, errors.New("force")
						}
					},
				},
			}
		},
		"ok/still-pending": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusPending,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
			}
			az1 := &Authorization{
				ID:     "a",
				Status: StatusValid,
			}
			az2 := &Authorization{
				ID:     "b",
				Status: StatusPending,
			}

			return test{
				o: o,
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						switch id {
						case az1.ID:
							return az1, nil
						case az2.ID:
							return az2, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected authz key %s", id))
							return nil, errors.New("force")
						}
					},
				},
			}
		},
		"ok/valid": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusPending,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
			}
			az1 := &Authorization{
				ID:     "a",
				Status: StatusValid,
			}
			az2 := &Authorization{
				ID:     "b",
				Status: StatusValid,
			}

			return test{
				o: o,
				db: &MockDB{
					MockUpdateOrder: func(ctx context.Context, updo *Order) error {
						assert.Equals(t, updo.ID, o.ID)
						assert.Equals(t, updo.AccountID, o.AccountID)
						assert.Equals(t, updo.Status, StatusReady)
						assert.Equals(t, updo.ExpiresAt, o.ExpiresAt)
						return nil
					},
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						switch id {
						case az1.ID:
							return az1, nil
						case az2.ID:
							return az2, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected authz key %s", id))
							return nil, errors.New("force")
						}
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := tc.o.UpdateStatus(context.Background(), tc.db); err != nil {
				if assert.NotNil(t, tc.err) {
					switch k := err.(type) {
					case *Error:
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
					default:
						assert.FatalError(t, errors.New("unexpected error type"))
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})

	}
}

type mockSignAuth struct {
	sign                func(csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	loadProvisionerByID func(string) (provisioner.Interface, error)
	ret1, ret2          interface{}
	err                 error
}

func (m *mockSignAuth) Sign(csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
	if m.sign != nil {
		return m.sign(csr, signOpts, extraOpts...)
	} else if m.err != nil {
		return nil, m.err
	}
	return []*x509.Certificate{m.ret1.(*x509.Certificate), m.ret2.(*x509.Certificate)}, m.err
}

func (m *mockSignAuth) LoadProvisionerByID(id string) (provisioner.Interface, error) {
	if m.loadProvisionerByID != nil {
		return m.loadProvisionerByID(id)
	}
	return m.ret1.(provisioner.Interface), m.err
}

func TestOrder_Finalize(t *testing.T) {
	type test struct {
		o    *Order
		err  *Error
		db   DB
		ca   CertificateAuthority
		csr  *x509.CertificateRequest
		prov Provisioner
	}
	tests := map[string]func(t *testing.T) test{
		"fail/invalid": func(t *testing.T) test {
			o := &Order{
				ID:     "oid",
				Status: StatusInvalid,
			}
			return test{
				o:   o,
				err: NewError(ErrorOrderNotReadyType, "order %s has been abandoned", o.ID),
			}
		},
		"fail/pending": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusPending,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
			}
			az1 := &Authorization{
				ID:     "a",
				Status: StatusValid,
			}
			az2 := &Authorization{
				ID:        "b",
				Status:    StatusPending,
				ExpiresAt: now.Add(5 * time.Minute),
			}

			return test{
				o: o,
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						switch id {
						case az1.ID:
							return az1, nil
						case az2.ID:
							return az2, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected authz key %s", id))
							return nil, errors.New("force")
						}
					},
				},
				err: NewError(ErrorOrderNotReadyType, "order %s is not ready", o.ID),
			}
		},
		"ok/already-valid": func(t *testing.T) test {
			o := &Order{
				ID:     "oid",
				Status: StatusValid,
			}
			return test{
				o: o,
			}
		},
		"fail/error-unexpected-status": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           "foo",
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
			}

			return test{
				o:   o,
				err: NewErrorISE("unrecognized order status: %s", o.Status),
			}
		},
		"fail/error-names-length-mismatch": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "dns", Value: "bar.internal"},
				},
			}
			orderNames := []string{"bar.internal", "foo.internal"}
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.internal",
				},
			}

			return test{
				o:   o,
				csr: csr,
				err: NewError(ErrorBadCSRType, "CSR names do not match identifiers exactly: "+
					"CSR names = %v, Order names = %v", []string{"foo.internal"}, orderNames),
			}
		},
		"fail/error-names-mismatch": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "dns", Value: "bar.internal"},
				},
			}
			orderNames := []string{"bar.internal", "foo.internal"}
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.internal",
				},
				DNSNames: []string{"zap.internal"},
			}

			return test{
				o:   o,
				csr: csr,
				err: NewError(ErrorBadCSRType, "CSR names do not match identifiers exactly: "+
					"CSR names = %v, Order names = %v", []string{"foo.internal", "zap.internal"}, orderNames),
			}
		},
		"fail/error-provisioner-auth": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "dns", Value: "bar.internal"},
				},
			}
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.internal",
				},
				DNSNames: []string{"bar.internal"},
			}

			return test{
				o:   o,
				csr: csr,
				prov: &MockProvisioner{
					MauthorizeSign: func(ctx context.Context, token string) ([]provisioner.SignOption, error) {
						assert.Equals(t, token, "")
						return nil, errors.New("force")
					},
				},
				err: NewErrorISE("error retrieving authorization options from ACME provisioner: force"),
			}
		},
		"fail/error-template-options": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "dns", Value: "bar.internal"},
				},
			}
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.internal",
				},
				DNSNames: []string{"bar.internal"},
			}

			return test{
				o:   o,
				csr: csr,
				prov: &MockProvisioner{
					MauthorizeSign: func(ctx context.Context, token string) ([]provisioner.SignOption, error) {
						assert.Equals(t, token, "")
						return nil, nil
					},
					MgetOptions: func() *provisioner.Options {
						return &provisioner.Options{
							X509: &provisioner.X509Options{
								TemplateData: json.RawMessage([]byte("fo{o")),
							},
						}
					},
				},
				err: NewErrorISE("error creating template options from ACME provisioner: error unmarshaling template data: invalid character 'o' in literal false (expecting 'a')"),
			}
		},
		"fail/error-ca-sign": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "dns", Value: "bar.internal"},
				},
			}
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.internal",
				},
				DNSNames: []string{"bar.internal"},
			}

			return test{
				o:   o,
				csr: csr,
				prov: &MockProvisioner{
					MauthorizeSign: func(ctx context.Context, token string) ([]provisioner.SignOption, error) {
						assert.Equals(t, token, "")
						return nil, nil
					},
					MgetOptions: func() *provisioner.Options {
						return nil
					},
				},
				ca: &mockSignAuth{
					sign: func(_csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return nil, errors.New("force")
					},
				},
				err: NewErrorISE("error signing certificate for order oID: force"),
			}
		},
		"fail/error-db.CreateCertificate": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "dns", Value: "bar.internal"},
				},
			}
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.internal",
				},
				DNSNames: []string{"bar.internal"},
			}

			foo := &x509.Certificate{Subject: pkix.Name{CommonName: "foo"}}
			bar := &x509.Certificate{Subject: pkix.Name{CommonName: "bar"}}
			baz := &x509.Certificate{Subject: pkix.Name{CommonName: "baz"}}

			return test{
				o:   o,
				csr: csr,
				prov: &MockProvisioner{
					MauthorizeSign: func(ctx context.Context, token string) ([]provisioner.SignOption, error) {
						assert.Equals(t, token, "")
						return nil, nil
					},
					MgetOptions: func() *provisioner.Options {
						return nil
					},
				},
				ca: &mockSignAuth{
					sign: func(_csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{foo, bar, baz}, nil
					},
				},
				db: &MockDB{
					MockCreateCertificate: func(ctx context.Context, cert *Certificate) error {
						assert.Equals(t, cert.AccountID, o.AccountID)
						assert.Equals(t, cert.OrderID, o.ID)
						assert.Equals(t, cert.Leaf, foo)
						assert.Equals(t, cert.Intermediates, []*x509.Certificate{bar, baz})
						return errors.New("force")
					},
				},
				err: NewErrorISE("error creating certificate for order oID: force"),
			}
		},
		"fail/error-db.UpdateOrder": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "dns", Value: "bar.internal"},
				},
			}
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.internal",
				},
				DNSNames: []string{"bar.internal"},
			}

			foo := &x509.Certificate{Subject: pkix.Name{CommonName: "foo"}}
			bar := &x509.Certificate{Subject: pkix.Name{CommonName: "bar"}}
			baz := &x509.Certificate{Subject: pkix.Name{CommonName: "baz"}}

			return test{
				o:   o,
				csr: csr,
				prov: &MockProvisioner{
					MauthorizeSign: func(ctx context.Context, token string) ([]provisioner.SignOption, error) {
						assert.Equals(t, token, "")
						return nil, nil
					},
					MgetOptions: func() *provisioner.Options {
						return nil
					},
				},
				ca: &mockSignAuth{
					sign: func(_csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{foo, bar, baz}, nil
					},
				},
				db: &MockDB{
					MockCreateCertificate: func(ctx context.Context, cert *Certificate) error {
						cert.ID = "certID"
						assert.Equals(t, cert.AccountID, o.AccountID)
						assert.Equals(t, cert.OrderID, o.ID)
						assert.Equals(t, cert.Leaf, foo)
						assert.Equals(t, cert.Intermediates, []*x509.Certificate{bar, baz})
						return nil
					},
					MockUpdateOrder: func(ctx context.Context, updo *Order) error {
						assert.Equals(t, updo.CertificateID, "certID")
						assert.Equals(t, updo.Status, StatusValid)
						assert.Equals(t, updo.ID, o.ID)
						assert.Equals(t, updo.AccountID, o.AccountID)
						assert.Equals(t, updo.ExpiresAt, o.ExpiresAt)
						assert.Equals(t, updo.AuthorizationIDs, o.AuthorizationIDs)
						assert.Equals(t, updo.Identifiers, o.Identifiers)
						return errors.New("force")
					},
				},
				err: NewErrorISE("error updating order oID: force"),
			}
		},
		"ok/new-cert": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "dns", Value: "bar.internal"},
				},
			}
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.internal",
				},
				DNSNames: []string{"bar.internal"},
			}

			foo := &x509.Certificate{Subject: pkix.Name{CommonName: "foo"}}
			bar := &x509.Certificate{Subject: pkix.Name{CommonName: "bar"}}
			baz := &x509.Certificate{Subject: pkix.Name{CommonName: "baz"}}

			return test{
				o:   o,
				csr: csr,
				prov: &MockProvisioner{
					MauthorizeSign: func(ctx context.Context, token string) ([]provisioner.SignOption, error) {
						assert.Equals(t, token, "")
						return nil, nil
					},
					MgetOptions: func() *provisioner.Options {
						return nil
					},
				},
				ca: &mockSignAuth{
					sign: func(_csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{foo, bar, baz}, nil
					},
				},
				db: &MockDB{
					MockCreateCertificate: func(ctx context.Context, cert *Certificate) error {
						cert.ID = "certID"
						assert.Equals(t, cert.AccountID, o.AccountID)
						assert.Equals(t, cert.OrderID, o.ID)
						assert.Equals(t, cert.Leaf, foo)
						assert.Equals(t, cert.Intermediates, []*x509.Certificate{bar, baz})
						return nil
					},
					MockUpdateOrder: func(ctx context.Context, updo *Order) error {
						assert.Equals(t, updo.CertificateID, "certID")
						assert.Equals(t, updo.Status, StatusValid)
						assert.Equals(t, updo.ID, o.ID)
						assert.Equals(t, updo.AccountID, o.AccountID)
						assert.Equals(t, updo.ExpiresAt, o.ExpiresAt)
						assert.Equals(t, updo.AuthorizationIDs, o.AuthorizationIDs)
						assert.Equals(t, updo.Identifiers, o.Identifiers)
						return nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := tc.o.Finalize(context.Background(), tc.db, tc.csr, tc.ca, tc.prov); err != nil {
				if assert.NotNil(t, tc.err) {
					switch k := err.(type) {
					case *Error:
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
					default:
						assert.FatalError(t, errors.New("unexpected error type"))
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}
