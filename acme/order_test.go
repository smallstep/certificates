package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/webhook"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"
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
					var k *Error
					if errors.As(err, &k) {
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
					} else {
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
	signWithContext       func(ctx context.Context, csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	areSANsAllowed        func(ctx context.Context, sans []string) error
	loadProvisionerByName func(string) (provisioner.Interface, error)
	ret1, ret2            interface{}
	err                   error
}

func (m *mockSignAuth) SignWithContext(ctx context.Context, csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
	if m.signWithContext != nil {
		return m.signWithContext(ctx, csr, signOpts, extraOpts...)
	} else if m.err != nil {
		return nil, m.err
	}
	return []*x509.Certificate{m.ret1.(*x509.Certificate), m.ret2.(*x509.Certificate)}, m.err
}

func (m *mockSignAuth) AreSANsAllowed(ctx context.Context, sans []string) error {
	if m.areSANsAllowed != nil {
		return m.areSANsAllowed(ctx, sans)
	}
	return m.err
}

func (m *mockSignAuth) LoadProvisionerByName(name string) (provisioner.Interface, error) {
	if m.loadProvisionerByName != nil {
		return m.loadProvisionerByName(name)
	}
	return m.ret1.(provisioner.Interface), m.err
}

func (m *mockSignAuth) IsRevoked(string) (bool, error) {
	return false, nil
}

func (m *mockSignAuth) Revoke(context.Context, *authority.RevokeOptions) error {
	return nil
}

func TestOrder_Finalize(t *testing.T) {
	mustSigner := func(kty, crv string, size int) crypto.Signer {
		s, err := keyutil.GenerateSigner(kty, crv, size)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

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
		"fail/non-matching-permanent-identifier-common-name": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "permanent-identifier", Value: "a-permanent-identifier"},
				},
			}

			signer := mustSigner("EC", "P-256", 0)
			fingerprint, err := keyutil.Fingerprint(signer.Public())
			if err != nil {
				t.Fatal(err)
			}

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "a-different-identifier",
				},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3},
						Value: []byte("a-permanent-identifier"),
					},
				},
			}
			return test{
				o:   o,
				csr: csr,
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						switch id {
						case "a":
							return &Authorization{
								ID:     id,
								Status: StatusValid,
							}, nil
						case "b":
							return &Authorization{
								ID:          id,
								Fingerprint: fingerprint,
								Status:      StatusValid,
							}, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected authorization %s", id))
							return nil, errors.New("force")
						}
					},
					MockUpdateOrder: func(ctx context.Context, o *Order) error {
						return nil
					},
				},
				err: &Error{
					Type:   "urn:ietf:params:acme:error:badCSR",
					Detail: "The CSR is unacceptable",
					Status: 400,
					Err: fmt.Errorf("CSR Subject Common Name does not match identifiers exactly: "+
						"CSR Subject Common Name = %s, Order Permanent Identifier = %s", csr.Subject.CommonName, "a-permanent-identifier"),
				},
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
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						return &Authorization{ID: id, Status: StatusValid}, nil
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
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						return &Authorization{ID: id, Status: StatusValid}, nil
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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return nil, errors.New("force")
					},
				},
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						return &Authorization{ID: id, Status: StatusValid}, nil
					},
				},
				err: NewErrorISE("error signing certificate for order oID: force"),
			}
		},
		"fail/webhook-error": func(t *testing.T) test {
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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return nil, errs.ForbiddenErr(&webhook.Error{Code: "theCode", Message: "The message"}, "forbidden error")
					},
				},
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						return &Authorization{ID: id, Status: StatusValid}, nil
					},
				},
				err: NewDetailedError(ErrorUnauthorizedType, "The message (theCode)").AddSubproblems(Subproblem{
					Type:   "urn:smallstep:acme:error:theCode",
					Detail: "The message",
				}),
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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{foo, bar, baz}, nil
					},
				},
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						return &Authorization{ID: id, Status: StatusValid}, nil
					},
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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{foo, bar, baz}, nil
					},
				},
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						return &Authorization{ID: id, Status: StatusValid}, nil
					},
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
		"fail/csr-fingerprint": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "permanent-identifier", Value: "a-permanent-identifier"},
				},
			}

			signer := mustSigner("EC", "P-256", 0)

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "a-permanent-identifier",
				},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3},
						Value: []byte("a-permanent-identifier"),
					},
				},
			}

			leaf := &x509.Certificate{
				Subject:   pkix.Name{CommonName: "a-permanent-identifier"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3},
						Value: []byte("a-permanent-identifier"),
					},
				},
			}
			inter := &x509.Certificate{Subject: pkix.Name{CommonName: "inter"}}
			root := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}

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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{leaf, inter, root}, nil
					},
				},
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						return &Authorization{
							ID:          id,
							Fingerprint: "other-fingerprint",
							Status:      StatusValid,
						}, nil
					},
					MockCreateCertificate: func(ctx context.Context, cert *Certificate) error {
						cert.ID = "certID"
						assert.Equals(t, cert.AccountID, o.AccountID)
						assert.Equals(t, cert.OrderID, o.ID)
						assert.Equals(t, cert.Leaf, leaf)
						assert.Equals(t, cert.Intermediates, []*x509.Certificate{inter, root})
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
				err: NewError(ErrorUnauthorizedType, "order oID csr does not match the attested key"),
			}
		},
		"ok/permanent-identifier": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "permanent-identifier", Value: "a-permanent-identifier"},
				},
			}

			signer := mustSigner("EC", "P-256", 0)
			fingerprint, err := keyutil.Fingerprint(signer.Public())
			if err != nil {
				t.Fatal(err)
			}

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "a-permanent-identifier",
				},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3},
						Value: []byte("a-permanent-identifier"),
					},
				},
			}

			leaf := &x509.Certificate{
				Subject:   pkix.Name{CommonName: "a-permanent-identifier"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3},
						Value: []byte("a-permanent-identifier"),
					},
				},
			}
			inter := &x509.Certificate{Subject: pkix.Name{CommonName: "inter"}}
			root := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}

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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{leaf, inter, root}, nil
					},
				},
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						switch id {
						case "a":
							return &Authorization{
								ID:     id,
								Status: StatusValid,
							}, nil
						case "b":
							return &Authorization{
								ID:          id,
								Fingerprint: fingerprint,
								Status:      StatusValid,
							}, nil
						default:
							assert.FatalError(t, errors.Errorf("unexpected authorization %s", id))
							return nil, errors.New("force")
						}
					},
					MockCreateCertificate: func(ctx context.Context, cert *Certificate) error {
						cert.ID = "certID"
						assert.Equals(t, cert.AccountID, o.AccountID)
						assert.Equals(t, cert.OrderID, o.ID)
						assert.Equals(t, cert.Leaf, leaf)
						assert.Equals(t, cert.Intermediates, []*x509.Certificate{inter, root})
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
		"ok/permanent-identifier-only": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "permanent-identifier", Value: "a-permanent-identifier"},
				},
			}

			signer := mustSigner("EC", "P-256", 0)
			fingerprint, err := keyutil.Fingerprint(signer.Public())
			if err != nil {
				t.Fatal(err)
			}

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "a-permanent-identifier",
				},
				DNSNames:  []string{"foo.internal"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3},
						Value: []byte("a-permanent-identifier"),
					},
				},
			}

			leaf := &x509.Certificate{
				Subject:   pkix.Name{CommonName: "a-permanent-identifier"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3},
						Value: []byte("a-permanent-identifier"),
					},
				},
			}
			inter := &x509.Certificate{Subject: pkix.Name{CommonName: "inter"}}
			root := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}

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
				// TODO(hs): we should work on making the mocks more realistic. Ideally, we should get rid of
				// the mock entirely, relying on an instances of provisioner, authority and DB (possibly hardest), so
				// that behavior of the tests is what an actual CA would do. We could gradually phase them out by
				// using the mocking functions as a wrapper for actual test helpers generated per test case or per
				// function that's tested.
				ca: &mockSignAuth{
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{leaf, inter, root}, nil
					},
				},
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						return &Authorization{
							ID:          id,
							Fingerprint: fingerprint,
							Status:      StatusValid,
						}, nil
					},
					MockCreateCertificate: func(ctx context.Context, cert *Certificate) error {
						cert.ID = "certID"
						assert.Equals(t, cert.AccountID, o.AccountID)
						assert.Equals(t, cert.OrderID, o.ID)
						assert.Equals(t, cert.Leaf, leaf)
						assert.Equals(t, cert.Intermediates, []*x509.Certificate{inter, root})
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
		"fail/csr-wire-id-csr-uri-missing": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "wireapp-device", Value: "{\"name\": \"device\", \"domain\": \"wire.com\", \"client-id\": \"wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com\", \"handle\": \"wireapp://%40alice_wire@wire.com\"}"},
				},
			}

			signer := mustSigner("EC", "P-256", 0)
			_, err := keyutil.Fingerprint(signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					Names: []pkix.AttributeTypeAndValue{
						{Type: asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241}, Value: "device"},
					},
					Organization: []string{"wire.com"},
				},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}

			leaf := &x509.Certificate{
				Subject:   pkix.Name{CommonName: "a-wireapp-user"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}
			inter := &x509.Certificate{Subject: pkix.Name{CommonName: "inter"}}
			root := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}

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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{leaf, inter, root}, nil
					},
				},
				db: &MockWireDB{
					MockDB: MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							return &Authorization{ID: id, Status: StatusValid}, nil
						},
					},
					MockGetDpopToken: func(ctx context.Context, orderID string) (map[string]interface{}, error) {
						assert.Equals(t, orderID, o.ID)
						dpopMap := map[string]interface{}{
							"dpop": "a-dpop-token",
						}
						return dpopMap, nil
					},
					MockGetOidcToken: func(ctx context.Context, orderID string) (map[string]interface{}, error) {
						assert.Equals(t, orderID, o.ID)
						oidcMap := map[string]interface{}{
							"oidc": "a-oidc-token",
						}
						return oidcMap, nil
					},
				},
				err: NewError(ErrorBadCSRType, "CSR URIs do not match identifiers exactly: CSR URIs = [], Order URIs = [wireapp://CzbfFjDOQrenCbDxVmgnFw%%21594930e9d50bb175@wire.com]"),
			}
		},
		"fail/csr-wire-id-csr-uri-mismatch": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "wireapp-device", Value: "{\"name\": \"device\", \"domain\": \"wire.com\", \"client-id\": \"wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com\", \"handle\": \"wireapp://%40alice_wire@wire.com\"}"},
				},
			}

			signer := mustSigner("EC", "P-256", 0)
			_, err := keyutil.Fingerprint(signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			wireURL, _ := url.Parse("someurl.com")
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					Names: []pkix.AttributeTypeAndValue{
						{Type: asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241}, Value: "device"},
					},
					Organization: []string{"wire.com"},
				},
				URIs: []*url.URL{
					wireURL,
				},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}

			leaf := &x509.Certificate{
				Subject:   pkix.Name{CommonName: "a-wireapp-user"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}
			inter := &x509.Certificate{Subject: pkix.Name{CommonName: "inter"}}
			root := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}

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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{leaf, inter, root}, nil
					},
				},
				db: &MockWireDB{
					MockDB: MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							return &Authorization{ID: id, Status: StatusValid}, nil
						},
					},
					MockGetDpopToken: func(ctx context.Context, orderID string) (map[string]interface{}, error) {
						assert.Equals(t, orderID, o.ID)
						dpopMap := map[string]interface{}{
							"dpop": "a-dpop-token",
						}
						return dpopMap, nil
					},
					MockGetOidcToken: func(ctx context.Context, orderID string) (map[string]interface{}, error) {
						assert.Equals(t, orderID, o.ID)
						oidcMap := map[string]interface{}{
							"oidc": "a-oidc-token",
						}
						return oidcMap, nil
					},
				},
				err: NewError(ErrorBadCSRType, "CSR URIs do not match identifiers exactly: CSR URIs = [someurl.com], Order URIs = [wireapp://CzbfFjDOQrenCbDxVmgnFw%%21594930e9d50bb175@wire.com]"),
			}
		},
		"fail/other-than-wire-ids-present": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "wireapp-device", Value: "{\"name\": \"device\", \"domain\": \"wire.com\", \"client-id\": \"wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com\", \"handle\": \"wireapp://%40alice_wire@wire.com\"}"},
					{Type: "permanent-identifier", Value: "a-permanent-identifier"},
				},
			}

			signer := mustSigner("EC", "P-256", 0)
			_, err := keyutil.Fingerprint(signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			wireURL, _ := url.Parse("wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com")
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					Names: []pkix.AttributeTypeAndValue{
						{Type: asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241}, Value: "device"},
					},
					Organization: []string{"wire.com"},
				},
				URIs: []*url.URL{
					wireURL,
				},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}

			leaf := &x509.Certificate{
				Subject:   pkix.Name{CommonName: "a-wireapp-user"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}
			inter := &x509.Certificate{Subject: pkix.Name{CommonName: "inter"}}
			root := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}

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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{leaf, inter, root}, nil
					},
				},
				db: &MockWireDB{
					MockDB: MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							return &Authorization{ID: id, Status: StatusValid}, nil
						},
					},
				},
				err: NewError(ErrorServerInternalType, "order must have exactly one WireUser and WireDevice identifier"),
			}
		},
		"fail/wire-id-org-missing": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "wireapp-user", Value: "{\"name\": \"Alice Smith\", \"domain\": \"wire.com\", \"handle\": \"wireapp://%40alice_wire@wire.com\"}"},
				},
			}

			signer := mustSigner("EC", "P-256", 0)
			_, err := keyutil.Fingerprint(signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			wireURL, _ := url.Parse("wireapp://%40alice_wire@wire.com")
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					Names: []pkix.AttributeTypeAndValue{
						{Type: asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241}, Value: "Alice Smith"},
					},
				},
				URIs: []*url.URL{
					wireURL,
				},
				PublicKey: signer.Public(),
			}

			leaf := &x509.Certificate{
				Subject:   pkix.Name{CommonName: "a-wireapp-user"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}
			inter := &x509.Certificate{Subject: pkix.Name{CommonName: "inter"}}
			root := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}

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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{leaf, inter, root}, nil
					},
				},
				db: &MockWireDB{
					MockDB: MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							return &Authorization{ID: id, Status: StatusValid}, nil
						},
					},
				},
				err: NewError(ErrorServerInternalType, "expected Organization [wire.com], found []"),
			}
		},
		"fail/wire-id-display-name-missing": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "wireapp-user", Value: "{\"name\": \"Alice Smith\", \"domain\": \"wire.com\", \"handle\": \"wireapp://%40alice_wire@wire.com\"}"},
				},
			}

			signer := mustSigner("EC", "P-256", 0)
			_, err := keyutil.Fingerprint(signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			wireURL, _ := url.Parse("wireapp://%40alice_wire@wire.com")
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					Organization: []string{"wire.com"},
				},
				URIs: []*url.URL{
					wireURL,
				},
				PublicKey: signer.Public(),
			}

			leaf := &x509.Certificate{
				Subject:   pkix.Name{CommonName: "a-wireapp-user"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}
			inter := &x509.Certificate{Subject: pkix.Name{CommonName: "inter"}}
			root := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}

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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{leaf, inter, root}, nil
					},
				},
				db: &MockWireDB{
					MockDB: MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							return &Authorization{ID: id, Status: StatusValid}, nil
						},
					},
				},
				err: NewError(ErrorServerInternalType, "CSR must contain the display name in '2.16.840.1.113730.3.1.241' OID"),
			}
		},
		"fail/wire-id-display-name-mismatch": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "wireapp-user", Value: "{\"name\": \"Alice Smith\", \"domain\": \"wire.com\", \"handle\": \"wireapp://%40alice_wire@wire.com\"}"},
				},
			}

			signer := mustSigner("EC", "P-256", 0)
			_, err := keyutil.Fingerprint(signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			wireURL, _ := url.Parse("wireapp://%40alice_wire@wire.com")
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					Names: []pkix.AttributeTypeAndValue{
						{Type: asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241}, Value: "Someone else"},
					},
					Organization: []string{"wire.com"},
				},
				URIs: []*url.URL{
					wireURL,
				},
				PublicKey: signer.Public(),
			}

			leaf := &x509.Certificate{
				Subject:   pkix.Name{CommonName: "a-wireapp-user"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}
			inter := &x509.Certificate{Subject: pkix.Name{CommonName: "inter"}}
			root := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}

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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{leaf, inter, root}, nil
					},
				},
				db: &MockWireDB{
					MockDB: MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							return &Authorization{ID: id, Status: StatusValid}, nil
						},
					},
				},
				err: NewError(ErrorServerInternalType, "expected displayName Alice Smith, found Someone else"),
			}
		},
		"ok/wire-id-user": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "wireapp-user", Value: "{\"name\": \"Alice Smith\", \"domain\": \"wire.com\", \"handle\": \"wireapp://%40alice_wire@wire.com\"}"},
				},
			}

			signer := mustSigner("EC", "P-256", 0)
			_, err := keyutil.Fingerprint(signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			wireURL, _ := url.Parse("wireapp://%40alice_wire@wire.com")
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					Names: []pkix.AttributeTypeAndValue{
						{Type: asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241}, Value: "Alice Smith"},
					},
					Organization: []string{"wire.com"},
				},
				URIs: []*url.URL{
					wireURL,
				},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}

			leaf := &x509.Certificate{
				Subject:   pkix.Name{CommonName: "a-wireapp-user"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}
			inter := &x509.Certificate{Subject: pkix.Name{CommonName: "inter"}}
			root := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}

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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{leaf, inter, root}, nil
					},
				},
				db: &MockWireDB{
					MockDB: MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							return &Authorization{ID: id, Status: StatusValid}, nil
						},
					},
					MockGetDpopToken: func(ctx context.Context, orderID string) (map[string]interface{}, error) {
						assert.Equals(t, orderID, o.ID)
						dpopMap := map[string]interface{}{
							"dpop": "a-dpop-token",
						}
						return dpopMap, nil
					},
					MockGetOidcToken: func(ctx context.Context, orderID string) (map[string]interface{}, error) {
						assert.Equals(t, orderID, o.ID)
						oidcMap := map[string]interface{}{
							"oidc": "a-oidc-token",
						}
						return oidcMap, nil
					},
				},
			}
		},
		"ok/wire-id-device": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "wireapp-device", Value: "{\"name\": \"device\", \"domain\": \"wire.com\", \"client-id\": \"wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com\", \"handle\": \"wireapp://%40alice_wire@wire.com\"}"},
				},
			}

			signer := mustSigner("EC", "P-256", 0)
			_, err := keyutil.Fingerprint(signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			wireURL, _ := url.Parse("wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com")
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					Names: []pkix.AttributeTypeAndValue{
						{Type: asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241}, Value: "device"},
					},
					Organization: []string{"wire.com"},
				},
				URIs: []*url.URL{
					wireURL,
				},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}

			leaf := &x509.Certificate{
				Subject:   pkix.Name{CommonName: "a-wireapp-user"},
				PublicKey: signer.Public(),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 3, 1, 241},
						Value: []byte("a-wireapp-user"),
					},
				},
			}
			inter := &x509.Certificate{Subject: pkix.Name{CommonName: "inter"}}
			root := &x509.Certificate{Subject: pkix.Name{CommonName: "root"}}

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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{leaf, inter, root}, nil
					},
				},
				db: &MockWireDB{
					MockDB: MockDB{
						MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
							return &Authorization{ID: id, Status: StatusValid}, nil
						},
					},
					MockGetDpopToken: func(ctx context.Context, orderID string) (map[string]interface{}, error) {
						assert.Equals(t, orderID, o.ID)
						dpopMap := map[string]interface{}{
							"dpop": "a-dpop-token",
						}
						return dpopMap, nil
					},
					MockGetOidcToken: func(ctx context.Context, orderID string) (map[string]interface{}, error) {
						assert.Equals(t, orderID, o.ID)
						oidcMap := map[string]interface{}{
							"oidc": "a-oidc-token",
						}
						return oidcMap, nil
					},
				},
			}
		},
		"ok/new-cert-dns": func(t *testing.T) test {
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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{foo, bar, baz}, nil
					},
				},
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						return &Authorization{ID: id, Status: StatusValid}, nil
					},
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
		"ok/new-cert-ip": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "ip", Value: "192.168.42.42"},
					{Type: "ip", Value: "192.168.43.42"},
				},
			}
			csr := &x509.CertificateRequest{
				IPAddresses: []net.IP{net.ParseIP("192.168.42.42"), net.ParseIP("192.168.43.42")}, // in case of IPs, no Common Name
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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{foo, bar, baz}, nil
					},
				},
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						return &Authorization{ID: id, Status: StatusValid}, nil
					},
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
		"ok/new-cert-dns-and-ip": func(t *testing.T) test {
			now := clock.Now()
			o := &Order{
				ID:               "oID",
				AccountID:        "accID",
				Status:           StatusReady,
				ExpiresAt:        now.Add(5 * time.Minute),
				AuthorizationIDs: []string{"a", "b"},
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "ip", Value: "192.168.42.42"},
				},
			}
			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.internal",
				},
				IPAddresses: []net.IP{net.ParseIP("192.168.42.42")},
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
					signWithContext: func(_ context.Context, _csr *x509.CertificateRequest, signOpts provisioner.SignOptions, extraOpts ...provisioner.SignOption) ([]*x509.Certificate, error) {
						assert.Equals(t, _csr, csr)
						return []*x509.Certificate{foo, bar, baz}, nil
					},
				},
				db: &MockDB{
					MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
						return &Authorization{ID: id, Status: StatusValid}, nil
					},
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
					var k *Error
					if errors.As(err, &k) {
						assert.Equals(t, k.Type, tc.err.Type)
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Status, tc.err.Status)
						assert.Equals(t, k.Err.Error(), tc.err.Err.Error())
						assert.Equals(t, k.Detail, tc.err.Detail)
						assert.Equals(t, k.Subproblems, tc.err.Subproblems)
					} else {
						assert.FatalError(t, errors.New("unexpected error type"))
					}
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func Test_uniqueSortedIPs(t *testing.T) {
	type args struct {
		ips []net.IP
	}
	tests := []struct {
		name string
		args args
		want []net.IP
	}{
		{
			name: "ok/empty",
			args: args{
				ips: []net.IP{},
			},
			want: []net.IP{},
		},
		{
			name: "ok/single-ipv4",
			args: args{
				ips: []net.IP{net.ParseIP("192.168.42.42")},
			},
			want: []net.IP{net.ParseIP("192.168.42.42")},
		},
		{
			name: "ok/multiple-ipv4",
			args: args{
				ips: []net.IP{net.ParseIP("192.168.42.42"), net.ParseIP("192.168.42.10"), net.ParseIP("192.168.42.1"), net.ParseIP("127.0.0.1")},
			},
			want: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.42.1"), net.ParseIP("192.168.42.10"), net.ParseIP("192.168.42.42")},
		}, {
			name: "ok/multiple-ipv4-with-varying-byte-representations",
			args: args{
				ips: []net.IP{net.ParseIP("192.168.42.42"), net.ParseIP("192.168.42.10"), net.ParseIP("192.168.42.1"), []byte{0x7f, 0x0, 0x0, 0x1}},
			},
			want: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.42.1"), net.ParseIP("192.168.42.10"), net.ParseIP("192.168.42.42")},
		},
		{
			name: "ok/unique-ipv4",
			args: args{
				ips: []net.IP{net.ParseIP("192.168.42.42"), net.ParseIP("192.168.42.42")},
			},
			want: []net.IP{net.ParseIP("192.168.42.42")},
		},
		{
			name: "ok/single-ipv6",
			args: args{
				ips: []net.IP{net.ParseIP("2001:db8::30")},
			},
			want: []net.IP{net.ParseIP("2001:db8::30")},
		},
		{
			name: "ok/multiple-ipv6",
			args: args{
				ips: []net.IP{net.ParseIP("2001:db8::30"), net.ParseIP("2001:db8::20"), net.ParseIP("2001:db8::10")},
			},
			want: []net.IP{net.ParseIP("2001:db8::10"), net.ParseIP("2001:db8::20"), net.ParseIP("2001:db8::30")},
		},
		{
			name: "ok/unique-ipv6",
			args: args{
				ips: []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::1")},
			},
			want: []net.IP{net.ParseIP("2001:db8::1")},
		},
		{
			name: "ok/mixed-ipv4-and-ipv6",
			args: args{
				ips: []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::1"), net.ParseIP("192.168.42.42"), net.ParseIP("192.168.42.42")},
			},
			want: []net.IP{net.ParseIP("192.168.42.42"), net.ParseIP("2001:db8::1")},
		},
		{
			name: "ok/mixed-ipv4-and-ipv6-and-varying-byte-representations",
			args: args{
				ips: []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::1"), net.ParseIP("192.168.42.42"), net.ParseIP("192.168.42.42"), []byte{0x7f, 0x0, 0x0, 0x1}},
			},
			want: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.42.42"), net.ParseIP("2001:db8::1")},
		},
		{
			name: "ok/mixed-ipv4-and-ipv6-and-more-varying-byte-representations",
			args: args{
				ips: []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::1"), net.ParseIP("192.168.42.42"), net.ParseIP("2001:db8::2"), net.ParseIP("192.168.42.42"), []byte{0x7f, 0x0, 0x0, 0x1}, []byte{0x7f, 0x0, 0x0, 0x1}, []byte{0x7f, 0x0, 0x0, 0x2}},
			},
			want: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2"), net.ParseIP("192.168.42.42"), net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uniqueSortedIPs(tt.args.ips)
			if !cmp.Equal(tt.want, got) {
				t.Errorf("uniqueSortedIPs() diff =\n%s", cmp.Diff(tt.want, got))
			}
		})
	}
}

func Test_numberOfIdentifierType(t *testing.T) {
	type args struct {
		typ IdentifierType
		ids []Identifier
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "ok/no-identifiers",
			args: args{
				typ: DNS,
				ids: []Identifier{},
			},
			want: 0,
		},
		{
			name: "ok/no-dns",
			args: args{
				typ: DNS,
				ids: []Identifier{
					{
						Type:  IP,
						Value: "192.168.42.42",
					},
				},
			},
			want: 0,
		},
		{
			name: "ok/no-ips",
			args: args{
				typ: IP,
				ids: []Identifier{
					{
						Type:  DNS,
						Value: "example.com",
					},
				},
			},
			want: 0,
		},
		{
			name: "ok/one-dns",
			args: args{
				typ: DNS,
				ids: []Identifier{
					{
						Type:  DNS,
						Value: "example.com",
					},
					{
						Type:  IP,
						Value: "192.168.42.42",
					},
				},
			},
			want: 1,
		},
		{
			name: "ok/one-ip",
			args: args{
				typ: IP,
				ids: []Identifier{
					{
						Type:  DNS,
						Value: "example.com",
					},
					{
						Type:  IP,
						Value: "192.168.42.42",
					},
				},
			},
			want: 1,
		},
		{
			name: "ok/more-dns",
			args: args{
				typ: DNS,
				ids: []Identifier{
					{
						Type:  DNS,
						Value: "example.com",
					},
					{
						Type:  DNS,
						Value: "*.example.com",
					},
					{
						Type:  IP,
						Value: "192.168.42.42",
					},
				},
			},
			want: 2,
		},
		{
			name: "ok/more-ips",
			args: args{
				typ: IP,
				ids: []Identifier{
					{
						Type:  DNS,
						Value: "example.com",
					},
					{
						Type:  IP,
						Value: "192.168.42.42",
					},
					{
						Type:  IP,
						Value: "192.168.42.43",
					},
				},
			},
			want: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := numberOfIdentifierType(tt.args.typ, tt.args.ids); got != tt.want {
				t.Errorf("numberOfIdentifierType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ipsAreEqual(t *testing.T) {
	type args struct {
		x net.IP
		y net.IP
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "ok/ipv4",
			args: args{
				x: net.ParseIP("192.168.42.42"),
				y: net.ParseIP("192.168.42.42"),
			},
			want: true,
		},
		{
			name: "fail/ipv4",
			args: args{
				x: net.ParseIP("192.168.42.42"),
				y: net.ParseIP("192.168.42.43"),
			},
			want: false,
		},
		{
			name: "ok/ipv6",
			args: args{
				x: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
				y: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
			},
			want: true,
		},
		{
			name: "fail/ipv6",
			args: args{
				x: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
				y: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7335"),
			},
			want: false,
		},
		{
			name: "fail/ipv4-and-ipv6",
			args: args{
				x: net.ParseIP("192.168.42.42"),
				y: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
			},
			want: false,
		},
		{
			name: "ok/ipv4-mapped-to-ipv6",
			args: args{
				x: net.ParseIP("192.168.42.42"),
				y: net.ParseIP("::ffff:192.168.42.42"), // parsed to the same IPv4 by Go
			},
			want: true, // we expect this to happen; a known issue in which ipv4 mapped ipv6 addresses are considered the same as their ipv4 counterpart
		},
		{
			name: "fail/invalid-ipv4-and-valid-ipv6",
			args: args{
				x: net.ParseIP("192.168.42.1000"),
				y: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
			},
			want: false,
		},
		{
			name: "fail/valid-ipv4-and-invalid-ipv6",
			args: args{
				x: net.ParseIP("192.168.42.42"),
				y: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:733400"),
			},
			want: false,
		},
		{
			name: "fail/invalid-ipv4-and-invalid-ipv6",
			args: args{
				x: net.ParseIP("192.168.42.1000"),
				y: net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:1000000"),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipsAreEqual(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("ipsAreEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_canonicalize(t *testing.T) {
	type args struct {
		csr *x509.CertificateRequest
	}
	tests := []struct {
		name string
		args args
		want *x509.CertificateRequest
	}{
		{
			name: "ok/dns",
			args: args{
				csr: &x509.CertificateRequest{
					DNSNames: []string{"www.example.com", "example.com"},
				},
			},
			want: &x509.CertificateRequest{
				DNSNames:    []string{"example.com", "www.example.com"},
				IPAddresses: []net.IP{},
			},
		},
		{
			name: "ok/common-name",
			args: args{
				csr: &x509.CertificateRequest{
					Subject: pkix.Name{
						CommonName: "example.com",
					},
					DNSNames: []string{"www.example.com"},
				},
			},
			want: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "example.com",
				},
				DNSNames:    []string{"example.com", "www.example.com"},
				IPAddresses: []net.IP{},
			},
		},
		{
			name: "ok/ipv4",
			args: args{
				csr: &x509.CertificateRequest{
					IPAddresses: []net.IP{net.ParseIP("192.168.43.42"), net.ParseIP("192.168.42.42")},
				},
			},
			want: &x509.CertificateRequest{
				DNSNames:    []string{},
				IPAddresses: []net.IP{net.ParseIP("192.168.42.42"), net.ParseIP("192.168.43.42")},
			},
		},
		{
			name: "ok/mixed",
			args: args{
				csr: &x509.CertificateRequest{
					DNSNames:    []string{"www.example.com", "example.com"},
					IPAddresses: []net.IP{net.ParseIP("192.168.43.42"), net.ParseIP("192.168.42.42")},
				},
			},
			want: &x509.CertificateRequest{
				DNSNames:    []string{"example.com", "www.example.com"},
				IPAddresses: []net.IP{net.ParseIP("192.168.42.42"), net.ParseIP("192.168.43.42")},
			},
		},
		{
			name: "ok/mixed-common-name",
			args: args{
				csr: &x509.CertificateRequest{
					Subject: pkix.Name{
						CommonName: "example.com",
					},
					DNSNames:    []string{"www.example.com"},
					IPAddresses: []net.IP{net.ParseIP("192.168.43.42"), net.ParseIP("192.168.42.42")},
				},
			},
			want: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "example.com",
				},
				DNSNames:    []string{"example.com", "www.example.com"},
				IPAddresses: []net.IP{net.ParseIP("192.168.42.42"), net.ParseIP("192.168.43.42")},
			},
		},
		{
			name: "ok/ip-common-name",
			args: args{
				csr: &x509.CertificateRequest{
					Subject: pkix.Name{
						CommonName: "127.0.0.1",
					},
					DNSNames:    []string{"example.com"},
					IPAddresses: []net.IP{net.ParseIP("192.168.43.42"), net.ParseIP("192.168.42.42")},
				},
			},
			want: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "127.0.0.1",
				},
				DNSNames:    []string{"example.com"},
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.42.42"), net.ParseIP("192.168.43.42")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalize(tt.args.csr)
			if !cmp.Equal(tt.want, got) {
				t.Errorf("canonicalize() diff =\n%s", cmp.Diff(tt.want, got))
			}
		})
	}
}

func TestOrder_sans(t *testing.T) {
	type fields struct {
		Identifiers []Identifier
	}
	tests := []struct {
		name   string
		fields fields
		csr    *x509.CertificateRequest
		want   []x509util.SubjectAlternativeName
		err    *Error
	}{
		{
			name: "ok/dns",
			fields: fields{
				Identifiers: []Identifier{
					{Type: "dns", Value: "example.com"},
				},
			},
			csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "example.com",
				},
			},
			want: []x509util.SubjectAlternativeName{
				{Type: "dns", Value: "example.com"},
			},
			err: nil,
		},
		{
			name: "fail/invalid-alternative-name-email",
			fields: fields{
				Identifiers: []Identifier{},
			},
			csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.internal",
				},
				EmailAddresses: []string{"test@example.com"},
			},
			want: []x509util.SubjectAlternativeName{},
			err:  NewError(ErrorBadCSRType, "Only DNS names and IP addresses are allowed"),
		},
		{
			name: "fail/error-names-length-mismatch",
			fields: fields{
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "dns", Value: "bar.internal"},
				},
			},
			csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.internal",
				},
			},
			want: []x509util.SubjectAlternativeName{},
			err: NewError(ErrorBadCSRType, "CSR names do not match identifiers exactly: "+
				"CSR names = %v, Order names = %v", []string{"foo.internal"}, []string{"bar.internal", "foo.internal"}),
		},
		{
			name: "fail/error-names-mismatch",
			fields: fields{
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "dns", Value: "bar.internal"},
				},
			},
			csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "foo.internal",
				},
				DNSNames: []string{"zap.internal"},
			},
			want: []x509util.SubjectAlternativeName{},
			err: NewError(ErrorBadCSRType, "CSR names do not match identifiers exactly: "+
				"CSR names = %v, Order names = %v", []string{"foo.internal", "zap.internal"}, []string{"bar.internal", "foo.internal"}),
		},
		{
			name: "ok/ipv4",
			fields: fields{
				Identifiers: []Identifier{
					{Type: "ip", Value: "192.168.43.42"},
					{Type: "ip", Value: "192.168.42.42"},
				},
			},
			csr: &x509.CertificateRequest{
				IPAddresses: []net.IP{net.ParseIP("192.168.43.42"), net.ParseIP("192.168.42.42")},
			},
			want: []x509util.SubjectAlternativeName{
				{Type: "ip", Value: "192.168.42.42"},
				{Type: "ip", Value: "192.168.43.42"},
			},
			err: nil,
		},
		{
			name: "ok/ipv6",
			fields: fields{
				Identifiers: []Identifier{
					{Type: "ip", Value: "2001:0db8:85a3::8a2e:0370:7335"},
					{Type: "ip", Value: "2001:0db8:85a3::8a2e:0370:7334"},
				},
			},
			csr: &x509.CertificateRequest{
				IPAddresses: []net.IP{net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7335"), net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
			},
			want: []x509util.SubjectAlternativeName{
				{Type: "ip", Value: "2001:db8:85a3::8a2e:370:7334"},
				{Type: "ip", Value: "2001:db8:85a3::8a2e:370:7335"},
			},
			err: nil,
		},
		{
			name: "fail/error-ips-length-mismatch",
			fields: fields{
				Identifiers: []Identifier{
					{Type: "ip", Value: "192.168.42.42"},
					{Type: "ip", Value: "192.168.43.42"},
				},
			},
			csr: &x509.CertificateRequest{
				IPAddresses: []net.IP{net.ParseIP("192.168.42.42")},
			},
			want: []x509util.SubjectAlternativeName{},
			err: NewError(ErrorBadCSRType, "CSR IPs do not match identifiers exactly: "+
				"CSR IPs = %v, Order IPs = %v", []net.IP{net.ParseIP("192.168.42.42")}, []net.IP{net.ParseIP("192.168.42.42"), net.ParseIP("192.168.43.42")}),
		},
		{
			name: "fail/error-ips-mismatch",
			fields: fields{
				Identifiers: []Identifier{
					{Type: "ip", Value: "192.168.42.42"},
					{Type: "ip", Value: "192.168.43.42"},
				},
			},
			csr: &x509.CertificateRequest{
				IPAddresses: []net.IP{net.ParseIP("192.168.42.42"), net.ParseIP("192.168.42.32")},
			},
			want: []x509util.SubjectAlternativeName{},
			err: NewError(ErrorBadCSRType, "CSR IPs do not match identifiers exactly: "+
				"CSR IPs = %v, Order IPs = %v", []net.IP{net.ParseIP("192.168.42.32"), net.ParseIP("192.168.42.42")}, []net.IP{net.ParseIP("192.168.42.42"), net.ParseIP("192.168.43.42")}),
		},
		{
			name: "ok/mixed",
			fields: fields{
				Identifiers: []Identifier{
					{Type: "dns", Value: "foo.internal"},
					{Type: "dns", Value: "bar.internal"},
					{Type: "ip", Value: "192.168.43.42"},
					{Type: "ip", Value: "192.168.42.42"},
					{Type: "ip", Value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
				},
			},
			csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "bar.internal",
				},
				DNSNames:    []string{"foo.internal"},
				IPAddresses: []net.IP{net.ParseIP("192.168.43.42"), net.ParseIP("192.168.42.42"), net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
			},
			want: []x509util.SubjectAlternativeName{
				{Type: "dns", Value: "bar.internal"},
				{Type: "dns", Value: "foo.internal"},
				{Type: "ip", Value: "192.168.42.42"},
				{Type: "ip", Value: "192.168.43.42"},
				{Type: "ip", Value: "2001:db8:85a3::8a2e:370:7334"},
			},
			err: nil,
		},
		{
			name: "fail/unsupported-identifier-type",
			fields: fields{
				Identifiers: []Identifier{
					{Type: "ipv4", Value: "192.168.42.42"},
				},
			},
			csr: &x509.CertificateRequest{
				IPAddresses: []net.IP{net.ParseIP("192.168.42.42")},
			},
			want: []x509util.SubjectAlternativeName{},
			err:  NewError(ErrorServerInternalType, "unsupported identifier type in order: ipv4"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Order{
				Identifiers: tt.fields.Identifiers,
			}
			canonicalizedCSR := canonicalize(tt.csr)
			got, err := o.sans(canonicalizedCSR)
			if tt.err != nil {
				if err == nil {
					t.Errorf("Order.sans() = %v, want error; got none", got)
					return
				}
				var k *Error
				if errors.As(err, &k) {
					assert.Equals(t, k.Type, tt.err.Type)
					assert.Equals(t, k.Detail, tt.err.Detail)
					assert.Equals(t, k.Status, tt.err.Status)
					assert.Equals(t, k.Err.Error(), tt.err.Err.Error())
					assert.Equals(t, k.Detail, tt.err.Detail)
				} else {
					assert.FatalError(t, errors.New("unexpected error type"))
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Order.sans() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOrder_getAuthorizationFingerprint(t *testing.T) {
	ctx := context.Background()
	type fields struct {
		AuthorizationIDs []string
	}
	type args struct {
		ctx context.Context
		db  DB
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{"ok", fields{[]string{"az1", "az2"}}, args{ctx, &MockDB{
			MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
				return &Authorization{ID: id, Status: StatusValid}, nil
			},
		}}, "", false},
		{"ok fingerprint", fields{[]string{"az1", "az2"}}, args{ctx, &MockDB{
			MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
				if id == "az1" {
					return &Authorization{ID: id, Status: StatusValid}, nil
				}
				return &Authorization{ID: id, Fingerprint: "fingerprint", Status: StatusValid}, nil
			},
		}}, "fingerprint", false},
		{"fail", fields{[]string{"az1", "az2"}}, args{ctx, &MockDB{
			MockGetAuthorization: func(ctx context.Context, id string) (*Authorization, error) {
				return nil, errors.New("force")
			},
		}}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Order{
				AuthorizationIDs: tt.fields.AuthorizationIDs,
			}
			got, err := o.getAuthorizationFingerprint(tt.args.ctx, tt.args.db)
			if (err != nil) != tt.wantErr {
				t.Errorf("Order.getAuthorizationFingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Order.getAuthorizationFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}
