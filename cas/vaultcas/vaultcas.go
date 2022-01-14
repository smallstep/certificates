package vaultcas

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/cas/apiv1"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	certutil "github.com/hashicorp/vault/sdk/helper/certutil"
	mapstructure "github.com/mitchellh/mapstructure"
)

func init() {
	apiv1.Register(apiv1.VaultCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

type VaultOptions struct {
	PKI             string `json:"pki,omitempty"`
	PKIRole         string `json:"pkiRole,omitempty`
	PKIRoleRSA      string `json:"pkiRoleRSA,omitempty`
	PKIRoleEC       string `json:"pkiRoleEC,omitempty`
	PKIRoleED25519  string `json:"PKIRoleED25519,omitempty`
	RoleID          string `json:"roleID,omitempty"`
	SecretID        string `json:"secretID,omitempty"`
	AppRole         string `json:"appRole,omitempty"`
	IsWrappingToken bool   `json:"isWrappingToken,omitempty"`
}

// VaultCAS implements a Certificate Authority Service using Hashicorp Vault.
type VaultCAS struct {
	client      *vault.Client
	config      VaultOptions
	fingerprint string
}

func loadOptions(config map[string]interface{}) (vc VaultOptions, err error) {
	err = mapstructure.Decode(config, &vc)
	if err != nil {
		return vc, err
	}

	if vc.PKI == "" {
		vc.PKI = "pki" // use default pki vault name
	}

	// pkirole or per key type must be defined
	if vc.PKIRole == "" && vc.PKIRoleRSA == "" && vc.PKIRoleEC == "" && vc.PKIRoleED25519 == "" {
		return vc, errors.New("loadOptions you must define a pki role")
	}

	// if pkirole is empty all others keys must be set
	if vc.PKIRole == "" && (vc.PKIRoleRSA == "" || vc.PKIRoleEC == "" || vc.PKIRoleED25519 == "") {
		return vc, errors.New("loadOptions if 'pkiRole' is empty, PKIRoleRSA, PKIRoleEC and PKIRoleED25519 cannot be empty")
	}

	// if pkirole is not empty, use it as default for unset keys
	if vc.PKIRole != "" {
		if vc.PKIRoleRSA == "" {
			vc.PKIRoleRSA = vc.PKIRole
		}
		if vc.PKIRoleEC == "" {
			vc.PKIRoleEC = vc.PKIRole
		}
		if vc.PKIRoleED25519 == "" {
			vc.PKIRoleED25519 = vc.PKIRole
		}
	}

	if vc.RoleID == "" {
		return vc, errors.New("loadOptions 'roleID' cannot be empty")
	}

	if vc.SecretID == "" {
		return vc, errors.New("loadOptions 'secretID' cannot be empty")
	}

	if vc.AppRole == "" {
		vc.AppRole = "auth/approle"
	}

	return vc, nil
}

func getCertificateAndChain(certb certutil.CertBundle) (*x509.Certificate, []*x509.Certificate, error) {
	cert, err := parseCertificate(certb.Certificate)
	if err != nil {
		return nil, nil, err
	}
	chain := make([]*x509.Certificate, len(certb.CAChain))
	for i := range certb.CAChain {
		chain[i], err = parseCertificate(certb.CAChain[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return cert, chain, nil
}

func parseCertificate(pemCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, errors.Errorf("parseCertificate: error decoding certificate: not a valid PEM encoded block '%v'", pemCert)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parseCertificate: error parsing certificate")
	}
	return cert, nil
}

func parseCertificateRequest(pemCsr string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemCsr))
	if block == nil {
		return nil, errors.New("error decoding certificate request: not a valid PEM encoded block")
	}
	cr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing certificate request")
	}
	return cr, nil
}

func (v *VaultCAS) createCertificate(cr *x509.CertificateRequest, lifetime time.Duration) (*x509.Certificate, []*x509.Certificate, error) {
	sans := make([]string, 0, len(cr.DNSNames)+len(cr.EmailAddresses)+len(cr.IPAddresses)+len(cr.URIs))
	sans = append(sans, cr.DNSNames...)
	sans = append(sans, cr.EmailAddresses...)
	for _, ip := range cr.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, u := range cr.URIs {
		sans = append(sans, u.String())
	}

	commonName := cr.Subject.CommonName
	if commonName == "" && len(sans) > 0 {
		commonName = sans[0]
	}

	var vaultPKIRole string
	csr := api.CertificateRequest{CertificateRequest: cr}

	switch {
	case csr.PublicKeyAlgorithm == x509.RSA:
		vaultPKIRole = v.config.PKIRoleRSA
	case csr.PublicKeyAlgorithm == x509.ECDSA:
		vaultPKIRole = v.config.PKIRoleEC
	case csr.PublicKeyAlgorithm == x509.Ed25519:
		vaultPKIRole = v.config.PKIRoleED25519
	default:
		return nil, nil, errors.Errorf("createCertificate: Unsupported public key algorithm '%v'", csr.PublicKeyAlgorithm)
	}

	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	if certPemBytes == nil {
		return nil, nil, errors.Errorf("createCertificate: Failed to encode pem '%v'", csr.Raw)
	}

	y := map[string]interface{}{
		"csr":    string(certPemBytes),
		"format": "pem_bundle",
		"ttl":    lifetime.Seconds(),
	}

	secret, err := v.client.Logical().Write(v.config.PKI+"/sign/"+vaultPKIRole, y)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "createCertificate: unable to sign certificate %v", y)
	}
	if secret == nil {
		return nil, nil, errors.New("createCertificate: secret sign is empty")
	}

	var certBundle certutil.CertBundle

	err = mapstructure.Decode(secret.Data, &certBundle)
	if err != nil {
		return nil, nil, err
	}

	// Return certificate and certificate chain
	return getCertificateAndChain(certBundle)
}

// New creates a new CertificateAuthorityService implementation
// using Hashicorp Vault
func New(ctx context.Context, opts apiv1.Options) (*VaultCAS, error) {
	if opts.CertificateAuthority == "" {
		return nil, errors.New("vaultCAS 'certificateAuthority' cannot be empty")
	}

	if opts.CertificateAuthorityFingerprint == "" {
		return nil, errors.New("vaultCAS 'certificateAuthorityFingerprint' cannot be empty")
	}

	vc, err := loadOptions(opts.Config)
	if err != nil {
		return nil, err
	}

	config := vault.DefaultConfig()
	config.Address = opts.CertificateAuthority

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "unable to initialize vault client")
	}

	var appRoleAuth *auth.AppRoleAuth
	if vc.IsWrappingToken == true {
		appRoleAuth, err = auth.NewAppRoleAuth(
			vc.RoleID,
			&auth.SecretID{FromString: vc.SecretID},
			auth.WithWrappingToken(),
			auth.WithMountPath(vc.AppRole),
		)
	} else {
		appRoleAuth, err = auth.NewAppRoleAuth(
			vc.RoleID,
			&auth.SecretID{FromString: vc.SecretID},
			auth.WithMountPath(vc.AppRole),
		)
	}
	if err != nil {
		return nil, errors.Wrap(err, "unable to initialize AppRole auth method")
	}

	authInfo, err := client.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return nil, errors.Wrap(err, "unable to login to AppRole auth method")
	}
	if authInfo == nil {
		return nil, errors.New("no auth info was returned after login")
	}

	return &VaultCAS{
		client:      client,
		config:      vc,
		fingerprint: opts.CertificateAuthorityFingerprint,
	}, nil
}

// CreateCertificate signs a new certificate using Hashicorp Vault.
func (v *VaultCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	switch {
	case req.CSR == nil:
		return nil, errors.New("CreateCertificate: `CSR` cannot be nil")
	case req.Lifetime == 0:
		return nil, errors.New("CreateCertificate: `LIFETIME` cannot be 0")
	}

	cert, chain, err := v.createCertificate(req.CSR, req.Lifetime)
	if err != nil {
		return nil, err
	}

	return &apiv1.CreateCertificateResponse{
		Certificate:      cert,
		CertificateChain: chain,
	}, nil
}

func (v *VaultCAS) GetCertificateAuthority(req *apiv1.GetCertificateAuthorityRequest) (*apiv1.GetCertificateAuthorityResponse, error) {
	secret, err := v.client.Logical().Read(v.config.PKI + "/cert/ca")
	if err != nil {
		return nil, errors.Wrap(err, "GetCertificateAuthority: unable to read root")
	}
	if secret == nil {
		return nil, errors.New("GetCertificateAuthority: secret root is empty")
	}

	var certBundle certutil.CertBundle

	err = mapstructure.Decode(secret.Data, &certBundle)
	if err != nil {
		return nil, err
	}

	cert, _, err := getCertificateAndChain(certBundle)
	if err != nil {
		return nil, err
	}
	return &apiv1.GetCertificateAuthorityResponse{
		RootCertificate: cert,
	}, nil
}

// RenewCertificate will always return a non-implemented error as renewals
// are not supported yet.
func (v *VaultCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	return nil, apiv1.ErrNotImplemented{Message: "vaultCAS does not support renewals"}
}

func (v *VaultCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	if req.SerialNumber == "" && req.Certificate == nil {
		return nil, errors.New("RevokeCertificate `serialNumber` or `certificate` are required")
	}

	serialNumber := req.SerialNumber
	if req.Certificate != nil {
		serialNumber = req.Certificate.SerialNumber.String()
	}

	serialNumberDash := strings.ReplaceAll(serialNumber, ":", "-")

	_, err := v.client.Logical().Write(v.config.PKI+"/revoke/"+serialNumberDash, nil)
	if err != nil {
		return nil, errors.Wrap(err, "RevokeCertificate unable to revoke certificate")
	}

	return &apiv1.RevokeCertificateResponse{
		Certificate:      req.Certificate,
		CertificateChain: nil,
	}, nil
}
