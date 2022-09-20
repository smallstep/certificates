package vaultcas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/cas/vaultcas/auth/approle"
	"github.com/smallstep/certificates/cas/vaultcas/auth/kubernetes"

	vault "github.com/hashicorp/vault/api"
)

func init() {
	apiv1.Register(apiv1.VaultCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

// VaultOptions defines the configuration options added using the
// apiv1.Options.Config field.
type VaultOptions struct {
	PKIMountPath   string          `json:"pkiMountPath,omitempty"`
	PKIRoleDefault string          `json:"pkiRoleDefault,omitempty"`
	PKIRoleRSA     string          `json:"pkiRoleRSA,omitempty"`
	PKIRoleEC      string          `json:"pkiRoleEC,omitempty"`
	PKIRoleEd25519 string          `json:"pkiRoleEd25519,omitempty"`
	AuthType       string          `json:"authType,omitempty"`
	AuthMountPath  string          `json:"authMountPath,omitempty"`
	AuthOptions    json.RawMessage `json:"authOptions,omitempty"`
}

// VaultCAS implements a Certificate Authority Service using Hashicorp Vault.
type VaultCAS struct {
	client      *vault.Client
	config      VaultOptions
	fingerprint string
}

type certBundle struct {
	leaf          *x509.Certificate
	intermediates []*x509.Certificate
	root          *x509.Certificate
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
		return nil, fmt.Errorf("unable to initialize vault client: %w", err)
	}

	var method vault.AuthMethod
	switch vc.AuthType {
	case "kubernetes":
		method, err = kubernetes.NewKubernetesAuthMethod(vc.AuthMountPath, vc.AuthOptions)
	case "approle":
		method, err = approle.NewApproleAuthMethod(vc.AuthMountPath, vc.AuthOptions)
	default:
		return nil, fmt.Errorf("unknown auth type: %s, only 'kubernetes' and 'approle' currently supported", vc.AuthType)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to configure %s auth method: %w", vc.AuthType, err)
	}

	authInfo, err := client.Auth().Login(ctx, method)
	if err != nil {
		return nil, fmt.Errorf("unable to login to %s auth method: %w", vc.AuthType, err)
	}
	if authInfo == nil {
		return nil, errors.New("no auth info was returned after login")
	}

	return &VaultCAS{
		client:      client,
		config:      *vc,
		fingerprint: opts.CertificateAuthorityFingerprint,
	}, nil
}

// CreateCertificate signs a new certificate using Hashicorp Vault.
func (v *VaultCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	switch {
	case req.CSR == nil:
		return nil, errors.New("createCertificate `csr` cannot be nil")
	case req.Lifetime == 0:
		return nil, errors.New("createCertificate `lifetime` cannot be 0")
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

// GetCertificateAuthority returns the root certificate of the certificate
// authority using the configured fingerprint.
func (v *VaultCAS) GetCertificateAuthority(req *apiv1.GetCertificateAuthorityRequest) (*apiv1.GetCertificateAuthorityResponse, error) {
	secret, err := v.client.Logical().Read(v.config.PKIMountPath + "/cert/ca_chain")
	if err != nil {
		return nil, fmt.Errorf("error reading ca chain: %w", err)
	}
	if secret == nil {
		return nil, errors.New("error reading ca chain: response is empty")
	}

	chain, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, errors.New("error unmarshaling vault response: certificate not found")
	}

	cert, err := getCertificateBundle(chain)
	if err != nil {
		return nil, err
	}
	if cert.root == nil {
		return nil, errors.New("error unmarshaling vault response: root certificate not found")
	}

	sum := sha256.Sum256(cert.root.Raw)
	if !strings.EqualFold(v.fingerprint, strings.ToLower(hex.EncodeToString(sum[:]))) {
		return nil, errors.New("error verifying vault root: fingerprint does not match")
	}

	return &apiv1.GetCertificateAuthorityResponse{
		RootCertificate: cert.root,
	}, nil
}

// RenewCertificate will always return a non-implemented error as renewals
// are not supported yet.
func (v *VaultCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	return nil, apiv1.NotImplementedError{Message: "vaultCAS does not support renewals"}
}

// RevokeCertificate revokes a certificate by serial number.
func (v *VaultCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	if req.SerialNumber == "" && req.Certificate == nil {
		return nil, errors.New("revokeCertificate `serialNumber` or `certificate` are required")
	}

	var sn *big.Int
	if req.SerialNumber != "" {
		var ok bool
		if sn, ok = new(big.Int).SetString(req.SerialNumber, 10); !ok {
			return nil, fmt.Errorf("error parsing serialNumber: %v cannot be converted to big.Int", req.SerialNumber)
		}
	} else {
		sn = req.Certificate.SerialNumber
	}

	vaultReq := map[string]interface{}{
		"serial_number": formatSerialNumber(sn),
	}
	_, err := v.client.Logical().Write(v.config.PKIMountPath+"/revoke/", vaultReq)
	if err != nil {
		return nil, fmt.Errorf("error revoking certificate: %w", err)
	}

	return &apiv1.RevokeCertificateResponse{
		Certificate:      req.Certificate,
		CertificateChain: nil,
	}, nil
}

func (v *VaultCAS) createCertificate(cr *x509.CertificateRequest, lifetime time.Duration) (*x509.Certificate, []*x509.Certificate, error) {
	var vaultPKIRole string

	switch {
	case cr.PublicKeyAlgorithm == x509.RSA:
		vaultPKIRole = v.config.PKIRoleRSA
	case cr.PublicKeyAlgorithm == x509.ECDSA:
		vaultPKIRole = v.config.PKIRoleEC
	case cr.PublicKeyAlgorithm == x509.Ed25519:
		vaultPKIRole = v.config.PKIRoleEd25519
	default:
		return nil, nil, fmt.Errorf("unsupported public key algorithm %v", cr.PublicKeyAlgorithm)
	}

	vaultReq := map[string]interface{}{
		"csr": string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: cr.Raw,
		})),
		"format": "pem_bundle",
		"ttl":    lifetime.Seconds(),
	}

	secret, err := v.client.Logical().Write(v.config.PKIMountPath+"/sign/"+vaultPKIRole, vaultReq)
	if err != nil {
		return nil, nil, fmt.Errorf("error signing certificate: %w", err)
	}
	if secret == nil {
		return nil, nil, errors.New("error signing certificate: response is empty")
	}

	chain, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, nil, errors.New("error unmarshaling vault response: certificate not found")
	}

	cert, err := getCertificateBundle(chain)
	if err != nil {
		return nil, nil, err
	}

	// Return certificate and certificate chain
	return cert.leaf, cert.intermediates, nil
}

func loadOptions(config json.RawMessage) (*VaultOptions, error) {
	// setup default values
	vc := VaultOptions{
		PKIMountPath:   "pki",
		PKIRoleDefault: "default",
	}

	err := json.Unmarshal(config, &vc)
	if err != nil {
		return nil, fmt.Errorf("error decoding vaultCAS config: %w", err)
	}

	if vc.PKIRoleRSA == "" {
		vc.PKIRoleRSA = vc.PKIRoleDefault
	}
	if vc.PKIRoleEC == "" {
		vc.PKIRoleEC = vc.PKIRoleDefault
	}
	if vc.PKIRoleEd25519 == "" {
		vc.PKIRoleEd25519 = vc.PKIRoleDefault
	}

	return &vc, nil
}

func parseCertificates(pemCert string) []*x509.Certificate {
	var certs []*x509.Certificate
	rest := []byte(pemCert)
	var block *pem.Block
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			break
		}
		certs = append(certs, cert)
	}
	return certs
}

func getCertificateBundle(chain string) (*certBundle, error) {
	var root *x509.Certificate
	var leaf *x509.Certificate
	var intermediates []*x509.Certificate
	for _, cert := range parseCertificates(chain) {
		switch {
		case isRoot(cert):
			root = cert
		case cert.BasicConstraintsValid && cert.IsCA:
			intermediates = append(intermediates, cert)
		default:
			leaf = cert
		}
	}

	certificate := &certBundle{
		root:          root,
		leaf:          leaf,
		intermediates: intermediates,
	}

	return certificate, nil
}

// isRoot returns true if the given certificate is a root certificate.
func isRoot(cert *x509.Certificate) bool {
	if cert.BasicConstraintsValid && cert.IsCA {
		return cert.CheckSignatureFrom(cert) == nil
	}
	return false
}

// formatSerialNumber formats a serial number to a dash-separated hexadecimal
// string.
func formatSerialNumber(sn *big.Int) string {
	var ret bytes.Buffer
	for _, b := range sn.Bytes() {
		if ret.Len() > 0 {
			ret.WriteString("-")
		}
		ret.WriteString(hex.EncodeToString([]byte{b}))
	}
	return ret.String()
}
