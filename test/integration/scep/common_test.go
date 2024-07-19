package sceptest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/cas/apiv1"
)

func newCAClient(t *testing.T, caURL, rootFilepath string) *ca.Client {
	caClient, err := ca.NewClient(
		caURL,
		ca.WithRootFile(rootFilepath),
	)
	require.NoError(t, err)
	return caClient
}

func requireHealthyCA(t *testing.T, caClient *ca.Client) {
	t.Helper()
	// Wait for CA
	time.Sleep(time.Second)

	ctx := context.Background()
	healthResponse, err := caClient.HealthWithContext(ctx)
	require.NoError(t, err)
	if assert.NotNil(t, healthResponse) {
		require.Equal(t, "ok", healthResponse.Status)
	}
}

// reservePort "reserves" a TCP port by opening a listener on a random
// port and immediately closing it. The port can then be assumed to be
// available for running a server on.
func reservePort(t *testing.T) (host, port string) {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	address := l.Addr().String()
	err = l.Close()
	require.NoError(t, err)

	host, port, err = net.SplitHostPort(address)
	require.NoError(t, err)

	return
}

type client struct {
	caURL      string
	caCert     *x509.Certificate
	httpClient *http.Client
}

func createSCEPClient(t *testing.T, caURL string, root *x509.Certificate) *client {
	t.Helper()
	trustedRoots := x509.NewCertPool()
	trustedRoots.AddCert(root)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs: trustedRoots,
	}
	httpClient := &http.Client{
		Transport: transport,
	}
	return &client{
		caURL:      caURL,
		httpClient: httpClient,
	}
}

func (c *client) getCACert(t *testing.T) error {
	// return early if CA certificate already available
	if c.caCert != nil {
		return nil
	}

	resp, err := c.httpClient.Get(fmt.Sprintf("%s?operation=GetCACert&message=test", c.caURL))
	if err != nil {
		return fmt.Errorf("failed get request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed reading response body: %w", err)
	}

	t.Log(string(body))

	// SCEP CA/RA certificate selection. If there's only a single certificate, it will
	// be used as the CA certificate at all times. If there's multiple, the first certificate
	// is assumed to be the certificate of the recipient to encrypt messages to.
	switch ct := resp.Header.Get("Content-Type"); ct {
	case "application/x-x509-ca-cert":
		cert, err := x509.ParseCertificate(body)
		if err != nil {
			return fmt.Errorf("failed parsing response body: %w", err)
		}
		if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
			return fmt.Errorf("certificate has unexpected public key type %T", cert.PublicKey)
		}
		c.caCert = cert
	case "application/x-x509-ca-ra-cert":
		certs, err := scep.CACerts(body)
		if err != nil {
			return fmt.Errorf("failed parsing response body: %w", err)
		}
		cert := certs[0]
		if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
			return fmt.Errorf("certificate has unexpected public key type %T", cert.PublicKey)
		}
		c.caCert = cert
	default:
		return fmt.Errorf("unexpected content-type value %q", ct)
	}

	return nil
}

func (c *client) requestCertificate(t *testing.T, commonName string, sans []string) (*x509.Certificate, error) {
	if err := c.getCACert(t); err != nil {
		return nil, fmt.Errorf("failed getting CA certificate: %w", err)
	}

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed creating SCEP private key: %w", err)
	}

	csr, err := x509util.CreateCertificateRequest(commonName, sans, signer)
	if err != nil {
		return nil, fmt.Errorf("failed creating CSR: %w", err)
	}

	tmpl := &x509.Certificate{
		Subject:        csr.Subject,
		PublicKey:      signer.Public(),
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now().Add(-1 * time.Hour),
		NotAfter:       time.Now().Add(1 * time.Hour),
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}

	selfSigned, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("failed creating self signed certificate: %w", err)
	}
	selfSignedCertificate, err := x509.ParseCertificate(selfSigned)
	if err != nil {
		return nil, fmt.Errorf("failed parsing self signed certificate: %w", err)
	}

	msgTmpl := &scep.PKIMessage{
		TransactionID: "test-1",
		MessageType:   scep.PKCSReq,
		SenderNonce:   []byte("test-nonce-1"),
		Recipients:    []*x509.Certificate{c.caCert},
		SignerCert:    selfSignedCertificate,
		SignerKey:     signer,
	}

	msg, err := scep.NewCSRRequest(csr, msgTmpl)
	if err != nil {
		return nil, fmt.Errorf("failed creating SCEP PKCSReq message: %w", err)
	}

	t.Log(string(msg.Raw))

	u, err := url.Parse(c.caURL)
	if err != nil {
		return nil, fmt.Errorf("failed parsing CA URL: %w", err)
	}

	opURL := u.ResolveReference(&url.URL{RawQuery: fmt.Sprintf("operation=PKIOperation&message=%s", url.QueryEscape(base64.StdEncoding.EncodeToString(msg.Raw)))})
	resp, err := c.httpClient.Get(opURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed get request: %w", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "application/x-pki-message" {
		return nil, fmt.Errorf("received unexpected content type %q", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %w", err)
	}

	t.Log(string(body))

	signedData, err := pkcs7.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("failed parsing response body: %w", err)
	}

	// TODO: verify the signature?

	p7, err := pkcs7.Parse(signedData.Content)
	if err != nil {
		return nil, fmt.Errorf("failed decrypting inner p7: %w", err)
	}

	content, err := p7.Decrypt(selfSignedCertificate, signer)
	if err != nil {
		return nil, fmt.Errorf("failed decrypting response: %w", err)
	}

	p7, err = pkcs7.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("failed parsing p7 content: %w", err)
	}

	cert := p7.Certificates[0]

	return cert, nil
}

type testCAS struct {
	ca *minica.CA
}

func (c *testCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	cert, err := c.ca.SignCSR(req.CSR)
	if err != nil {
		return nil, fmt.Errorf("failed signing CSR: %w", err)
	}

	return &apiv1.CreateCertificateResponse{
		Certificate:      cert,
		CertificateChain: []*x509.Certificate{cert, c.ca.Intermediate},
	}, nil
}
func (c *testCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	return nil, errors.New("not implemented")
}

func (c *testCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	return nil, errors.New("not implemented")
}

func (c *testCAS) GetCertificateAuthority(req *apiv1.GetCertificateAuthorityRequest) (*apiv1.GetCertificateAuthorityResponse, error) {
	return &apiv1.GetCertificateAuthorityResponse{
		RootCertificate:          c.ca.Root,
		IntermediateCertificates: []*x509.Certificate{c.ca.Intermediate},
	}, nil
}

var _ apiv1.CertificateAuthorityService = (*testCAS)(nil)
var _ apiv1.CertificateAuthorityGetter = (*testCAS)(nil)
