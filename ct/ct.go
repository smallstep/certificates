package ct

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/pkg/errors"
)

var (
	oidExtensionCTPoison              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidSignedCertificateTimestampList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// Config represents the configuration for the certificate authority client.
type Config struct {
	URI           string    `json:"uri"`
	Key           string    `json:"key"`
	NotAfterStart time.Time `json:"notAfterStart,omitempty"`
	NotAfterLimit time.Time `json:"notAfterLimit,omitempty"`
}

// Validate validates the ct configuration.
func (c *Config) Validate() error {
	switch {
	case c.URI == "":
		return errors.New("ct uri cannot be empty")
	case c.Key == "":
		return errors.New("ct key cannot be empty")
	default:
		return nil
	}
}

// Client is the interface used to communicate with the certificate transparency logs.
type Client interface {
	GetSCTs(asn1Data ...[]byte) (*SCT, error)
	SubmitToLogs(asn1Data ...[]byte) (*SCT, error)
}

type logClient interface {
	AddChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error)
	AddPreChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error)
}

// SCT represents a Signed Certificate Timestamp.
type SCT struct {
	LogURL string
	SCT    *ct.SignedCertificateTimestamp
}

// GetExtension returns the extension representing an SCT that will be added to
// a certificate.
func (t *SCT) GetExtension() pkix.Extension {
	val, err := cttls.Marshal(*t.SCT)
	if err != nil {
		panic(err)
	}
	value, err := cttls.Marshal(ctx509.SignedCertificateTimestampList{
		SCTList: []ctx509.SerializedSCT{
			{Val: val},
		},
	})
	if err != nil {
		panic(err)
	}
	rawValue, err := asn1.Marshal(value)
	if err != nil {
		panic(err)
	}
	return pkix.Extension{
		Id:       oidSignedCertificateTimestampList,
		Critical: false,
		Value:    rawValue,
	}
}

// AddPoisonExtension appends the ct poison extension to the given certificate.
func AddPoisonExtension(cert *x509.Certificate) {
	cert.Extensions = append(cert.Extensions, pkix.Extension{
		Id:       oidExtensionCTPoison,
		Critical: true,
	})
}

// ClientImpl is the implementation of a certificate transparency Client.
type ClientImpl struct {
	config    Config
	logClient logClient
	timeout   time.Duration
}

// New creates a new Client
func New(c Config) (*ClientImpl, error) {
	der, err := readPublicKey(c.Key)
	if err != nil {
		return nil, err
	}

	// Initialize ct client
	logClient, err := client.New(c.URI, &http.Client{}, jsonclient.Options{
		PublicKeyDER: der,
		UserAgent:    "smallstep certificates",
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create client to %s", c.URI)
	}

	// Validate connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := logClient.GetSTH(ctx); err != nil {
		return nil, errors.Wrapf(err, "failed to connect to %s", c.URI)
	}
	log.Printf("connecting to CT log %s", c.URI)
	log.Println("CT support is experimental and can change at any time")

	return &ClientImpl{
		config:    c,
		logClient: logClient,
		timeout:   30 * time.Second,
	}, nil
}

// GetSCTs submit the precertificate to the logs and returns the list of SCTs to
// embed into the certificate.
func (c *ClientImpl) GetSCTs(asn1Data ...[]byte) (*SCT, error) {
	chain := chainFromDERs(asn1Data)
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	sct, err := c.logClient.AddPreChain(ctx, chain)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get SCT from %s", c.config.URI)
	}
	logLeafHash("AddPreChain", asn1Data, sct, true)
	return &SCT{
		LogURL: c.config.URI,
		SCT:    sct,
	}, nil
}

// SubmitToLogs submits the certificate to the certificate transparency logs.
func (c *ClientImpl) SubmitToLogs(asn1Data ...[]byte) (*SCT, error) {
	chain := chainFromDERs(asn1Data)
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	sct, err := c.logClient.AddChain(ctx, chain)
	if err != nil {
		return nil, errors.Wrapf(err, "failed submit certificate to %s", c.config.URI)
	}
	logLeafHash("AddChain", asn1Data, sct, false)
	return &SCT{
		LogURL: c.config.URI,
		SCT:    sct,
	}, nil
}

// readPublicKey extracts the DER from the given file.
func readPublicKey(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", filename)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(rest) > 0 {
		return nil, errors.Wrapf(err, "invalid public key %s", filename)
	}
	return block.Bytes, nil
}

func chainFromDERs(asn1Data [][]byte) []ct.ASN1Cert {
	var chain []ct.ASN1Cert
	for _, der := range asn1Data {
		chain = append(chain, ct.ASN1Cert{Data: der})
	}
	return chain
}

func logLeafHash(op string, asn1Data [][]byte, sct *ct.SignedCertificateTimestamp, isPrecert bool) {
	var etype ct.LogEntryType
	if isPrecert {
		etype = ct.PrecertLogEntryType
	} else {
		etype = ct.X509LogEntryType
	}

	chain := make([]*ctx509.Certificate, len(asn1Data))
	for i := range asn1Data {
		cert, err := ctx509.ParseCertificate(asn1Data[i])
		if err != nil {
			log.Println(err)
			return
		}
		chain[i] = cert
	}

	leafEntry, err := ct.MerkleTreeLeafFromChain(chain, etype, sct.Timestamp)
	if err != nil {
		log.Println(err)
		return
	}

	leafHash, err := ct.LeafHashForLeaf(leafEntry)
	if err != nil {
		log.Println(err)
		return
	}

	log.Printf("Op: %s, LogID: %x, LeafHash: %x, Timestamp: %d\n", op, sct.LogID.KeyID[:], leafHash, sct.Timestamp)
}
