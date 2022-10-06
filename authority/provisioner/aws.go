package provisioner

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/sshutil"
	"go.step.sm/crypto/x509util"
	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/errs"
)

// awsIssuer is the string used as issuer in the generated tokens.
const awsIssuer = "ec2.amazonaws.com"

// awsIdentityURL is the url used to retrieve the instance identity document.
const awsIdentityURL = "http://169.254.169.254/latest/dynamic/instance-identity/document"

// awsSignatureURL is the url used to retrieve the instance identity signature.
const awsSignatureURL = "http://169.254.169.254/latest/dynamic/instance-identity/signature"

// awsAPITokenURL is the url used to get the IMDSv2 API token
const awsAPITokenURL = "http://169.254.169.254/latest/api/token" //nolint:gosec // no credentials here

// awsAPITokenTTL is the default TTL to use when requesting IMDSv2 API tokens
// -- we keep this short-lived since we get a new token with every call to readURL()
const awsAPITokenTTL = "30"

// awsMetadataTokenHeader is the header that must be passed with every IMDSv2 request
const awsMetadataTokenHeader = "X-aws-ec2-metadata-token" //nolint:gosec // no credentials here

// awsMetadataTokenTTLHeader is the header used to indicate the token TTL requested
const awsMetadataTokenTTLHeader = "X-aws-ec2-metadata-token-ttl-seconds" //nolint:gosec // no credentials here

// awsCertificate is the certificate used to validate the instance identity
// signature.
//
// The first certificate is used in:
//
//	ap-northeast-2, ap-south-1, ap-southeast-1, ap-southeast-2
//	eu-central-1, eu-north-1, eu-west-1, eu-west-2, eu-west-3
//	us-east-1, us-east-2, us-west-1, us-west-2
//	ca-central-1, sa-east-1
//
// The second certificate is used in:
//
//	eu-south-1
//
// The third certificate is used in:
//
//	ap-east-1
//
// The fourth certificate is used in:
//
//	af-south-1
//
// The fifth certificate is used in:
//
//	me-south-1
const awsCertificate = `-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu
Y29tMB4XDTE0MDYwNTE0MjgwMloXDTI0MDYwNTE0MjgwMlowajELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJL
XeE4hwvo0sD4f3j9AgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIs
77VBdlE4MIGcBgNVHSMEgZQwgZGAFCXWzAgVyrbwnFncFFIs77VBdlE4oW6kbDBq
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh
dHRsZTEYMBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1h
em9uYXdzLmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF
BQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8T
C1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ
7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICNjCCAZ+gAwIBAgIJAOZ3GEIaDcugMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV
BAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0
dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0xOTEwMjQx
NTE5MDlaGA8yMTk5MDMyOTE1MTkwOVowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgT
EFdhc2hpbmd0b24gU3RhdGUxEDAOBgNVBAcTB1NlYXR0bGUxIDAeBgNVBAoTF0Ft
YXpvbiBXZWIgU2VydmljZXMgTExDMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQCjiPgW3vsXRj4JoA16WQDyoPc/eh3QBARaApJEc4nPIGoUolpAXcjFhWplo2O+
ivgfCsc4AU9OpYdAPha3spLey/bhHPRi1JZHRNqScKP0hzsCNmKhfnZTIEQCFvsp
DRp4zr91/WS06/flJFBYJ6JHhp0KwM81XQG59lV6kkoW7QIDAQABMA0GCSqGSIb3
DQEBCwUAA4GBAGLLrY3P+HH6C57dYgtJkuGZGT2+rMkk2n81/abzTJvsqRqGRrWv
XRKRXlKdM/dfiuYGokDGxiC0Mg6TYy6wvsR2qRhtXW1OtZkiHWcQCnOttz+8vpew
wx8JGMvowtuKB1iMsbwyRqZkFYLcvH+Opfb/Aayi20/ChQLdI6M2R5VU
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICSzCCAbQCCQDtQvkVxRvK9TANBgkqhkiG9w0BAQsFADBqMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2VhdHRsZTEYMBYGA1UE
ChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1hem9uYXdzLmNvbTAe
Fw0xOTAyMDMwMzAwMDZaFw0yOTAyMDIwMzAwMDZaMGoxCzAJBgNVBAYTAlVTMRMw
EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgwFgYDVQQKEw9B
bWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3MuY29tMIGfMA0G
CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1kkHXYTfc7gY5Q55JJhjTieHAgacaQkiR
Pity9QPDE3b+NXDh4UdP1xdIw73JcIIG3sG9RhWiXVCHh6KkuCTqJfPUknIKk8vs
M3RXflUpBe8Pf+P92pxqPMCz1Fr2NehS3JhhpkCZVGxxwLC5gaG0Lr4rFORubjYY
Rh84dK98VwIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAA6xV9f0HMqXjPHuGILDyaNN
dKcvplNFwDTydVg32MNubAGnecoEBtUPtxBsLoVYXCOb+b5/ZMDubPF9tU/vSXuo
TpYM5Bq57gJzDRaBOntQbX9bgHiUxw6XZWaTS/6xjRJDT5p3S1E0mPI3lP/eJv4o
Ezk5zb3eIf10/sqt4756
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICNjCCAZ+gAwIBAgIJAKumfZiRrNvHMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV
BAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0
dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0xOTExMjcw
NzE0MDVaGA8yMTk5MDUwMjA3MTQwNVowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgT
EFdhc2hpbmd0b24gU3RhdGUxEDAOBgNVBAcTB1NlYXR0bGUxIDAeBgNVBAoTF0Ft
YXpvbiBXZWIgU2VydmljZXMgTExDMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQDFd571nUzVtke3rPyRkYfvs3jh0C0EMzzG72boyUNjnfw1+m0TeFraTLKb9T6F
7TuB/ZEN+vmlYqr2+5Va8U8qLbPF0bRH+FdaKjhgWZdYXxGzQzU3ioy5W5ZM1VyB
7iUsxEAlxsybC3ziPYaHI42UiTkQNahmoroNeqVyHNnBpQIDAQABMA0GCSqGSIb3
DQEBCwUAA4GBAAJLylWyElEgOpW4B1XPyRVD4pAds8Guw2+krgqkY0HxLCdjosuH
RytGDGN+q75aAoXzW5a7SGpxLxk6Hfv0xp3RjDHsoeP0i1d8MD3hAC5ezxS4oukK
s5gbPOnokhKTMPXbTdRn5ZifCbWlx+bYN/mTYKvxho7b5SVg2o1La9aK
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDPDCCAqWgAwIBAgIJAMl6uIV/zqJFMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxlMSAw
HgYDVQQKDBdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzEaMBgGA1UEAwwRZWMyLmFt
YXpvbmF3cy5jb20wIBcNMTkwNDI2MTQzMjQ3WhgPMjE5ODA5MjkxNDMyNDdaMHIx
CzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0
dGxlMSAwHgYDVQQKDBdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzEaMBgGA1UEAwwR
ZWMyLmFtYXpvbmF3cy5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALVN
CDTZEnIeoX1SEYqq6k1BV0ZlpY5y3KnoOreCAE589TwS4MX5+8Fzd6AmACmugeBP
Qk7Hm6b2+g/d4tWycyxLaQlcq81DB1GmXehRkZRgGeRge1ePWd1TUA0I8P/QBT7S
gUePm/kANSFU+P7s7u1NNl+vynyi0wUUrw7/wIZTAgMBAAGjgdcwgdQwHQYDVR0O
BBYEFILtMd+T4YgH1cgc+hVsVOV+480FMIGkBgNVHSMEgZwwgZmAFILtMd+T4YgH
1cgc+hVsVOV+480FoXakdDByMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGlu
Z3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEgMB4GA1UECgwXQW1hem9uIFdlYiBTZXJ2
aWNlcyBMTEMxGjAYBgNVBAMMEWVjMi5hbWF6b25hd3MuY29tggkAyXq4hX/OokUw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQBhkNTBIFgWFd+ZhC/LhRUY
4OjEiykmbEp6hlzQ79T0Tfbn5A4NYDI2icBP0+hmf6qSnIhwJF6typyd1yPK5Fqt
NTpxxcXmUKquX+pHmIkK1LKDO8rNE84jqxrxRsfDi6by82fjVYf2pgjJW8R1FAw+
mL5WQRFexbfB5aXhcMo0AA==
-----END CERTIFICATE-----`

// awsSignatureAlgorithm is the signature algorithm used to verify the identity
// document signature.
const awsSignatureAlgorithm = x509.SHA256WithRSA

type awsConfig struct {
	identityURL        string
	signatureURL       string
	tokenURL           string
	tokenTTL           string
	certificates       []*x509.Certificate
	signatureAlgorithm x509.SignatureAlgorithm
}

func newAWSConfig(certPath string) (*awsConfig, error) {
	var certBytes []byte
	if certPath == "" {
		certBytes = []byte(awsCertificate)
	} else {
		if b, err := os.ReadFile(certPath); err == nil {
			certBytes = b
		} else {
			return nil, errors.Wrapf(err, "error reading %s", certPath)
		}
	}

	// Read all the certificates.
	var certs []*x509.Certificate
	for len(certBytes) > 0 {
		var block *pem.Block
		block, certBytes = pem.Decode(certBytes)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing AWS IID certificate")
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("error parsing AWS IID certificate: no certificates found")
	}

	return &awsConfig{
		identityURL:        awsIdentityURL,
		signatureURL:       awsSignatureURL,
		tokenURL:           awsAPITokenURL,
		tokenTTL:           awsAPITokenTTL,
		certificates:       certs,
		signatureAlgorithm: awsSignatureAlgorithm,
	}, nil
}

type awsPayload struct {
	jose.Claims
	Amazon   awsAmazonPayload `json:"amazon"`
	SANs     []string         `json:"sans"`
	document awsInstanceIdentityDocument
}

type awsAmazonPayload struct {
	Document  []byte `json:"document"`
	Signature []byte `json:"signature"`
}

type awsInstanceIdentityDocument struct {
	AccountID          string    `json:"accountId"`
	Architecture       string    `json:"architecture"`
	AvailabilityZone   string    `json:"availabilityZone"`
	BillingProducts    []string  `json:"billingProducts"`
	DevpayProductCodes []string  `json:"devpayProductCodes"`
	ImageID            string    `json:"imageId"`
	InstanceID         string    `json:"instanceId"`
	InstanceType       string    `json:"instanceType"`
	KernelID           string    `json:"kernelId"`
	PendingTime        time.Time `json:"pendingTime"`
	PrivateIP          string    `json:"privateIp"`
	RamdiskID          string    `json:"ramdiskId"`
	Region             string    `json:"region"`
	Version            string    `json:"version"`
}

// AWS is the provisioner that supports identity tokens created from the Amazon
// Web Services Instance Identity Documents.
//
// If DisableCustomSANs is true, only the internal DNS and IP will be added as a
// SAN. By default it will accept any SAN in the CSR.
//
// If DisableTrustOnFirstUse is true, multiple sign request for this provisioner
// with the same instance will be accepted. By default only the first request
// will be accepted.
//
// If InstanceAge is set, only the instances with a pendingTime within the given
// period will be accepted.
//
// IIDRoots can be used to specify a path to the certificates used to verify the
// identity certificate signature.
//
// Amazon Identity docs are available at
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
type AWS struct {
	*base
	ID                     string   `json:"-"`
	Type                   string   `json:"type"`
	Name                   string   `json:"name"`
	Accounts               []string `json:"accounts"`
	DisableCustomSANs      bool     `json:"disableCustomSANs"`
	DisableTrustOnFirstUse bool     `json:"disableTrustOnFirstUse"`
	IMDSVersions           []string `json:"imdsVersions"`
	InstanceAge            Duration `json:"instanceAge,omitempty"`
	IIDRoots               string   `json:"iidRoots,omitempty"`
	Claims                 *Claims  `json:"claims,omitempty"`
	Options                *Options `json:"options,omitempty"`
	config                 *awsConfig
	ctl                    *Controller
}

// GetID returns the provisioner unique identifier.
func (p *AWS) GetID() string {
	if p.ID != "" {
		return p.ID
	}
	return p.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner
// from a token.
func (p *AWS) GetIDForToken() string {
	return "aws/" + p.Name
}

// GetTokenID returns the identifier of the token.
func (p *AWS) GetTokenID(token string) (string, error) {
	payload, err := p.authorizeToken(token)
	if err != nil {
		return "", err
	}
	// If TOFU is disabled create an ID for the token, so it cannot be reused.
	// The timestamps, document and signatures should be mostly unique.
	if p.DisableTrustOnFirstUse {
		sum := sha256.Sum256([]byte(token))
		return strings.ToLower(hex.EncodeToString(sum[:])), nil
	}

	// Use provisioner + instance-id as the identifier.
	unique := fmt.Sprintf("%s.%s", p.GetIDForToken(), payload.document.InstanceID)
	sum := sha256.Sum256([]byte(unique))
	return strings.ToLower(hex.EncodeToString(sum[:])), nil
}

// GetName returns the name of the provisioner.
func (p *AWS) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *AWS) GetType() Type {
	return TypeAWS
}

// GetEncryptedKey is not available in an AWS provisioner.
func (p *AWS) GetEncryptedKey() (kid, key string, ok bool) {
	return "", "", false
}

// GetIdentityToken retrieves the identity document and it's signature and
// generates a token with them.
func (p *AWS) GetIdentityToken(subject, caURL string) (string, error) {
	// Initialize the config if this method is used from the cli.
	if err := p.assertConfig(); err != nil {
		return "", err
	}

	var idoc awsInstanceIdentityDocument
	doc, err := p.readURL(p.config.identityURL)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving identity document:\n  Are you in an AWS VM?\n  Is the metadata service enabled?\n  Are you using the proper metadata service version?")
	}
	if err := json.Unmarshal(doc, &idoc); err != nil {
		return "", errors.Wrap(err, "error unmarshaling identity document")
	}
	sig, err := p.readURL(p.config.signatureURL)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving identity document:\n  Are you in an AWS VM?\n  Is the metadata service enabled?\n  Are you using the proper metadata service version?")
	}
	signature, err := base64.StdEncoding.DecodeString(string(sig))
	if err != nil {
		return "", errors.Wrap(err, "error decoding identity document signature")
	}
	if err := p.checkSignature(doc, signature); err != nil {
		return "", err
	}

	audience, err := generateSignAudience(caURL, p.GetIDForToken())
	if err != nil {
		return "", err
	}

	// Create unique ID for Trust On First Use (TOFU). Only the first instance
	// per provisioner is allowed as we don't have a way to trust the given
	// sans.
	unique := fmt.Sprintf("%s.%s", p.GetIDForToken(), idoc.InstanceID)
	sum := sha256.Sum256([]byte(unique))

	// Create a JWT from the identity document
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: signature},
		new(jose.SignerOptions).WithType("JWT"),
	)
	if err != nil {
		return "", errors.Wrap(err, "error creating signer")
	}

	now := time.Now()
	payload := awsPayload{
		Claims: jose.Claims{
			Issuer:    awsIssuer,
			Subject:   subject,
			Audience:  []string{audience},
			Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
			NotBefore: jose.NewNumericDate(now),
			IssuedAt:  jose.NewNumericDate(now),
			ID:        strings.ToLower(hex.EncodeToString(sum[:])),
		},
		Amazon: awsAmazonPayload{
			Document:  doc,
			Signature: signature,
		},
	}

	tok, err := jose.Signed(signer).Claims(payload).CompactSerialize()
	if err != nil {
		return "", errors.Wrap(err, "error serializing token")
	}

	return tok, nil
}

// Init validates and initializes the AWS provisioner.
func (p *AWS) Init(config Config) (err error) {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	case p.InstanceAge.Value() < 0:
		return errors.New("provisioner instanceAge cannot be negative")
	}

	// Add default config
	if p.config, err = newAWSConfig(p.IIDRoots); err != nil {
		return err
	}

	// validate IMDS versions
	if len(p.IMDSVersions) == 0 {
		p.IMDSVersions = []string{"v2", "v1"}
	}
	for _, v := range p.IMDSVersions {
		switch v {
		case "v1":
			// valid
		case "v2":
			// valid
		default:
			return errors.Errorf("%s: not a supported AWS Instance Metadata Service version", v)
		}
	}

	config.Audiences = config.Audiences.WithFragment(p.GetIDForToken())
	p.ctl, err = NewController(p, p.Claims, config, p.Options)
	return
}

// AuthorizeSign validates the given token and returns the sign options that
// will be used on certificate creation.
func (p *AWS) AuthorizeSign(ctx context.Context, token string) ([]SignOption, error) {
	payload, err := p.authorizeToken(token)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "aws.AuthorizeSign")
	}

	doc := payload.document

	// Template options
	data := x509util.NewTemplateData()
	data.SetCommonName(payload.Claims.Subject)
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	// Enforce known CN and default DNS and IP if configured.
	// By default we'll accept the CN and SANs in the CSR.
	// There's no way to trust them other than TOFU.
	var so []SignOption
	if p.DisableCustomSANs {
		dnsName := fmt.Sprintf("ip-%s.%s.compute.internal", strings.ReplaceAll(doc.PrivateIP, ".", "-"), doc.Region)
		so = append(so,
			dnsNamesValidator([]string{dnsName}),
			ipAddressesValidator([]net.IP{
				net.ParseIP(doc.PrivateIP),
			}),
			emailAddressesValidator(nil),
			urisValidator(nil),
		)

		// Template options
		data.SetSANs([]string{dnsName, doc.PrivateIP})
	}

	templateOptions, err := CustomTemplateOptions(p.Options, data, x509util.DefaultIIDLeafTemplate)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "aws.AuthorizeSign")
	}

	return append(so,
		p,
		templateOptions,
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeAWS, p.Name, doc.AccountID, "InstanceID", doc.InstanceID),
		profileDefaultDuration(p.ctl.Claimer.DefaultTLSCertDuration()),
		// validators
		defaultPublicKeyValidator{},
		commonNameValidator(payload.Claims.Subject),
		newValidityValidator(p.ctl.Claimer.MinTLSCertDuration(), p.ctl.Claimer.MaxTLSCertDuration()),
		newX509NamePolicyValidator(p.ctl.getPolicy().getX509()),
		p.ctl.newWebhookController(data, linkedca.Webhook_X509),
	), nil
}

// AuthorizeRenew returns an error if the renewal is disabled.
// NOTE: This method does not actually validate the certificate or check it's
// revocation status. Just confirms that the provisioner that created the
// certificate was configured to allow renewals.
func (p *AWS) AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error {
	return p.ctl.AuthorizeRenew(ctx, cert)
}

// assertConfig initializes the config if it has not been initialized
func (p *AWS) assertConfig() (err error) {
	if p.config != nil {
		return
	}
	p.config, err = newAWSConfig(p.IIDRoots)
	return err
}

// checkSignature returns an error if the signature is not valid.
func (p *AWS) checkSignature(signed, signature []byte) error {
	for _, crt := range p.config.certificates {
		if err := crt.CheckSignature(p.config.signatureAlgorithm, signed, signature); err == nil {
			return nil
		}
	}
	return errors.New("error validating identity document signature")
}

// readURL does a GET request to the given url and returns the body. It's not
// using pkg/errors to avoid verbose errors, the caller should use it and write
// the appropriate error.
func (p *AWS) readURL(url string) ([]byte, error) {
	var resp *http.Response
	var err error

	// Initialize IMDS versions when this is called from the cli.
	if len(p.IMDSVersions) == 0 {
		p.IMDSVersions = []string{"v2", "v1"}
	}

	for _, v := range p.IMDSVersions {
		switch v {
		case "v1":
			resp, err = p.readURLv1(url)
			if err == nil && resp.StatusCode < 400 {
				return p.readResponseBody(resp)
			}
		case "v2":
			resp, err = p.readURLv2(url)
			if err == nil && resp.StatusCode < 400 {
				return p.readResponseBody(resp)
			}
		default:
			return nil, fmt.Errorf("%s: not a supported AWS Instance Metadata Service version", v)
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	// all versions have been exhausted and we haven't returned successfully yet so pass
	// the error on to the caller
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("request for metadata returned non-successful status code %d",
		resp.StatusCode)
}

func (p *AWS) readURLv1(url string) (*http.Response, error) {
	client := http.Client{}

	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (p *AWS) readURLv2(url string) (*http.Response, error) {
	client := http.Client{}

	// first get the token
	req, err := http.NewRequest(http.MethodPut, p.config.tokenURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set(awsMetadataTokenTTLHeader, p.config.tokenTTL)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("request for API token returned non-successful status code %d", resp.StatusCode)
	}
	token, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// now make the request
	req, err = http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set(awsMetadataTokenHeader, string(token))
	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (p *AWS) readResponseBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// authorizeToken performs common jwt authorization actions and returns the
// claims for case specific downstream parsing.
// e.g. a Sign request will auth/validate different fields than a Revoke request.
func (p *AWS) authorizeToken(token string) (*awsPayload, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errs.Wrapf(http.StatusUnauthorized, err, "aws.authorizeToken; error parsing aws token")
	}
	if len(jwt.Headers) == 0 {
		return nil, errs.InternalServer("aws.authorizeToken; error parsing token, header is missing")
	}

	var unsafeClaims awsPayload
	if err := jwt.UnsafeClaimsWithoutVerification(&unsafeClaims); err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err, "aws.authorizeToken; error unmarshaling claims")
	}

	var payload awsPayload
	if err := jwt.Claims(unsafeClaims.Amazon.Signature, &payload); err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err, "aws.authorizeToken; error verifying claims")
	}

	// Validate identity document signature
	if err := p.checkSignature(payload.Amazon.Document, payload.Amazon.Signature); err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err, "aws.authorizeToken; invalid aws token signature")
	}

	var doc awsInstanceIdentityDocument
	if err := json.Unmarshal(payload.Amazon.Document, &doc); err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err, "aws.authorizeToken; error unmarshaling aws identity document")
	}

	switch {
	case doc.AccountID == "":
		return nil, errs.Unauthorized("aws.authorizeToken; aws identity document accountId cannot be empty")
	case doc.InstanceID == "":
		return nil, errs.Unauthorized("aws.authorizeToken; aws identity document instanceId cannot be empty")
	case doc.PrivateIP == "":
		return nil, errs.Unauthorized("aws.authorizeToken; aws identity document privateIp cannot be empty")
	case doc.Region == "":
		return nil, errs.Unauthorized("aws.authorizeToken; aws identity document region cannot be empty")
	}

	// According to "rfc7519 JSON Web Token" acceptable skew should be no
	// more than a few minutes.
	now := time.Now().UTC()
	if err = payload.ValidateWithLeeway(jose.Expected{
		Issuer: awsIssuer,
		Time:   now,
	}, time.Minute); err != nil {
		return nil, errs.Wrapf(http.StatusUnauthorized, err, "aws.authorizeToken; invalid aws token")
	}

	// validate audiences with the defaults
	if !matchesAudience(payload.Audience, p.ctl.Audiences.Sign) {
		return nil, errs.Unauthorized("aws.authorizeToken; invalid token - invalid audience claim (aud)")
	}

	// Validate subject, it has to be known if disableCustomSANs is enabled
	if p.DisableCustomSANs {
		if payload.Subject != doc.InstanceID &&
			payload.Subject != doc.PrivateIP &&
			payload.Subject != fmt.Sprintf("ip-%s.%s.compute.internal", strings.ReplaceAll(doc.PrivateIP, ".", "-"), doc.Region) {
			return nil, errs.Unauthorized("aws.authorizeToken; invalid token - invalid subject claim (sub)")
		}
	}

	// validate accounts
	if len(p.Accounts) > 0 {
		var found bool
		for _, sa := range p.Accounts {
			if sa == doc.AccountID {
				found = true
				break
			}
		}
		if !found {
			return nil, errs.Unauthorized("aws.authorizeToken; invalid aws identity document - accountId is not valid")
		}
	}

	// validate instance age
	if d := p.InstanceAge.Value(); d > 0 {
		if now.Sub(doc.PendingTime) > d {
			return nil, errs.Unauthorized("aws.authorizeToken; aws identity document pendingTime is too old")
		}
	}

	payload.document = doc
	return &payload, nil
}

// AuthorizeSSHSign returns the list of SignOption for a SignSSH request.
func (p *AWS) AuthorizeSSHSign(ctx context.Context, token string) ([]SignOption, error) {
	if !p.ctl.Claimer.IsSSHCAEnabled() {
		return nil, errs.Unauthorized("aws.AuthorizeSSHSign; ssh ca is disabled for aws provisioner '%s'", p.GetName())
	}
	claims, err := p.authorizeToken(token)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "aws.AuthorizeSSHSign")
	}

	doc := claims.document
	signOptions := []SignOption{}

	// Enforce host certificate.
	defaults := SignSSHOptions{
		CertType: SSHHostCert,
	}

	// Validated principals.
	principals := []string{
		doc.PrivateIP,
		fmt.Sprintf("ip-%s.%s.compute.internal", strings.ReplaceAll(doc.PrivateIP, ".", "-"), doc.Region),
	}

	// Only enforce known principals if disable custom sans is true.
	if p.DisableCustomSANs {
		defaults.Principals = principals
	} else {
		// Check that at least one principal is sent in the request.
		signOptions = append(signOptions, &sshCertOptionsRequireValidator{
			Principals: true,
		})
	}

	// Certificate templates.
	data := sshutil.CreateTemplateData(sshutil.HostCert, doc.InstanceID, principals)
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	templateOptions, err := CustomSSHTemplateOptions(p.Options, data, sshutil.DefaultIIDTemplate)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "aws.AuthorizeSSHSign")
	}
	signOptions = append(signOptions, templateOptions)

	return append(signOptions,
		p,
		// Validate user SignSSHOptions.
		sshCertOptionsValidator(defaults),
		// Set the validity bounds if not set.
		&sshDefaultDuration{p.ctl.Claimer},
		// Validate public key
		&sshDefaultPublicKeyValidator{},
		// Validate the validity period.
		&sshCertValidityValidator{p.ctl.Claimer},
		// Require all the fields in the SSH certificate
		&sshCertDefaultValidator{},
		// Ensure that all principal names are allowed
		newSSHNamePolicyValidator(p.ctl.getPolicy().getSSHHost(), nil),
		// Call webhooks
		p.ctl.newWebhookController(data, linkedca.Webhook_SSH),
	), nil
}
