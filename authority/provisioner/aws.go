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
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/errs"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/sshutil"
	"go.step.sm/crypto/x509util"
)

// awsIssuer is the string used as issuer in the generated tokens.
const awsIssuer = "ec2.amazonaws.com"

// awsIdentityURL is the url used to retrieve the instance identity document.
const awsIdentityURL = "http://169.254.169.254/latest/dynamic/instance-identity/document"

// awsSignatureURL is the url used to retrieve the instance identity signature.
const awsSignatureURL = "http://169.254.169.254/latest/dynamic/instance-identity/signature"

// awsAPITokenURL is the url used to get the IMDSv2 API token
const awsAPITokenURL = "http://169.254.169.254/latest/api/token"

// awsAPITokenTTL is the default TTL to use when requesting IMDSv2 API tokens
// -- we keep this short-lived since we get a new token with every call to readURL()
const awsAPITokenTTL = "30"

// awsMetadataTokenHeader is the header that must be passed with every IMDSv2 request
const awsMetadataTokenHeader = "X-aws-ec2-metadata-token"

// awsMetadataTokenTTLHeader is the header used to indicate the token TTL requested
const awsMetadataTokenTTLHeader = "X-aws-ec2-metadata-token-ttl-seconds"

// awsCertificate is the certificate used to validate the instance identity
// signature.
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
-----END CERTIFICATE-----`

// awsSignatureAlgorithm is the signature algorithm used to verify the identity
// document signature.
const awsSignatureAlgorithm = x509.SHA256WithRSA

type awsConfig struct {
	identityURL        string
	signatureURL       string
	tokenURL           string
	tokenTTL           string
	certificate        *x509.Certificate
	signatureAlgorithm x509.SignatureAlgorithm
}

func newAWSConfig() (*awsConfig, error) {
	block, _ := pem.Decode([]byte(awsCertificate))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("error decoding AWS certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing AWS certificate")
	}
	return &awsConfig{
		identityURL:        awsIdentityURL,
		signatureURL:       awsSignatureURL,
		tokenURL:           awsAPITokenURL,
		tokenTTL:           awsAPITokenTTL,
		certificate:        cert,
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
// Amazon Identity docs are available at
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
type AWS struct {
	*base
	Type                   string   `json:"type"`
	Name                   string   `json:"name"`
	Accounts               []string `json:"accounts"`
	DisableCustomSANs      bool     `json:"disableCustomSANs"`
	DisableTrustOnFirstUse bool     `json:"disableTrustOnFirstUse"`
	IMDSVersions           []string `json:"imdsVersions"`
	InstanceAge            Duration `json:"instanceAge,omitempty"`
	Claims                 *Claims  `json:"claims,omitempty"`
	Options                *Options `json:"options,omitempty"`
	claimer                *Claimer
	config                 *awsConfig
	audiences              Audiences
}

// GetID returns the provisioner unique identifier.
func (p *AWS) GetID() string {
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
	return payload.ID, nil
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
func (p *AWS) GetEncryptedKey() (kid string, key string, ok bool) {
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

	audience, err := generateSignAudience(caURL, p.GetID())
	if err != nil {
		return "", err
	}

	// Create unique ID for Trust On First Use (TOFU). Only the first instance
	// per provisioner is allowed as we don't have a way to trust the given
	// sans.
	unique := fmt.Sprintf("%s.%s", p.GetID(), idoc.InstanceID)
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
		return "", errors.Wrap(err, "error serialiazing token")
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
	// Update claims with global ones
	if p.claimer, err = NewClaimer(p.Claims, config.Claims); err != nil {
		return err
	}
	// Add default config
	if p.config, err = newAWSConfig(); err != nil {
		return err
	}
	p.audiences = config.Audiences.WithFragment(p.GetID())

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

	return nil
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
		dnsName := fmt.Sprintf("ip-%s.%s.compute.internal", strings.Replace(doc.PrivateIP, ".", "-", -1), doc.Region)
		so = append(so, dnsNamesValidator([]string{dnsName}))
		so = append(so, ipAddressesValidator([]net.IP{
			net.ParseIP(doc.PrivateIP),
		}))
		so = append(so, emailAddressesValidator(nil))
		so = append(so, urisValidator(nil))

		// Template options
		data.SetSANs([]string{dnsName, doc.PrivateIP})
	}

	templateOptions, err := CustomTemplateOptions(p.Options, data, x509util.DefaultIIDLeafTemplate)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "aws.AuthorizeSign")
	}

	return append(so,
		templateOptions,
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeAWS, p.Name, doc.AccountID, "InstanceID", doc.InstanceID),
		profileDefaultDuration(p.claimer.DefaultTLSCertDuration()),
		// validators
		defaultPublicKeyValidator{},
		commonNameValidator(payload.Claims.Subject),
		newValidityValidator(p.claimer.MinTLSCertDuration(), p.claimer.MaxTLSCertDuration()),
	), nil
}

// AuthorizeRenew returns an error if the renewal is disabled.
// NOTE: This method does not actually validate the certificate or check it's
// revocation status. Just confirms that the provisioner that created the
// certificate was configured to allow renewals.
func (p *AWS) AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error {
	if p.claimer.IsDisableRenewal() {
		return errs.Unauthorized("aws.AuthorizeRenew; renew is disabled for aws provisioner %s", p.GetID())
	}
	return nil
}

// assertConfig initializes the config if it has not been initialized
func (p *AWS) assertConfig() (err error) {
	if p.config != nil {
		return
	}
	p.config, err = newAWSConfig()
	return err
}

// checkSignature returns an error if the signature is not valid.
func (p *AWS) checkSignature(signed, signature []byte) error {
	if err := p.config.certificate.CheckSignature(p.config.signatureAlgorithm, signed, signature); err != nil {
		return errors.Wrap(err, "error validating identity document signature")
	}
	return nil
}

// readURL does a GET request to the given url and returns the body. It's not
// using pkg/errors to avoid verbose errors, the caller should use it and write
// the appropriate error.
func (p *AWS) readURL(url string) ([]byte, error) {
	var resp *http.Response
	var err error

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
	return nil, fmt.Errorf("Request for metadata returned non-successful status code %d",
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
	req, err := http.NewRequest(http.MethodPut, p.config.tokenURL, nil)
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
		return nil, fmt.Errorf("Request for API token returned non-successful status code %d", resp.StatusCode)
	}
	token, err := ioutil.ReadAll(resp.Body)
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
	b, err := ioutil.ReadAll(resp.Body)
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
	if !matchesAudience(payload.Audience, p.audiences.Sign) {
		return nil, errs.Unauthorized("aws.authorizeToken; invalid token - invalid audience claim (aud)")
	}

	// Validate subject, it has to be known if disableCustomSANs is enabled
	if p.DisableCustomSANs {
		if payload.Subject != doc.InstanceID &&
			payload.Subject != doc.PrivateIP &&
			payload.Subject != fmt.Sprintf("ip-%s.%s.compute.internal", strings.Replace(doc.PrivateIP, ".", "-", -1), doc.Region) {
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
	if !p.claimer.IsSSHCAEnabled() {
		return nil, errs.Unauthorized("aws.AuthorizeSSHSign; ssh ca is disabled for aws provisioner %s", p.GetID())
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
		fmt.Sprintf("ip-%s.%s.compute.internal", strings.Replace(doc.PrivateIP, ".", "-", -1), doc.Region),
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
		// Validate user SignSSHOptions.
		sshCertOptionsValidator(defaults),
		// Set the validity bounds if not set.
		&sshDefaultDuration{p.claimer},
		// Validate public key
		&sshDefaultPublicKeyValidator{},
		// Validate the validity period.
		&sshCertValidityValidator{p.claimer},
		// Require all the fields in the SSH certificate
		&sshCertDefaultValidator{},
	), nil
}
