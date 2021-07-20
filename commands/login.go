package commands

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/config"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
	"go.step.sm/linkedca"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const loginEndpoint = "linkedca.smallstep.com:443"
const uuidPattern = "^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$"

type linkedCAClaims struct {
	jose.Claims
	SANs []string `json:"sans"`
	SHA  string   `json:"sha"`
}

func init() {
	command.Register(cli.Command{
		Name:  "login",
		Usage: "create the certificates to authorize your Linked CA instance",
		UsageText: `**step-ca login** **--token*=<token>
		[**--linkedca**=<endpoint>] [**--root**=<file>]`,
		Action: loginAction,
		Description: `**step-ca login** ...

## POSITIONAL ARGUMENTS

<authority>
:  The authority uuid provided by the web app.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "token",
				Usage: "The <token> used to authenticate with the Linked CA in order to create the initial credentials",
			},
		},
	})
}

func loginAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	token := ctx.String("token")
	if token == "" {
		return errs.RequiredFlag(ctx, "token")
	}

	var claims linkedCAClaims
	tok, err := jose.ParseSigned(token)
	if err != nil {
		return errors.Wrap(err, "error parsing token")
	}
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return errors.Wrap(err, "error parsing token")
	}
	if len(claims.Audience) != 0 {
		return errors.Wrap(err, "error parsing token: invalid aud claim")
	}
	u, err := url.Parse(claims.Audience[0])
	if err != nil {
		return errors.Wrap(err, "error parsing token: invalid aud claim")
	}
	if claims.SHA == "" {
		return errors.Wrap(err, "error parsing token: invalid sha claim")
	}
	authority, err := getAuthority(claims.SANs)
	if err != nil {
		return err
	}

	// Get and verify root certificate
	root, err := getRootCertificate(u.Host, claims.SHA)
	if err != nil {
		return err
	}

	pool := x509.NewCertPool()
	pool.AddCert(root)

	gctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, err := grpc.DialContext(gctx, u.Host, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs: pool,
	})))
	if err != nil {
		return errors.Wrapf(err, "error connecting %s", u.Host)
	}

	// Create csr
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		return err
	}

	csr, err := x509util.CreateCertificateRequest(claims.Subject, claims.SANs, signer)
	if err != nil {
		return err
	}
	block, err := pemutil.Serialize(csr)
	if err != nil {
		return err
	}

	// Perform login and get signed certificate
	client := linkedca.NewMajordomoClient(conn)
	gctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := client.Login(gctx, &linkedca.LoginRequest{
		AuthorityId:           authority,
		Token:                 token,
		PemCertificateRequest: string(pem.EncodeToMemory(block)),
	})
	if err != nil {
		return errors.Wrap(err, "error doing login")
	}

	certData, rootData, err := parseLoginResponse(resp)
	if err != nil {
		return err
	}
	block, err = pemutil.Serialize(signer, pemutil.WithPKCS8(true))
	if err != nil {
		return err
	}
	keyData := pem.EncodeToMemory(block)

	base := filepath.Join(config.StepPath(), "linkedca")
	if err := os.MkdirAll(base, 0700); err != nil {
		return errors.Wrap(err, "error creating linkedca directory")
	}
	rootFile := filepath.Join(base, "root_ca.crt")
	certFile := filepath.Join(base, "linkedca.crt")
	keyFile := filepath.Join(base, "linkedca.key")

	if err := ioutil.WriteFile(rootFile, []byte(rootData), 0600); err != nil {
		return errors.Wrap(err, "error writing file")
	}
	if err := ioutil.WriteFile(certFile, []byte(certData), 0600); err != nil {
		return errors.Wrap(err, "error writing file")
	}
	if err := ioutil.WriteFile(keyFile, []byte(keyData), 0600); err != nil {
		return errors.Wrap(err, "error writing file")
	}

	ui.PrintSelected("Certificate", certFile)
	ui.PrintSelected("Key", keyFile)
	ui.PrintSelected("Root", rootFile)
	return nil
}

func getAuthority(sans []string) (string, error) {
	for _, s := range sans {
		if strings.HasPrefix(s, "urn:smallstep:authority:") {
			if regexp.MustCompile(uuidPattern).MatchString(s[24:]) {
				return s[24:], nil
			}
		}
	}
	return "", fmt.Errorf("error parsing token: invalid sans claim")
}

func getRootCertificate(endpoint, fingerprint string) (*x509.Certificate, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, err := grpc.DialContext(ctx, endpoint, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true,
	})))
	if err != nil {
		return nil, errors.Wrapf(err, "error connecting %s", endpoint)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := linkedca.NewMajordomoClient(conn)
	resp, err := client.GetRootCertificate(ctx, &linkedca.GetRootCertificateRequest{
		Fingerprint: fingerprint,
	})
	if err != nil {
		return nil, fmt.Errorf("error getting root certificate: %w", err)
	}

	var block *pem.Block
	b := []byte(resp.PemCertificate)
	for len(b) > 0 {
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %w", err)
		}

		// verify the sha256
		sum := sha256.Sum256(cert.Raw)
		if !strings.EqualFold(fingerprint, hex.EncodeToString(sum[:])) {
			return nil, fmt.Errorf("error verifying certificate: SHA256 fingerprint does not match")
		}

		return cert, nil
	}

	return nil, fmt.Errorf("error getting root certificate: certificate not found")
}

func parseLoginResponse(resp *linkedca.LoginResponse) ([]byte, []byte, error) {
	var block *pem.Block
	var bundle []*x509.Certificate
	b := []byte(resp.PemCertificateChain)
	for len(b) > 0 {
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, errors.New("error decoding login response: pemCertificateChain is not a certificate bundle")
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, errors.Wrap(err, "error parsing login response")
		}
		bundle = append(bundle, crt)
	}
	if len(bundle) == 0 {
		return nil, nil, errors.New("error decoding login response: pemCertificateChain should not be empty")
	}

	last := len(bundle) - 1

	certBytes := []byte(resp.PemCertificate)
	for i := 0; i < last; i++ {
		certBytes = append(certBytes, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: bundle[i].Raw,
		})...)
	}

	return certBytes, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: bundle[last].Raw,
	}), nil
}
