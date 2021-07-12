package commands

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
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
}

func init() {
	command.Register(cli.Command{
		Name:  "login",
		Usage: "create the certificates to authorize your Linked CA instance",
		UsageText: `**step-ca login** <authority> **--token*=<token>
		[**--linkedca**=<endpoint>] [**--root**=<file>]`,
		Action: loginAction,
		Description: `**step-ca login** ...

## POSITIONAL ARGUMENTS

<authority>
:  The authority uuid provided by the web app.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "token",
				Usage: "The one-time <token> used to authenticate with the Linked CA in order to create the initial credentials",
			},
			cli.StringFlag{
				Name:  "linkedca",
				Usage: "The linkedca <endpoint> to connect to.",
				Value: loginEndpoint,
			},
			cli.StringFlag{
				Name:  "root",
				Usage: "The root certificate <file> used to authenticate with the linkedca endpoint.",
			},
		},
	})
}

func loginAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	authority := args[0]
	token := ctx.String("token")
	endpoint := ctx.String("linkedca")
	rx := regexp.MustCompile(uuidPattern)
	switch {
	case !rx.MatchString(authority):
		return errors.Errorf("positional argument %s is not a valid uuid", authority)
	case token == "":
		return errs.RequiredFlag(ctx, "token")
	case endpoint == "":
		return errs.RequiredFlag(ctx, "linkedca")
	}

	var claims linkedCAClaims
	tok, err := jose.ParseSigned(token)
	if err != nil {
		return errors.Wrap(err, "error parsing token")
	}
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return errors.Wrap(err, "error parsing payload")
	}

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

	var options []grpc.DialOption
	if root := ctx.String("root"); root != "" {
		b, err := ioutil.ReadFile(root)
		if err != nil {
			return errors.Wrap(err, "error reading file")
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return errors.Errorf("error reading %s: no certificates were found", root)
		}

		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs: pool,
		})))
	} else {
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	gctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(gctx, endpoint, options...)
	if err != nil {
		return errors.Wrapf(err, "error connecting %s", endpoint)
	}

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
