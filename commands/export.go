package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"unicode"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/urfave/cli"
	"google.golang.org/protobuf/encoding/protojson"

	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
)

func init() {
	command.Register(cli.Command{
		Name:      "export",
		Usage:     "export the current configuration of step-ca",
		UsageText: "**step-ca export** <config>",
		Action:    exportAction,
		Description: `**step-ca export** exports the current configuration of step-ca.

Note that neither the PKI password nor the certificate issuer password will be
included in the export file.

## POSITIONAL ARGUMENTS

<config>
:  The ca.json that contains the step-ca configuration.

## EXAMPLES

Export the current configuration:
'''
$ step-ca export $(step path)/config/ca.json
'''`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "password-file",
				Usage: `path to the <file> containing the password to decrypt the
intermediate private key.`,
			},
			cli.StringFlag{
				Name: "issuer-password-file",
				Usage: `path to the <file> containing the password to decrypt the
certificate issuer private key used in the RA mode.`,
			},
		},
	})
}

func exportAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	configFile := ctx.Args().Get(0)
	passwordFile := ctx.String("password-file")
	issuerPasswordFile := ctx.String("issuer-password-file")

	cfg, err := config.LoadConfiguration(configFile)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	if passwordFile != "" {
		b, err := os.ReadFile(passwordFile)
		if err != nil {
			return errors.Wrapf(err, "error reading %s", passwordFile)
		}
		cfg.Password = string(bytes.TrimRightFunc(b, unicode.IsSpace))
	}
	if issuerPasswordFile != "" {
		b, err := os.ReadFile(issuerPasswordFile)
		if err != nil {
			return errors.Wrapf(err, "error reading %s", issuerPasswordFile)
		}
		if cfg.AuthorityConfig.CertificateIssuer != nil {
			cfg.AuthorityConfig.CertificateIssuer.Password = string(bytes.TrimRightFunc(b, unicode.IsSpace))
		}
	}

	auth, err := authority.New(cfg)
	if err != nil {
		return err
	}

	export, err := auth.Export()
	if err != nil {
		return err
	}

	b, err := protojson.Marshal(export)
	if err != nil {
		return errors.Wrap(err, "error marshaling export")
	}

	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "\t"); err != nil {
		return errors.Wrap(err, "error indenting export")
	}

	fmt.Println(buf.String())
	return nil
}
