package commands

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"unicode"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/ca"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/errs"
)

// AppCommand is the action used as the top action.
var AppCommand = cli.Command{
	Name:   "start",
	Action: appAction,
	UsageText: `**step-ca** <config>
[**--password-file**=<file>] [**--issuer-password-file**=<file>] [**--resolver**=<addr>]`,
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
		cli.StringFlag{
			Name:  "resolver",
			Usage: "address of a DNS resolver to be used instead of the default.",
		},
	},
}

// AppAction is the action used when the top command runs.
func appAction(ctx *cli.Context) error {
	passFile := ctx.String("password-file")
	issuerPassFile := ctx.String("issuer-password-file")
	resolver := ctx.String("resolver")

	// If zero cmd line args show help, if >1 cmd line args show error.
	if ctx.NArg() == 0 {
		return cli.ShowAppHelp(ctx)
	}
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	configFile := ctx.Args().Get(0)
	config, err := authority.LoadConfiguration(configFile)
	if err != nil {
		fatal(err)
	}

	var password []byte
	if passFile != "" {
		if password, err = ioutil.ReadFile(passFile); err != nil {
			fatal(errors.Wrapf(err, "error reading %s", passFile))
		}
		password = bytes.TrimRightFunc(password, unicode.IsSpace)
	}

	var issuerPassword []byte
	if issuerPassFile != "" {
		if issuerPassword, err = ioutil.ReadFile(issuerPassFile); err != nil {
			fatal(errors.Wrapf(err, "error reading %s", issuerPassFile))
		}
		issuerPassword = bytes.TrimRightFunc(issuerPassword, unicode.IsSpace)
	}

	// replace resolver if requested
	if resolver != "" {
		net.DefaultResolver.PreferGo = true
		net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, resolver)
		}
	}

	srv, err := ca.New(config,
		ca.WithConfigFile(configFile),
		ca.WithPassword(password),
		ca.WithIssuerPassword(issuerPassword))
	if err != nil {
		fatal(err)
	}

	go ca.StopReloaderHandler(srv)
	if err = srv.Run(); err != nil && err != http.ErrServerClosed {
		fatal(err)
	}
	return nil
}

// fatal writes the passed error on the standard error and exits with the exit
// code 1. If the environment variable STEPDEBUG is set to 1 it shows the
// stack trace of the error.
func fatal(err error) {
	if os.Getenv("STEPDEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(2)
}
