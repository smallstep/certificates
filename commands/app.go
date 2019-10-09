package commands

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"unicode"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

// AppCommand is the action used as the top action.
var AppCommand = cli.Command{
	Name:   "start",
	Action: appAction,
	UsageText: `**step-ca** <config>
	[**--password-file**=<file>]`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name: "password-file",
			Usage: `path to the <file> containing the password to decrypt the
intermediate private key.`,
		},
	},
}

// AppAction is the action used when the top command runs.
func appAction(ctx *cli.Context) error {
	passFile := ctx.String("password-file")

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

	srv, err := ca.New(config, ca.WithConfigFile(configFile), ca.WithPassword(password))
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
