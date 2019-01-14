package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"time"
	"unicode"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/usage"
	"github.com/urfave/cli"
)

// commit and buildTime are filled in during build by the Makefile
var (
	BuildTime = "N/A"
	Version   = "N/A"
)

// Version returns the current version of the binary.
func version() string {
	out := Version
	if out == "N/A" {
		out = "0000000-dev"
	}
	return fmt.Sprintf("Smallstep CA/%s (%s/%s)",
		out, runtime.GOOS, runtime.GOARCH)
}

// ReleaseDate returns the time of when the binary was built.
func releaseDate() string {
	out := BuildTime
	if out == "N/A" {
		out = time.Now().UTC().Format("2006-01-02 15:04 MST")
	}

	return out
}

// Print version and release date.
func printFullVersion() {
	fmt.Printf("%s\n", version())
	fmt.Printf("Release Date: %s\n", releaseDate())
}

func main() {
	// Override global framework components
	cli.VersionPrinter = func(c *cli.Context) {
		printFullVersion()
	}
	cli.AppHelpTemplate = usage.AppHelpTemplate
	cli.SubcommandHelpTemplate = usage.SubcommandHelpTemplate
	cli.CommandHelpTemplate = usage.CommandHelpTemplate
	cli.HelpPrinter = usage.HelpPrinter
	cli.FlagNamePrefixer = usage.FlagNamePrefixer
	cli.FlagStringer = stringifyFlag
	// Configure cli app
	app := cli.NewApp()
	app.Name = "step-ca"
	app.HelpName = "step-ca"
	app.Version = version()
	app.Usage = "an online certificate authority for secure automated certificate management"
	app.UsageText = `**step-ca** <config> [**--password-file**=<file>] [**--version**]`
	app.Description = `**step-ca** runs the Step Online Certificate Authority
(Step CA) using the given configuration.

See the README.md for more detailed configuration documentation.

## POSITIONAL ARGUMENTS

<config>
: File that configures the operation of the Step CA; this file is generated
when you initialize the Step CA using 'step ca init'

## EXIT CODES

This command will run indefinitely on success and return \>0 if any error occurs.

## EXAMPLES

These examples assume that you have already initialized your PKI by running
'step ca init'. If you have not completed this step please see the 'Getting Started'
section of the README.

Run the Step CA and prompt for password:
'''
$ step-ca $STEPPATH/config/ca.json
'''

Run the Step CA and read the password from a file - this is useful for
automating deployment:
'''
$ step-ca $STEPPATH/config/ca.json --password-file ./password.txt
'''`
	app.Flags = append(app.Flags, []cli.Flag{
		cli.StringFlag{
			Name: "password-file",
			Usage: `path to the <file> containing the password to decrypt the
intermediate private key.`,
		},
	}...)
	app.Copyright = "(c) 2019 Smallstep Labs, Inc."

	// All non-successful output should be written to stderr
	app.Writer = os.Stdout
	app.ErrWriter = os.Stderr
	app.Commands = []cli.Command{
		{
			Name:  "version",
			Usage: "Displays the current version of the cli",
			// Command prints out the current version of the tool
			Action: func(c *cli.Context) error {
				printFullVersion()
				return nil
			},
		},
		{
			Name:      "help",
			Aliases:   []string{"h"},
			Usage:     "displays help for the specified command or command group",
			ArgsUsage: "",
			Action:    usage.HelpCommandAction,
		},
	}

	// Start the golang debug logger if environment variable is set.
	// See https://golang.org/pkg/net/http/pprof/
	debugProfAddr := os.Getenv("STEP_PROF_ADDR")
	if debugProfAddr != "" {
		go func() {
			log.Println(http.ListenAndServe(debugProfAddr, nil))
		}()
	}

	app.Action = func(ctx *cli.Context) error {
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

	if err := app.Run(os.Args); err != nil {
		if os.Getenv("STEPDEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
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

func flagValue(f cli.Flag) reflect.Value {
	fv := reflect.ValueOf(f)
	for fv.Kind() == reflect.Ptr {
		fv = reflect.Indirect(fv)
	}
	return fv
}

var placeholderString = regexp.MustCompile(`<.*?>`)

func stringifyFlag(f cli.Flag) string {
	fv := flagValue(f)
	usage := fv.FieldByName("Usage").String()
	placeholder := placeholderString.FindString(usage)
	if placeholder == "" {
		placeholder = "<value>"
	}
	return cli.FlagNamePrefixer(fv.FieldByName("Name").String(), placeholder) + "\t" + usage
}
