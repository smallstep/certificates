package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"time"
	"unicode"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/usage"
	"github.com/urfave/cli"
)

type config struct {
	Name    string `json:"name"`
	DNS     string `json:"dns"`
	Address string `json:"address"`
}
type onboardingPayload struct {
	Fingerprint string `json:"fingerprint"`
}

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

// appHelpTemplate contains the modified template for the main app
var appHelpTemplate = `## NAME
**{{.HelpName}}** -- {{.Usage}}

## USAGE
{{if .UsageText}}{{.UsageText}}{{else}}**{{.HelpName}}**{{if .Commands}} <command>{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}_[arguments]_{{end}}{{end}}{{if .Description}}

## DESCRIPTION
{{.Description}}{{end}}{{if .VisibleCommands}}

## COMMANDS

{{range .VisibleCategories}}{{if .Name}}{{.Name}}:{{end}}
|||
|---|---|{{range .VisibleCommands}}
| **{{join .Names ", "}}** | {{.Usage}} |{{end}}
{{end}}{{if .VisibleFlags}}{{end}}

## OPTIONS

{{range $index, $option := .VisibleFlags}}{{if $index}}
{{end}}{{$option}}
{{end}}{{end}}{{if .Copyright}}{{if len .Authors}}

## AUTHOR{{with $length := len .Authors}}{{if ne 1 $length}}S{{end}}{{end}}:

{{range $index, $author := .Authors}}{{if $index}}
{{end}}{{$author}}{{end}}{{end}}{{if .Version}}{{if not .HideVersion}}

## ONLINE

This documentation is available online at https://smallstep.com/docs/certificates

## VERSION

{{.Version}}{{end}}{{end}}

## COPYRIGHT

{{.Copyright}}

## FEEDBACK ` +
	html.UnescapeString("&#"+strconv.Itoa(128525)+";") + " " +
	html.UnescapeString("&#"+strconv.Itoa(127867)+";") +
	`

The **step-ca** utility is not instrumented for usage statistics. It does not phone home.
But your feedback is extremely valuable. Any information you can provide regarding how you’re using **step-ca** helps.
Please send us a sentence or two, good or bad: **feedback@smallstep.com** or join https://gitter.im/smallstep/community.
{{end}}
`

func main() {
	// Override global framework components
	cli.VersionPrinter = func(c *cli.Context) {
		printFullVersion()
	}
	cli.AppHelpTemplate = appHelpTemplate
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
			Usage: "Displays the current version of step-ca",
			// Command prints out the current version of the tool
			Action: func(c *cli.Context) error {
				printFullVersion()
				return nil
			},
		},
		{
			Name:  "start",
			Usage: "Starts step-ca with the (optional) specified configuration",
			// TODO this should accept an optional config parameter that defaults to ~/.step/config/ca.json
			// as well as an optional token parameter for connecting to the onboarding flow
			Action: func(c *cli.Context) error {
				fmt.Printf("Connecting to onboarding guide...\n\n")

				token := c.Args().Get(0)

				res, err := http.Get("http://localhost:3002/onboarding/" + token)
				if err != nil {
					log.Fatal(err)
				}

				body, err := ioutil.ReadAll(res.Body)
				if err != nil {
					log.Fatal(err)
				}

				configuration := config{}
				err = json.Unmarshal(body, &configuration)
				if err != nil {
					log.Fatal(err)
				}

				fmt.Printf("Connected! Initializing step-ca with the following configuration...\n\n")
				fmt.Printf("Name: %s\n", configuration.Name)
				fmt.Printf("DNS: %s\n", configuration.DNS)
				fmt.Printf("Address: %s\n", configuration.Address)
				// TODO generate this password
				fmt.Printf("Provisioner Password: abcdef1234567890\n\n")

				// TODO actually initialize the CA config (automatically add an "admin" JWT provisioner)
				// and start listening
				// TODO get the root cert fingerprint to post back to the onboarding guide
				payload, err := json.Marshal(onboardingPayload{Fingerprint: "foobarbatbaz"})
				if err != nil {
					log.Fatal(err)
				}

				req, err := http.NewRequest("POST", "http://localhost:3002/onboarding/"+token, bytes.NewBuffer(payload))
				req.Header.Set("Content-Type", "application/json")
				if err != nil {
					log.Fatal(err)
				}

				client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					log.Fatal(err)
				}
				resp.Body.Close()

				fmt.Printf("Initialized!\n")
				fmt.Printf("Step CA has been started. Please return to the onboarding guide in your browser to continue.\n")
				for {
					time.Sleep(1 * time.Second)
				}
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

	app.Action = func(_ *cli.Context) error {
		// Hack to be able to run a the top action as a subcommand
		cmd := cli.Command{Name: "start", Action: startAction, Flags: app.Flags}
		set := flag.NewFlagSet(app.Name, flag.ContinueOnError)
		set.Parse(os.Args)
		ctx := cli.NewContext(app, set, nil)
		return cmd.Run(ctx)
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

func startAction(ctx *cli.Context) error {
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
		switch f.(type) {
		case cli.BoolFlag, cli.BoolTFlag:
		default:
			placeholder = "<value>"
		}
	}
	return cli.FlagNamePrefixer(fv.FieldByName("Name").String(), placeholder) + "\t" + usage
}
