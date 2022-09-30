package main

import (
	"flag"
	"fmt"
	"html"
	"log"
	"math/rand"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"time"

	// Server profiler
	//nolint:gosec // profile server, if enabled runs on a different port
	_ "net/http/pprof"

	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/commands"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/command/version"
	"go.step.sm/cli-utils/step"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/cli-utils/usage"
	"go.step.sm/crypto/pemutil"

	// Enabled kms interfaces.
	_ "go.step.sm/crypto/kms/awskms"
	_ "go.step.sm/crypto/kms/azurekms"
	_ "go.step.sm/crypto/kms/cloudkms"
	_ "go.step.sm/crypto/kms/pkcs11"
	_ "go.step.sm/crypto/kms/softkms"
	_ "go.step.sm/crypto/kms/sshagentkms"
	_ "go.step.sm/crypto/kms/yubikey"

	// Enabled cas interfaces.
	_ "github.com/smallstep/certificates/cas/cloudcas"
	_ "github.com/smallstep/certificates/cas/softcas"
	_ "github.com/smallstep/certificates/cas/stepcas"
	_ "github.com/smallstep/certificates/cas/vaultcas"
)

// commit and buildTime are filled in during build by the Makefile
var (
	BuildTime = "N/A"
	Version   = "N/A"
)

func init() {
	step.Set("Smallstep CA", Version, BuildTime)
	authority.GlobalVersion.Version = Version
	rand.Seed(time.Now().UnixNano())
	// Add support for asking passwords
	pemutil.PromptPassword = func(msg string) ([]byte, error) {
		return ui.PromptPassword(msg)
	}
}

func exit(code int) {
	ui.Reset()
	os.Exit(code)
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
Please send us a sentence or two, good or bad: **feedback@smallstep.com** or https://github.com/smallstep/certificates/discussions.
{{end}}
`

func main() {
	// Initialize windows terminal
	ui.Init()

	// Override global framework components
	cli.VersionPrinter = func(c *cli.Context) {
		version.Command(c)
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
	app.Version = step.Version()
	app.Usage = "an online certificate authority for secure automated certificate management"
	app.UsageText = `**step-ca** [config] [**--context**=<name>] [**--password-file**=<file>]
[**--ssh-host-password-file**=<file>] [**--ssh-user-password-file**=<file>]
[**--issuer-password-file**=<file>] [**--resolver**=<addr>] [**--help**] [**--version**]`
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
'''
Run the Step CA for the context selected with step and a custom password file:
'''
$ step context select ssh
$ step-ca --password-file ./password.txt
'''
Run the Step CA for the context named _mybiz_ and prompt for password:
'''
$ step-ca --context=mybiz
'''
Run the Step CA for the context named _mybiz_ and an alternate ca.json file:
'''
$ step-ca --context=mybiz other-ca.json
'''
Run the Step CA for the context named _mybiz_ and read the password from a file - this is useful for
automating deployment:
'''
$ step-ca --context=mybiz --password-file ./password.txt
'''
`
	app.Flags = append(app.Flags, commands.AppCommand.Flags...)
	app.Flags = append(app.Flags, cli.HelpFlag)
	app.Copyright = fmt.Sprintf("(c) 2018-%d Smallstep Labs, Inc.", time.Now().Year())

	// All non-successful output should be written to stderr
	app.Writer = os.Stdout
	app.ErrWriter = os.Stderr
	app.Commands = command.Retrieve()

	// Start the golang debug logger if environment variable is set.
	// See https://golang.org/pkg/net/http/pprof/
	debugProfAddr := os.Getenv("STEP_PROF_ADDR")
	if debugProfAddr != "" {
		go func() {
			srv := http.Server{
				Addr:              debugProfAddr,
				ReadHeaderTimeout: 15 * time.Second,
			}
			log.Println(srv.ListenAndServe())
		}()
	}

	app.Action = func(_ *cli.Context) error {
		// Hack to be able to run a the top action as a subcommand
		set := flag.NewFlagSet(app.Name, flag.ContinueOnError)
		set.Parse(os.Args)
		ctx := cli.NewContext(app, set, nil)
		return commands.AppCommand.Run(ctx)
	}

	if err := app.Run(os.Args); err != nil {
		if os.Getenv("STEPDEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		exit(1)
	}

	exit(0)
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
	usg := fv.FieldByName("Usage").String()
	placeholder := placeholderString.FindString(usg)
	if placeholder == "" {
		switch f.(type) {
		case cli.BoolFlag, cli.BoolTFlag:
		default:
			placeholder = "<value>"
		}
	}
	return cli.FlagNamePrefixer(fv.FieldByName("Name").String(), placeholder) + "\t" + usg
}
