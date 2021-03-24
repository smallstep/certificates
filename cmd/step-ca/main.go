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
	_ "net/http/pprof"

	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/commands"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/command/version"
	"go.step.sm/cli-utils/config"
	"go.step.sm/cli-utils/usage"

	// Enabled kms interfaces.
	_ "github.com/smallstep/certificates/kms/awskms"
	_ "github.com/smallstep/certificates/kms/cloudkms"
	_ "github.com/smallstep/certificates/kms/softkms"
	_ "github.com/smallstep/certificates/kms/sshagentkms"

	// Experimental kms interfaces.
	_ "github.com/smallstep/certificates/kms/pkcs11"
	_ "github.com/smallstep/certificates/kms/yubikey"

	// Enabled cas interfaces.
	_ "github.com/smallstep/certificates/cas/cloudcas"
	_ "github.com/smallstep/certificates/cas/softcas"
	_ "github.com/smallstep/certificates/cas/stepcas"
)

// commit and buildTime are filled in during build by the Makefile
var (
	BuildTime = "N/A"
	Version   = "N/A"
)

func init() {
	config.Set("Smallstep CA", Version, BuildTime)
	authority.GlobalVersion.Version = Version
	rand.Seed(time.Now().UnixNano())
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
	app.Version = config.Version()
	app.Usage = "an online certificate authority for secure automated certificate management"
	app.UsageText = `**step-ca** <config> [**--password-file**=<file>] [**--issuer-password-file**=<file>] [**--resolver**=<addr>] [**--help**] [**--version**]`
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
	app.Flags = append(app.Flags, commands.AppCommand.Flags...)
	app.Flags = append(app.Flags, cli.HelpFlag)
	app.Copyright = "(c) 2018-2020 Smallstep Labs, Inc."

	// All non-successful output should be written to stderr
	app.Writer = os.Stdout
	app.ErrWriter = os.Stderr
	app.Commands = command.Retrieve()

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
		os.Exit(1)
	}
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
