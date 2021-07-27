package commands

import (
	"bytes"
	"encoding/json"
	"fmt"

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

## POSITIONAL ARGUMENTS

<config>
:  The ca.json that contains the step-ca configuration.

## EXAMPLES

Export the current configuration:
'''
$ step-ca export $(step path)/config/ca.json
'''`,
	})
}

func exportAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	configFile := ctx.Args().Get(0)

	config, err := config.LoadConfiguration(configFile)
	if err != nil {
		return err
	}

	auth, err := authority.New(config)
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
