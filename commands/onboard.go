package commands

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/pki"
	"github.com/urfave/cli"
	"go.step.sm/cli-utils/command"
	"go.step.sm/cli-utils/errs"
	"go.step.sm/cli-utils/fileutil"
	"go.step.sm/cli-utils/ui"
	"go.step.sm/crypto/randutil"
)

// defaultOnboardingURL is the production onboarding url, to use a development
// url use:
//   export STEP_CA_ONBOARDING_URL=http://localhost:3002/onboarding/
const defaultOnboardingURL = "https://api.smallstep.com/onboarding/"

type onboardingConfiguration struct {
	Name     string `json:"name"`
	DNS      string `json:"dns"`
	Address  string `json:"address"`
	password []byte
}

type onboardingPayload struct {
	Fingerprint string `json:"fingerprint"`
}

type onboardingError struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
}

func (e onboardingError) Error() string {
	return e.Message
}

func init() {
	command.Register(cli.Command{
		Name:      "onboard",
		Usage:     "configure and run step-ca from the onboarding guide",
		UsageText: "**step-ca onboard** <token>",
		Action:    onboardAction,
		Description: `**step-ca onboard** configures step certificates using the onboarding guide.

Open https://smallstep.com/onboarding in your browser and start the CA with the
given token:
'''
$ step-ca onboard <token>
'''

## POSITIONAL ARGUMENTS

<token>
:  The token string provided by the onboarding guide.`,
	})
}

func onboardAction(ctx *cli.Context) error {
	if ctx.NArg() == 0 {
		return cli.ShowCommandHelp(ctx, "onboard")
	}
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	// Get onboarding url
	onboarding := defaultOnboardingURL
	if v := os.Getenv("STEP_CA_ONBOARDING_URL"); v != "" {
		onboarding = v
	}

	u, err := url.Parse(onboarding)
	if err != nil {
		return errors.Wrapf(err, "error parsing %s", onboarding)
	}

	ui.Println("Connecting to onboarding guide...")

	token := ctx.Args().Get(0)
	onboardingURL := u.ResolveReference(&url.URL{Path: token}).String()

	res, err := http.Get(onboardingURL)
	if err != nil {
		return errors.Wrap(err, "error connecting onboarding guide")
	}
	if res.StatusCode >= 400 {
		var msg onboardingError
		if err := readJSON(res.Body, &msg); err != nil {
			return errors.Wrap(err, "error unmarshaling response")
		}
		return errors.Wrap(msg, "error receiving onboarding guide")
	}

	var config onboardingConfiguration
	if err := readJSON(res.Body, &config); err != nil {
		return errors.Wrap(err, "error unmarshaling response")
	}

	password, err := randutil.ASCII(32)
	if err != nil {
		return err
	}
	config.password = []byte(password)

	ui.Println("Initializing step-ca with the following configuration:")
	ui.PrintSelected("Name", config.Name)
	ui.PrintSelected("DNS", config.DNS)
	ui.PrintSelected("Address", config.Address)
	ui.PrintSelected("Password", password)
	ui.Println()

	caConfig, fp, err := onboardPKI(config)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(onboardingPayload{Fingerprint: fp})
	if err != nil {
		return errors.Wrap(err, "error marshaling payload")
	}

	resp, err := http.Post(onboardingURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return errors.Wrap(err, "error connecting onboarding guide")
	}
	if resp.StatusCode >= 400 {
		var msg onboardingError
		if err := readJSON(resp.Body, &msg); err != nil {
			ui.Printf("%s {{ \"error unmarshalling response: %v\" | yellow }}\n", ui.IconWarn, err)
		} else {
			ui.Printf("%s {{ \"error posting fingerprint: %s\" | yellow }}\n", ui.IconWarn, msg.Message)
		}
	} else {
		resp.Body.Close()
	}

	ui.Println("Initialized!")
	ui.Println("Step CA is starting. Please return to the onboarding guide in your browser to continue.")

	srv, err := ca.New(caConfig, ca.WithPassword(config.password))
	if err != nil {
		fatal(err)
	}

	go ca.StopReloaderHandler(srv)
	if err = srv.Run(); err != nil && err != http.ErrServerClosed {
		fatal(err)
	}

	return nil
}

func onboardPKI(config onboardingConfiguration) (*authority.Config, string, error) {
	p, err := pki.New(apiv1.Options{
		Type:      apiv1.SoftCAS,
		IsCreator: true,
	})
	if err != nil {
		return nil, "", err
	}

	p.SetAddress(config.Address)
	p.SetDNSNames([]string{config.DNS})

	ui.Println("Generating root certificate...")
	root, err := p.GenerateRootCertificate(config.Name, config.Name, config.Name, config.password)
	if err != nil {
		return nil, "", err
	}

	ui.Println("Generating intermediate certificate...")
	err = p.GenerateIntermediateCertificate(config.Name, config.Name, config.Name, root, config.password)
	if err != nil {
		return nil, "", err
	}

	// Generate provisioner
	p.SetProvisioner("admin")
	ui.Println("Generating admin provisioner...")
	if err = p.GenerateKeyPairs(config.password); err != nil {
		return nil, "", err
	}

	// Generate and write configuration
	caConfig, err := p.GenerateConfig()
	if err != nil {
		return nil, "", err
	}

	b, err := json.MarshalIndent(caConfig, "", "   ")
	if err != nil {
		return nil, "", errors.Wrapf(err, "error marshaling %s", p.GetCAConfigPath())
	}
	if err = fileutil.WriteFile(p.GetCAConfigPath(), b, 0666); err != nil {
		return nil, "", errs.FileError(err, p.GetCAConfigPath())
	}

	return caConfig, p.GetRootFingerprint(), nil
}

func readJSON(r io.ReadCloser, v interface{}) error {
	defer r.Close()
	return json.NewDecoder(r).Decode(v)
}
