package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/crypto/randutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

type onboardingConfiguration struct {
	Name     string `json:"name"`
	DNS      string `json:"dns"`
	Address  string `json:"address"`
	password []byte
}

type onboardingPayload struct {
	Fingerprint string `json:"fingerprint"`
}

func init() {
	command.Register(cli.Command{
		Name:      "onboard",
		Usage:     "Configure and run step-ca from the onboarding guide",
		UsageText: "**step-ca onboard** <token>",
		Action:    onboardAction,
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
	onboarding := "http://localhost:3002/onboarding/"
	if v := os.Getenv("STEP_CA_ONBOARDING_URL"); v != "" {
		onboarding = v
	}

	u, err := url.Parse(onboarding)
	if err != nil {
		return errors.Wrapf(err, "error parsing %s", onboarding)
	}

	fmt.Printf("Connecting to onboarding guide...\n\n")

	token := ctx.Args().Get(0)
	onboardingURL := u.ResolveReference(&url.URL{Path: token}).String()

	res, err := http.Get(onboardingURL)
	if err != nil {
		return errors.Wrap(err, "error connecting onboarding guide")
	}
	if res.StatusCode >= 400 {
		res.Body.Close()
		return errors.Errorf("error connecting onboarding guide: %s", res.Status)
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

	fmt.Printf("Connected! Initializing step-ca with the following configuration...\n\n")
	fmt.Printf("Name: %s\n", config.Name)
	fmt.Printf("DNS: %s\n", config.DNS)
	fmt.Printf("Address: %s\n", config.Address)
	fmt.Printf("Password: %s\n\n", password)

	caConfig, fp, err := onboardPKI(config)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(onboardingPayload{Fingerprint: fp})
	if err != nil {
		return errors.Wrap(err, "error marshalling payload")
	}

	resp, err := http.Post(onboardingURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return errors.Wrap(err, "error connecting onboarding guide")
	}
	resp.Body.Close()

	fmt.Printf("Initialized!\n")
	fmt.Printf("Step CA is starting. Please return to the onboarding guide in your browser to continue.\n")

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
	p, err := pki.New(pki.GetPublicPath(), pki.GetSecretsPath(), pki.GetConfigPath())
	if err != nil {
		return nil, "", err
	}

	p.SetAddress(config.Address)
	p.SetDNSNames([]string{config.DNS})

	rootCrt, rootKey, err := p.GenerateRootCertificate(config.Name+" Root CA", config.password)
	if err != nil {
		return nil, "", err
	}

	err = p.GenerateIntermediateCertificate(config.Name+" Intermediate CA", rootCrt, rootKey, config.password)
	if err != nil {
		return nil, "", err
	}

	// Generate provisioner
	p.SetProvisioner("admin")
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
	if err = utils.WriteFile(p.GetCAConfigPath(), b, 0666); err != nil {
		return nil, "", errs.FileError(err, p.GetCAConfigPath())
	}

	return caConfig, p.GetRootFingerprint(), nil
}

func readJSON(r io.ReadCloser, v interface{}) error {
	defer r.Close()
	return json.NewDecoder(r).Decode(v)
}
