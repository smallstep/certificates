package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"runtime"
	"time"
	"unicode"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/ca"
)

// Version is set by an LDFLAG at build time representing the git tag or commit
// for the current release
var Version = "N/A"

// BuildTime is set by an LDFLAG at build time representing the timestamp at
// the time of build
var BuildTime = "N/A"

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] <config.json>\n\n", path.Base(os.Args[0]))
	flag.PrintDefaults()
}

func printVersion() {
	version, buildTime := Version, BuildTime
	if version == "N/A" {
		version = "0000000-dev"
	}
	if buildTime == "N/A" {
		buildTime = time.Now().UTC().Format("2006-01-02 15:04 MST")
	}
	fmt.Printf("Smallstep CA/%s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Release Date: %s\n", buildTime)
}

func main() {
	var version bool
	var configFile, passFile string
	flag.StringVar(&passFile, "password-file", "", "path to file containing a password")
	flag.BoolVar(&version, "version", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()

	if version {
		printVersion()
		os.Exit(0)
	}

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	configFile = flag.Arg(0)
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
