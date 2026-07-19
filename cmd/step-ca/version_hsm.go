//go:build cgo

package main

import (
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/cli-utils/step"
)

func init() {
	Version += "+hsm"
	step.Set("Smallstep CA", Version, BuildTime)
	authority.GlobalVersion.Version = Version
}
