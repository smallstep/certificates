package pki

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/smallstep/cli-utils/errs"
	"github.com/smallstep/cli-utils/fileutil"
	"github.com/smallstep/cli-utils/step"

	"github.com/smallstep/certificates/templates"
)

// getTemplates returns all the templates enabled
func (p *PKI) getTemplates() *templates.Templates {
	if !p.options.enableSSH {
		return nil
	}
	return &templates.Templates{
		SSH:  &templates.DefaultSSHTemplates,
		Data: map[string]interface{}{},
	}
}

// generateTemplates generates given templates.
func generateTemplates(t *templates.Templates) error {
	if t == nil {
		return nil
	}

	base := GetTemplatesPath()
	// Generate SSH templates
	if t.SSH != nil {
		// all ssh templates are under ssh:
		sshDir := filepath.Join(base, "ssh")
		if _, err := os.Stat(sshDir); os.IsNotExist(err) {
			if err = os.MkdirAll(sshDir, 0700); err != nil {
				return errs.FileError(err, sshDir)
			}
		}
		// Create all templates
		for _, t := range t.SSH.User {
			data, ok := templates.DefaultSSHTemplateData[t.Name]
			if !ok {
				return errors.Errorf("template %s does not exists", t.Name)
			}
			if err := fileutil.WriteFile(step.Abs(t.TemplatePath), []byte(data), 0644); err != nil {
				return err
			}
		}
		for _, t := range t.SSH.Host {
			data, ok := templates.DefaultSSHTemplateData[t.Name]
			if !ok {
				return errors.Errorf("template %s does not exists", t.Name)
			}
			if err := fileutil.WriteFile(step.Abs(t.TemplatePath), []byte(data), 0644); err != nil {
				return err
			}
		}
	}

	return nil
}
