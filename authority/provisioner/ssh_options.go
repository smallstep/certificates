package provisioner

import (
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
	"go.step.sm/crypto/sshutil"
)

// SSHCertificateOptions is an interface that returns a list of options passed when
// creating a new certificate.
type SSHCertificateOptions interface {
	Options(SignSSHOptions) []sshutil.Option
}

type sshCertificateOptionsFunc func(SignSSHOptions) []sshutil.Option

func (fn sshCertificateOptionsFunc) Options(so SignSSHOptions) []sshutil.Option {
	return fn(so)
}

// SSHOptions are a collection of custom options that can be added to each
// provisioner.
type SSHOptions struct {
	// Template contains an SSH certificate template. It can be a JSON template
	// escaped in a string or it can be also encoded in base64.
	Template string `json:"template,omitempty"`

	// TemplateFile points to a file containing a SSH certificate template.
	TemplateFile string `json:"templateFile,omitempty"`

	// TemplateData is a JSON object with variables that can be used in custom
	// templates.
	TemplateData json.RawMessage `json:"templateData,omitempty"`

	// User contains SSH user certificate options.
	User *SSHUserCertificateOptions `json:"user,omitempty"`

	// Host contains SSH host certificate options.
	Host *SSHHostCertificateOptions `json:"host,omitempty"`
}

// SSHUserCertificateOptions is a collection of SSH user certificate options.
type SSHUserCertificateOptions struct {
	// AllowedNames contains the names the provisioner is authorized to sign
	AllowedNames *SSHNameOptions `json:"allow,omitempty"`

	// DeniedNames contains the names the provisioner is not authorized to sign
	DeniedNames *SSHNameOptions `json:"deny,omitempty"`
}

// SSHHostCertificateOptions is a collection of SSH host certificate options.
// It's an alias of SSHUserCertificateOptions, as the options are the same
// for both types of certificates.
type SSHHostCertificateOptions SSHUserCertificateOptions

// SSHNameOptions models the SSH name policy configuration.
type SSHNameOptions struct {
	DNSDomains     []string `json:"dns,omitempty"`
	IPRanges       []string `json:"ip,omitempty"`
	EmailAddresses []string `json:"email,omitempty"`
	Principals     []string `json:"principal,omitempty"`
}

// HasTemplate returns true if a template is defined in the provisioner options.
func (o *SSHOptions) HasTemplate() bool {
	return o != nil && (o.Template != "" || o.TemplateFile != "")
}

// GetAllowedNameOptions returns the AllowedSSHNameOptions, which models the
// names that a provisioner is authorized to sign SSH certificates for.
func (o *SSHUserCertificateOptions) GetAllowedNameOptions() *SSHNameOptions {
	if o == nil {
		return nil
	}
	return o.AllowedNames
}

// GetDeniedNameOptions returns the DeniedSSHNameOptions, which models the
// names that a provisioner is NOT authorized to sign SSH certificates for.
func (o *SSHUserCertificateOptions) GetDeniedNameOptions() *SSHNameOptions {
	if o == nil {
		return nil
	}
	return o.DeniedNames
}

// HasNames checks if the SSHNameOptions has one or more
// names configured.
func (o *SSHNameOptions) HasNames() bool {
	return len(o.DNSDomains) > 0 ||
		len(o.EmailAddresses) > 0 ||
		len(o.Principals) > 0
}

// TemplateSSHOptions generates a SSHCertificateOptions with the template and
// data defined in the ProvisionerOptions, the provisioner generated data, and
// the user data provided in the request. If no template has been provided,
// x509util.DefaultLeafTemplate will be used.
func TemplateSSHOptions(o *Options, data sshutil.TemplateData) (SSHCertificateOptions, error) {
	return CustomSSHTemplateOptions(o, data, sshutil.DefaultTemplate)
}

// CustomSSHTemplateOptions generates a CertificateOptions with the template, data
// defined in the ProvisionerOptions, the provisioner generated data and the
// user data provided in the request. If no template has been provided in the
// ProvisionerOptions, the given template will be used.
func CustomSSHTemplateOptions(o *Options, data sshutil.TemplateData, defaultTemplate string) (SSHCertificateOptions, error) {
	opts := o.GetSSHOptions()
	if data == nil {
		data = sshutil.NewTemplateData()
	}

	if opts != nil {
		// Add template data if any.
		if len(opts.TemplateData) > 0 && string(opts.TemplateData) != "null" {
			if err := json.Unmarshal(opts.TemplateData, &data); err != nil {
				return nil, errors.Wrap(err, "error unmarshaling template data")
			}
		}
	}

	return sshCertificateOptionsFunc(func(so SignSSHOptions) []sshutil.Option {
		// We're not provided user data without custom templates.
		if !opts.HasTemplate() {
			return []sshutil.Option{
				sshutil.WithTemplate(defaultTemplate, data),
			}
		}

		// Add user provided data.
		if len(so.TemplateData) > 0 {
			userObject := make(map[string]interface{})
			if err := json.Unmarshal(so.TemplateData, &userObject); err != nil {
				data.SetUserData(map[string]interface{}{})
			} else {
				data.SetUserData(userObject)
			}
		}

		// Load a template from a file if Template is not defined.
		if opts.Template == "" && opts.TemplateFile != "" {
			return []sshutil.Option{
				sshutil.WithTemplateFile(opts.TemplateFile, data),
			}
		}

		// Load a template from the Template fields
		// 1. As a JSON in a string.
		template := strings.TrimSpace(opts.Template)
		if strings.HasPrefix(template, "{") {
			return []sshutil.Option{
				sshutil.WithTemplate(template, data),
			}
		}
		// 2. As a base64 encoded JSON.
		return []sshutil.Option{
			sshutil.WithTemplateBase64(template, data),
		}
	}), nil
}
