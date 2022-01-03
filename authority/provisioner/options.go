package provisioner

import (
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/x509util"
)

// CertificateOptions is an interface that returns a list of options passed when
// creating a new certificate.
type CertificateOptions interface {
	Options(SignOptions) []x509util.Option
}

type certificateOptionsFunc func(SignOptions) []x509util.Option

func (fn certificateOptionsFunc) Options(so SignOptions) []x509util.Option {
	return fn(so)
}

// Options are a collection of custom options that can be added to
// each provisioner.
type Options struct {
	X509 *X509Options `json:"x509,omitempty"`
	SSH  *SSHOptions  `json:"ssh,omitempty"`
}

// GetX509Options returns the X.509 options.
func (o *Options) GetX509Options() *X509Options {
	if o == nil {
		return nil
	}
	return o.X509
}

// GetSSHOptions returns the SSH options.
func (o *Options) GetSSHOptions() *SSHOptions {
	if o == nil {
		return nil
	}
	return o.SSH
}

// X509Options contains specific options for X.509 certificates.
type X509Options struct {
	// Template contains a X.509 certificate template. It can be a JSON template
	// escaped in a string or it can be also encoded in base64.
	Template string `json:"template,omitempty"`

	// TemplateFile points to a file containing a X.509 certificate template.
	TemplateFile string `json:"templateFile,omitempty"`

	// TemplateData is a JSON object with variables that can be used in custom
	// templates.
	TemplateData json.RawMessage `json:"templateData,omitempty"`

	// AllowedNames contains the SANs the provisioner is authorized to sign
	AllowedNames *AllowedX509NameOptions `json:"allow,omitempty"`

	// DeniedNames contains the SANs the provisioner is not authorized to sign
	DeniedNames *DeniedX509NameOptions `json:"deny,omitempty"`
}

// HasTemplate returns true if a template is defined in the provisioner options.
func (o *X509Options) HasTemplate() bool {
	return o != nil && (o.Template != "" || o.TemplateFile != "")
}

// GetAllowedNameOptions returns the AllowedNameOptions, which models the
// SANs that a provisioner is authorized to sign x509 certificates for.
func (o *X509Options) GetAllowedNameOptions() *AllowedX509NameOptions {
	if o == nil {
		return nil
	}
	return o.AllowedNames
}

// GetDeniedNameOptions returns the DeniedNameOptions, which models the
// SANs that a provisioner is NOT authorized to sign x509 certificates for.
func (o *X509Options) GetDeniedNameOptions() *DeniedX509NameOptions {
	if o == nil {
		return nil
	}
	return o.DeniedNames
}

// AllowedX509NameOptions models the allowed names
type AllowedX509NameOptions struct {
	DNSDomains     []string `json:"dns,omitempty"`
	IPRanges       []string `json:"ip,omitempty"` // TODO(hs): support IPs as well as ranges
	EmailAddresses []string `json:"email,omitempty"`
	URIDomains     []string `json:"uri,omitempty"`
}

// DeniedX509NameOptions models the denied names
type DeniedX509NameOptions struct {
	DNSDomains     []string `json:"dns,omitempty"`
	IPRanges       []string `json:"ip,omitempty"` // TODO(hs): support IPs as well as ranges
	EmailAddresses []string `json:"email,omitempty"`
	URIDomains     []string `json:"uri,omitempty"`
}

// HasNames checks if the AllowedNameOptions has one or more
// names configured.
func (o *AllowedX509NameOptions) HasNames() bool {
	return len(o.DNSDomains) > 0 ||
		len(o.IPRanges) > 0 ||
		len(o.EmailAddresses) > 0 ||
		len(o.URIDomains) > 0
}

// HasNames checks if the DeniedNameOptions has one or more
// names configured.
func (o *DeniedX509NameOptions) HasNames() bool {
	return len(o.DNSDomains) > 0 ||
		len(o.IPRanges) > 0 ||
		len(o.EmailAddresses) > 0 ||
		len(o.URIDomains) > 0
}

// TemplateOptions generates a CertificateOptions with the template and data
// defined in the ProvisionerOptions, the provisioner generated data, and the
// user data provided in the request. If no template has been provided,
// x509util.DefaultLeafTemplate will be used.
func TemplateOptions(o *Options, data x509util.TemplateData) (CertificateOptions, error) {
	return CustomTemplateOptions(o, data, x509util.DefaultLeafTemplate)
}

// CustomTemplateOptions generates a CertificateOptions with the template, data
// defined in the ProvisionerOptions, the provisioner generated data and the
// user data provided in the request. If no template has been provided in the
// ProvisionerOptions, the given template will be used.
func CustomTemplateOptions(o *Options, data x509util.TemplateData, defaultTemplate string) (CertificateOptions, error) {
	opts := o.GetX509Options()
	if data == nil {
		data = x509util.NewTemplateData()
	}

	if opts != nil {
		// Add template data if any.
		if len(opts.TemplateData) > 0 && string(opts.TemplateData) != "null" {
			if err := json.Unmarshal(opts.TemplateData, &data); err != nil {
				return nil, errors.Wrap(err, "error unmarshaling template data")
			}
		}
	}

	return certificateOptionsFunc(func(so SignOptions) []x509util.Option {
		// We're not provided user data without custom templates.
		if !opts.HasTemplate() {
			return []x509util.Option{
				x509util.WithTemplate(defaultTemplate, data),
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
			return []x509util.Option{
				x509util.WithTemplateFile(opts.TemplateFile, data),
			}
		}

		// Load a template from the Template fields
		// 1. As a JSON in a string.
		template := strings.TrimSpace(opts.Template)
		if strings.HasPrefix(template, "{") {
			return []x509util.Option{
				x509util.WithTemplate(template, data),
			}
		}
		// 2. As a base64 encoded JSON.
		return []x509util.Option{
			x509util.WithTemplateBase64(template, data),
		}
	}), nil
}

// unsafeParseSigned parses the given token and returns all the claims without
// verifying the signature of the token.
func unsafeParseSigned(s string) (map[string]interface{}, error) {
	token, err := jose.ParseSigned(s)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]interface{})
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}
