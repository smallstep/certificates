package provisioner

import (
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/x509util"
)

// CertificateOptions is an interface that returns a list of options passed when
// creating a new certificate.
type CertificateOptions interface {
	Options(Options) []x509util.Option
}

type certificateOptionsFunc func(Options) []x509util.Option

func (fn certificateOptionsFunc) Options(so Options) []x509util.Option {
	return fn(so)
}

type ProvisionerOptions struct {
	Template     string          `json:"template"`
	TemplateFile string          `json:"templateFile`
	TemplateData json.RawMessage `json:"templateData"`
}

// TemplateOptions generate a CertificateOptions with the template and data
// defined in the ProvisionerOptions, the provisioner generated data, and the
// user data provided in the request.
func TemplateOptions(o *ProvisionerOptions, data x509util.TemplateData) (CertificateOptions, error) {
	if o != nil {
		if data == nil {
			data = make(x509util.TemplateData)
		}

		// Add template data if any.
		if len(o.TemplateData) > 0 {
			if err := json.Unmarshal(o.TemplateData, &data); err != nil {
				return nil, errors.Wrap(err, "error unmarshaling template data")
			}
		}

	}

	return certificateOptionsFunc(func(so Options) []x509util.Option {
		// We're not provided user data without custom templates.
		if o == nil || (o.Template == "" && o.TemplateFile == "") {
			return []x509util.Option{
				x509util.WithTemplate(x509util.DefaultLeafTemplate, data),
			}
		}

		// Add user provided data.
		if len(so.TemplateData) > 0 {
			userObject := make(map[string]interface{})
			if err := json.Unmarshal(so.TemplateData, &userObject); err != nil {
				data[x509util.UserKey] = map[string]interface{}{}
			} else {
				data[x509util.UserKey] = userObject
			}
		}
		if o.Template == "" && o.TemplateFile != "" {
			return []x509util.Option{
				x509util.WithTemplateFile(o.TemplateFile, data),
			}
		}
		return []x509util.Option{
			x509util.WithTemplateFile(o.Template, data),
		}
	}), nil
}
