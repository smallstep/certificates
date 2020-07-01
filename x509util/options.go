package x509util

import (
	"bytes"
	"io/ioutil"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/pkg/errors"
	"github.com/smallstep/cli/config"
)

type Options struct {
	CertBuffer *bytes.Buffer
}

func (o *Options) apply(opts []Option) (*Options, error) {
	for _, fn := range opts {
		if err := fn(o); err != nil {
			return o, err
		}
	}
	return o, nil
}

type Option func(o *Options) error

func WithTemplate(path string, data map[string]interface{}) Option {
	return func(o *Options) error {
		filename := config.StepAbs(path)
		b, err := ioutil.ReadFile(filename)
		if err != nil {
			return errors.Wrapf(err, "error reading %s", path)
		}

		tmpl, err := template.New(path).Funcs(sprig.TxtFuncMap()).Parse(string(b))
		if err != nil {
			return errors.Wrapf(err, "error parsing %s", path)
		}

		buf := new(bytes.Buffer)
		if err := tmpl.Execute(buf, data); err != nil {
			return errors.Wrapf(err, "error executing %s", path)
		}
		o.CertBuffer = buf
		return nil
	}
}
