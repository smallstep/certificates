package sshutil

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/pkg/errors"
	"github.com/smallstep/cli/config"
	"golang.org/x/crypto/ssh"
)

func getFuncMap(failMessage *string) template.FuncMap {
	m := sprig.TxtFuncMap()
	m["fail"] = func(msg string) (string, error) {
		*failMessage = msg
		return "", errors.New(msg)
	}
	return m
}

// Options are the options that can be passed to NewCertificate.
type Options struct {
	CertBuffer *bytes.Buffer
}

func (o *Options) apply(key ssh.PublicKey, opts []Option) (*Options, error) {
	for _, fn := range opts {
		if err := fn(key, o); err != nil {
			return o, err
		}
	}
	return o, nil
}

// Option is the type used as a variadic argument in NewCertificate.
type Option func(key ssh.PublicKey, o *Options) error

// WithTemplate is an options that executes the given template text with the
// given data.
func WithTemplate(text string, data TemplateData) Option {
	return func(key ssh.PublicKey, o *Options) error {
		terr := new(TemplateError)
		funcMap := getFuncMap(&terr.Message)

		tmpl, err := template.New("template").Funcs(funcMap).Parse(text)
		if err != nil {
			return errors.Wrapf(err, "error parsing template")
		}

		buf := new(bytes.Buffer)
		data.SetPublicKey(key)
		if err := tmpl.Execute(buf, data); err != nil {
			if terr.Message != "" {
				return terr
			}
			return errors.Wrapf(err, "error executing template")
		}
		o.CertBuffer = buf
		return nil
	}
}

// WithTemplateBase64 is an options that executes the given template base64
// string with the given data.
func WithTemplateBase64(s string, data TemplateData) Option {
	return func(key ssh.PublicKey, o *Options) error {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return errors.Wrap(err, "error decoding template")
		}
		fn := WithTemplate(string(b), data)
		return fn(key, o)
	}
}

// WithTemplateFile is an options that reads the template file and executes it
// with the given data.
func WithTemplateFile(path string, data TemplateData) Option {
	return func(key ssh.PublicKey, o *Options) error {
		filename := config.StepAbs(path)
		b, err := ioutil.ReadFile(filename)
		if err != nil {
			return errors.Wrapf(err, "error reading %s", path)
		}
		fn := WithTemplate(string(b), data)
		return fn(key, o)
	}
}
