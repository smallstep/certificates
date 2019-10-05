package templates

import (
	"bytes"
	"io/ioutil"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/pkg/errors"
)

// TemplateType defines how a template will be written in disk.
type TemplateType string

const (
	// Snippet will mark a template as a part of a file.
	Snippet TemplateType = "snippet"
	// File will mark a templates as a full file.
	File TemplateType = "file"
)

// Output represents the text representation of a rendered template.
type Output struct {
	Name    string       `json:"name"`
	Type    TemplateType `json:"type"`
	Comment string       `json:"comment"`
	Path    string       `json:"path"`
	Content []byte       `json:"content"`
}

// Templates is a collection of templates and variables.
type Templates struct {
	SSH  *SSHTemplates          `json:"ssh,omitempty"`
	Data map[string]interface{} `json:"data,omitempty"`
}

// Validate returns an error if a template is not valid.
func (t *Templates) Validate() (err error) {
	if t == nil {
		return nil
	}

	// Validate members
	if err = t.SSH.Validate(); err != nil {
		return
	}

	// Do not allow "Step" and "User"
	if t.Data != nil {
		if _, ok := t.Data["Step"]; ok {
			return errors.New("templates variables cannot contain 'Step' as a property")
		}
		if _, ok := t.Data["User"]; ok {
			return errors.New("templates variables cannot contain 'User' as a property")
		}
	}
	return nil
}

// LoadAll preloads all templates in memory. It returns an error if an error is
// found parsing at least one template.
func LoadAll(t *Templates) (err error) {
	if t.SSH != nil {
		for _, tt := range t.SSH.User {
			if err = tt.Load(); err != nil {
				return err
			}
		}
		for _, tt := range t.SSH.Host {
			if err = tt.Load(); err != nil {
				return err
			}
		}
	}
	return nil
}

// SSHTemplates contains the templates defining ssh configuration files.
type SSHTemplates struct {
	User []Template `json:"user"`
	Host []Template `json:"host"`
}

// Validate returns an error if a template is not valid.
func (t *SSHTemplates) Validate() (err error) {
	if t == nil {
		return nil
	}
	for _, tt := range t.User {
		if err = tt.Validate(); err != nil {
			return
		}
	}
	for _, tt := range t.Host {
		if err = tt.Validate(); err != nil {
			return
		}
	}
	return
}

// Template represents on template file.
type Template struct {
	*template.Template
	Name         string       `json:"name"`
	Type         TemplateType `json:"type"`
	TemplatePath string       `json:"template"`
	Path         string       `json:"path"`
	Comment      string       `json:"comment"`
}

// Validate returns an error if the template is not valid.
func (t *Template) Validate() error {
	switch {
	case t == nil:
		return nil
	case t.Name == "":
		return errors.New("template name cannot be empty")
	case t.TemplatePath == "":
		return errors.New("template template cannot be empty")
	case t.Path == "":
		return errors.New("template path cannot be empty")
	}

	// Defaults
	if t.Type == "" {
		t.Type = Snippet
	}
	if t.Comment == "" {
		t.Comment = "#"
	}

	return nil
}

// Load loads the template in memory, returns an error if the parsing of the
// template fails.
func (t *Template) Load() error {
	if t.Template == nil {
		b, err := ioutil.ReadFile(t.TemplatePath)
		if err != nil {
			return errors.Wrapf(err, "error reading %s", t.TemplatePath)
		}
		tmpl, err := template.New(t.Name).Funcs(sprig.TxtFuncMap()).Parse(string(b))
		if err != nil {
			return errors.Wrapf(err, "error parsing %s", t.TemplatePath)
		}
		t.Template = tmpl
	}
	return nil
}

// Render executes the template with the given data and returns the rendered
// version.
func (t *Template) Render(data interface{}) ([]byte, error) {
	if err := t.Load(); err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := t.Execute(buf, data); err != nil {
		return nil, errors.Wrapf(err, "error executing %s", t.TemplatePath)
	}
	return buf.Bytes(), nil
}

// Output renders the template and returns a template.Output struct or an error.
func (t *Template) Output(data interface{}) (Output, error) {
	b, err := t.Render(data)
	if err != nil {
		return Output{}, err
	}

	return Output{
		Name:    t.Name,
		Type:    t.Type,
		Comment: t.Comment,
		Path:    t.Path,
		Content: b,
	}, nil
}
