package templates

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/pkg/errors"
	"go.step.sm/cli-utils/fileutil"
	"go.step.sm/cli-utils/step"
)

// TemplateType defines how a template will be written in disk.
type TemplateType string

const (
	// Snippet will mark a template as a part of a file.
	Snippet TemplateType = "snippet"
	// PrependLine is a template for prepending a single line to a file. If the
	// line already exists in the file it will be removed first.
	PrependLine TemplateType = "prepend-line"
	// File will mark a templates as a full file.
	File TemplateType = "file"
	// Directory will mark a template as a directory.
	Directory TemplateType = "directory"
)

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
	if t != nil {
		if t.SSH != nil {
			for _, tt := range t.SSH.User {
				if err = tt.Load(); err != nil {
					return
				}
			}
			for _, tt := range t.SSH.Host {
				if err = tt.Load(); err != nil {
					return
				}
			}
		}
	}
	return
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

// Template represents a template file.
type Template struct {
	*template.Template
	Name         string       `json:"name"`
	Type         TemplateType `json:"type"`
	TemplatePath string       `json:"template"`
	Path         string       `json:"path"`
	Comment      string       `json:"comment"`
	RequiredData []string     `json:"requires,omitempty"`
	Content      []byte       `json:"-"`
}

// Validate returns an error if the template is not valid.
func (t *Template) Validate() error {
	switch {
	case t == nil:
		return nil
	case t.Name == "":
		return errors.New("template name cannot be empty")
	case t.Type != Snippet && t.Type != File && t.Type != Directory && t.Type != PrependLine:
		return errors.Errorf("invalid template type %s, it must be %s, %s, %s, or %s", t.Type, Snippet, PrependLine, File, Directory)
	case t.TemplatePath == "" && t.Type != Directory && len(t.Content) == 0:
		return errors.New("template template cannot be empty")
	case t.TemplatePath != "" && t.Type == Directory:
		return errors.New("template template must be empty with directory type")
	case t.TemplatePath != "" && len(t.Content) > 0:
		return errors.New("template template must be empty with content")
	case t.Path == "":
		return errors.New("template path cannot be empty")
	}

	if t.TemplatePath != "" {
		// Check for file
		st, err := os.Stat(step.Abs(t.TemplatePath))
		if err != nil {
			return errors.Wrapf(err, "error reading %s", t.TemplatePath)
		}
		if st.IsDir() {
			return errors.Errorf("error reading %s: is not a file", t.TemplatePath)
		}

		// Defaults
		if t.Comment == "" {
			t.Comment = "#"
		}
	}

	return nil
}

// ValidateRequiredData checks that the given data contains all the keys
// required.
func (t *Template) ValidateRequiredData(data map[string]string) error {
	for _, key := range t.RequiredData {
		if _, ok := data[key]; !ok {
			return errors.Errorf("required variable '%s' is missing", key)
		}
	}
	return nil
}

// Load loads the template in memory, returns an error if the parsing of the
// template fails.
func (t *Template) Load() error {
	if t.Template == nil && t.Type != Directory {
		switch {
		case t.TemplatePath != "":
			filename := step.Abs(t.TemplatePath)
			b, err := os.ReadFile(filename)
			if err != nil {
				return errors.Wrapf(err, "error reading %s", filename)
			}
			return t.LoadBytes(b)
		default:
			return t.LoadBytes(t.Content)
		}
	}
	return nil
}

// LoadBytes loads the template in memory, returns an error if the parsing of
// the template fails.
func (t *Template) LoadBytes(b []byte) error {
	t.backfill(b)
	tmpl, err := template.New(t.Name).Funcs(StepFuncMap()).Parse(string(b))
	if err != nil {
		return errors.Wrapf(err, "error parsing template %s", t.Name)
	}
	t.Template = tmpl
	return nil
}

// Render executes the template with the given data and returns the rendered
// version.
func (t *Template) Render(data interface{}) ([]byte, error) {
	if t.Type == Directory {
		return nil, nil
	}

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
		Path:    t.Path,
		Comment: t.Comment,
		Content: b,
	}, nil
}

// backfill updates old templates with the required data.
func (t *Template) backfill(b []byte) {
	if strings.EqualFold(t.Name, "sshd_config.tpl") && len(t.RequiredData) == 0 {
		a := bytes.TrimSpace(b)
		b := bytes.TrimSpace([]byte(DefaultSSHTemplateData[t.Name]))
		if bytes.Equal(a, b) {
			t.RequiredData = []string{"Certificate", "Key"}
		}
	}
}

// Output represents the text representation of a rendered template.
type Output struct {
	Name    string       `json:"name"`
	Type    TemplateType `json:"type"`
	Path    string       `json:"path"`
	Comment string       `json:"comment"`
	Content []byte       `json:"content"`
}

// Write writes the Output to the filesystem as a directory, file or snippet.
func (o *Output) Write() error {
	// Replace ${STEPPATH} with the base step path.
	o.Path = strings.ReplaceAll(o.Path, "${STEPPATH}", step.BasePath())

	path := step.Abs(o.Path)
	if o.Type == Directory {
		return mkdir(path, 0700)
	}

	dir := filepath.Dir(path)
	if err := mkdir(dir, 0700); err != nil {
		return err
	}

	switch o.Type {
	case File:
		return fileutil.WriteFile(path, o.Content, 0600)
	case Snippet:
		return fileutil.WriteSnippet(path, o.Content, 0600)
	case PrependLine:
		return fileutil.PrependLine(path, o.Content, 0600)
	default:
		// Default to using a Snippet type if the type is not known.
		return fileutil.WriteSnippet(path, o.Content, 0600)
	}
}

func mkdir(path string, perm os.FileMode) error {
	if err := os.MkdirAll(path, perm); err != nil {
		return errors.Wrapf(err, "error creating %s", path)
	}
	return nil
}

// StepFuncMap returns sprig.TxtFuncMap but removing the "env" and "expandenv"
// functions to avoid any leak of information.
func StepFuncMap() template.FuncMap {
	m := sprig.TxtFuncMap()
	delete(m, "env")
	delete(m, "expandenv")
	return m
}
