package templates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/smallstep/assert"
	"golang.org/x/crypto/ssh"
)

func TestTemplates_Validate(t *testing.T) {
	sshTemplates := &SSHTemplates{
		User: []Template{
			{Name: "known_host.tpl", Type: File, TemplatePath: "../authority/testdata/templates/known_hosts.tpl", Path: "ssh/known_host", Comment: "#"},
		},
		Host: []Template{
			{Name: "ca.tpl", Type: File, TemplatePath: "../authority/testdata/templates/ca.tpl", Path: "/etc/ssh/ca.pub", Comment: "#"},
		},
	}
	type fields struct {
		SSH  *SSHTemplates
		Data map[string]interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{sshTemplates, nil}, false},
		{"okWithData", fields{sshTemplates, map[string]interface{}{"Foo": "Bar"}}, false},
		{"badSSH", fields{&SSHTemplates{User: []Template{{}}}, nil}, true},
		{"badDataUser", fields{sshTemplates, map[string]interface{}{"User": "Bar"}}, true},
		{"badDataStep", fields{sshTemplates, map[string]interface{}{"Step": "Bar"}}, true},
	}
	var nilValue *Templates
	assert.NoError(t, nilValue.Validate())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &Templates{
				SSH:  tt.fields.SSH,
				Data: tt.fields.Data,
			}
			if err := tmpl.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Templates.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSSHTemplates_Validate(t *testing.T) {
	user := []Template{
		{Name: "include.tpl", Type: Snippet, TemplatePath: "../authority/testdata/templates/include.tpl", Path: "~/.ssh/config", Comment: "#"},
	}
	host := []Template{
		{Name: "ca.tpl", Type: File, TemplatePath: "../authority/testdata/templates/ca.tpl", Path: "/etc/ssh/ca.pub", Comment: "#"},
	}
	content := []Template{
		{Name: "test.tpl", Type: File, Content: []byte("some content"), Path: "/test.pub", Comment: "#"},
	}
	badContent := []Template{
		{Name: "ca.tpl", Type: File, TemplatePath: "../authority/testdata/templates/ca.tpl", Content: []byte("some content"), Path: "/etc/ssh/ca.pub", Comment: "#"},
	}

	type fields struct {
		User []Template
		Host []Template
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{user, host}, false},
		{"user", fields{user, nil}, false},
		{"host", fields{nil, host}, false},
		{"content", fields{content, nil}, false},
		{"badUser", fields{[]Template{{}}, nil}, true},
		{"badHost", fields{nil, []Template{{}}}, true},
		{"badContent", fields{badContent, nil}, true},
	}
	var nilValue *SSHTemplates
	assert.NoError(t, nilValue.Validate())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &SSHTemplates{
				User: tt.fields.User,
				Host: tt.fields.Host,
			}
			if err := tmpl.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("SSHTemplates.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTemplate_Validate(t *testing.T) {
	okPath := "~/.ssh/config"
	okTmplPath := "../authority/testdata/templates/include.tpl"

	type fields struct {
		Name         string
		Type         TemplateType
		TemplatePath string
		Path         string
		Comment      string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"okSnippet", fields{"include.tpl", Snippet, okTmplPath, okPath, "#"}, false},
		{"okFile", fields{"file.tpl", File, okTmplPath, okPath, "#"}, false},
		{"okDirectory", fields{"dir.tpl", Directory, "", "/tmp/dir", "#"}, false},
		{"badName", fields{"", Snippet, okTmplPath, okPath, "#"}, true},
		{"badType", fields{"include.tpl", "", okTmplPath, okPath, "#"}, true},
		{"badType", fields{"include.tpl", "foo", okTmplPath, okPath, "#"}, true},
		{"badTemplatePath", fields{"include.tpl", Snippet, "", okPath, "#"}, true},
		{"badTemplatePath", fields{"include.tpl", File, "", okPath, "#"}, true},
		{"badTemplatePath", fields{"include.tpl", Directory, okTmplPath, okPath, "#"}, true},
		{"badPath", fields{"include.tpl", Snippet, okTmplPath, "", "#"}, true},
		{"missingTemplate", fields{"include.tpl", Snippet, "./testdata/include.tpl", okTmplPath, "#"}, true},
		{"directoryTemplate", fields{"include.tpl", File, "../authority/testdata", okTmplPath, "#"}, true},
	}
	var nilValue *Template
	assert.NoError(t, nilValue.Validate())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &Template{
				Name:         tt.fields.Name,
				Type:         tt.fields.Type,
				TemplatePath: tt.fields.TemplatePath,
				Path:         tt.fields.Path,
				Comment:      tt.fields.Comment,
			}
			if err := tmpl.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Template.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadAll(t *testing.T) {
	tmpl := &Templates{
		SSH: &SSHTemplates{
			User: []Template{
				{Name: "include.tpl", Type: Snippet, TemplatePath: "../authority/testdata/templates/include.tpl", Path: "~/.ssh/config", Comment: "#"},
			},
			Host: []Template{
				{Name: "ca.tpl", Type: File, TemplatePath: "../authority/testdata/templates/ca.tpl", Path: "/etc/ssh/ca.pub", Comment: "#"},
			},
		},
	}

	type args struct {
		t *Templates
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{tmpl}, false},
		{"empty", args{&Templates{}}, false},
		{"nil", args{nil}, false},
		{"badUser", args{&Templates{SSH: &SSHTemplates{User: []Template{{TemplatePath: "missing"}}}}}, true},
		{"badHost", args{&Templates{SSH: &SSHTemplates{Host: []Template{{TemplatePath: "missing"}}}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := LoadAll(tt.args.t); (err != nil) != tt.wantErr {
				t.Errorf("LoadAll() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTemplate_Load(t *testing.T) {
	type fields struct {
		Name         string
		Type         TemplateType
		TemplatePath string
		Path         string
		Comment      string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{"include.tpl", Snippet, "../authority/testdata/templates/include.tpl", "~/.ssh/config", "#"}, false},
		{"ok backfill", fields{"sshd_config.tpl", Snippet, "../authority/testdata/templates/sshd_config.tpl", "/etc/ssh/sshd_config", "#"}, false},
		{"error", fields{"error.tpl", Snippet, "../authority/testdata/templates/error.tpl", "/tmp/error", "#"}, true},
		{"missing", fields{"include.tpl", Snippet, "./testdata/include.tpl", "~/.ssh/config", "#"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &Template{
				Name:         tt.fields.Name,
				Type:         tt.fields.Type,
				TemplatePath: tt.fields.TemplatePath,
				Path:         tt.fields.Path,
				Comment:      tt.fields.Comment,
			}
			if err := tmpl.Load(); (err != nil) != tt.wantErr {
				t.Errorf("Template.Load() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTemplate_Render(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	user, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)
	userB64 := base64.StdEncoding.EncodeToString(user.Marshal())

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	host, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)
	hostB64 := base64.StdEncoding.EncodeToString(host.Marshal())

	data := map[string]interface{}{
		"Step": &Step{
			SSH: StepSSH{
				UserKey: user,
				HostKey: host,
			},
		},
		"User": map[string]string{
			"StepPath": "/tmp/.step",
			"User":     "john",
			"GOOS":     "linux",
		},
	}

	type fields struct {
		Name         string
		Type         TemplateType
		TemplatePath string
		Path         string
		Comment      string
	}
	type args struct {
		data interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"snippet", fields{"include.tpl", Snippet, "../authority/testdata/templates/include.tpl", "~/.ssh/config", "#"}, args{data}, []byte("Host *\n\tInclude /tmp/.step/ssh/config"), false},
		{"file", fields{"known_hosts.tpl", File, "../authority/testdata/templates/known_hosts.tpl", "ssh/known_hosts", "#"}, args{data}, []byte(fmt.Sprintf("@cert-authority * %s %s", host.Type(), hostB64)), false},
		{"file", fields{"ca.tpl", File, "../authority/testdata/templates/ca.tpl", "/etc/ssh/ca.pub", "#"}, args{data}, []byte(fmt.Sprintf("%s %s", user.Type(), userB64)), false},
		{"directory", fields{"dir.tpl", Directory, "", "/tmp/dir", ""}, args{data}, nil, false},
		{"error", fields{"error.tpl", File, "../authority/testdata/templates/error.tpl", "/tmp/error", "#"}, args{data}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &Template{
				Name:         tt.fields.Name,
				Type:         tt.fields.Type,
				TemplatePath: tt.fields.TemplatePath,
				Path:         tt.fields.Path,
				Comment:      tt.fields.Comment,
			}
			got, err := tmpl.Render(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Template.Render() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Template.Render() = %v, want %v", string(got), string(tt.want))
			}
		})
	}
}

func TestTemplate_Output(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	user, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)
	userB64 := base64.StdEncoding.EncodeToString(user.Marshal())

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.FatalError(t, err)
	host, err := ssh.NewPublicKey(key.Public())
	assert.FatalError(t, err)
	hostB64 := base64.StdEncoding.EncodeToString(host.Marshal())

	data := map[string]interface{}{
		"Step": &Step{
			SSH: StepSSH{
				UserKey: user,
				HostKey: host,
			},
		},
		"User": map[string]string{
			"StepPath": "/tmp/.step",
		},
	}

	type fields struct {
		Name         string
		Type         TemplateType
		TemplatePath string
		Path         string
		Comment      string
	}
	type args struct {
		data interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"snippet", fields{"include.tpl", Snippet, "../authority/testdata/templates/include.tpl", "~/.ssh/config", "#"}, args{data}, []byte("Host *\n\tInclude /tmp/.step/ssh/config"), false},
		{"file", fields{"known_hosts.tpl", File, "../authority/testdata/templates/known_hosts.tpl", "ssh/known_hosts", "#"}, args{data}, []byte(fmt.Sprintf("@cert-authority * %s %s", host.Type(), hostB64)), false},
		{"file", fields{"ca.tpl", File, "../authority/testdata/templates/ca.tpl", "/etc/ssh/ca.pub", "#"}, args{data}, []byte(fmt.Sprintf("%s %s", user.Type(), userB64)), false},
		{"directory", fields{"dir.tpl", Directory, "", "/tmp/dir", ""}, args{data}, nil, false},
		{"error", fields{"error.tpl", File, "../authority/testdata/templates/error.tpl", "/tmp/error", "#"}, args{data}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var want Output
			if !tt.wantErr {
				want = Output{
					Name:    tt.fields.Name,
					Type:    tt.fields.Type,
					Path:    tt.fields.Path,
					Comment: tt.fields.Comment,
					Content: tt.want,
				}
			}

			tmpl := &Template{
				Name:         tt.fields.Name,
				Type:         tt.fields.Type,
				TemplatePath: tt.fields.TemplatePath,
				Path:         tt.fields.Path,
				Comment:      tt.fields.Comment,
			}
			got, err := tmpl.Output(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Template.Output() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Template.Output() = %v, want %v", got, want)
			}
		})
	}
}

func TestOutput_Write(t *testing.T) {
	dir, err := os.MkdirTemp("", "test-output-write")
	assert.FatalError(t, err)
	defer os.RemoveAll(dir)

	join := func(elem ...string) string {
		elems := append([]string{dir}, elem...)
		return filepath.Join(elems...)
	}
	assert.FatalError(t, os.Mkdir(join("bad"), 0644))

	type fields struct {
		Name    string
		Type    TemplateType
		Path    string
		Comment string
		Content []byte
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"snippet", fields{"snippet", Snippet, join("snippet"), "#", []byte("some content")}, false},
		{"file", fields{"file", File, join("file"), "#", []byte("some content")}, false},
		{"snippetInDir", fields{"file", Snippet, join("dir", "snippets", "snippet"), "#", []byte("some content")}, false},
		{"fileInDir", fields{"file", File, join("dir", "files", "file"), "#", []byte("some content")}, false},
		{"directory", fields{"directory", Directory, join("directory"), "", nil}, false},
		{"snippetErr", fields{"snippet", Snippet, join("bad", "snippet"), "#", []byte("some content")}, true},
		{"fileErr", fields{"file", File, join("bad", "file"), "#", []byte("some content")}, true},
		{"directoryErr", fields{"directory", Directory, join("bad", "directory"), "", nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Output{
				Name:    tt.fields.Name,
				Type:    tt.fields.Type,
				Comment: tt.fields.Comment,
				Path:    tt.fields.Path,
				Content: tt.fields.Content,
			}
			if err := o.Write(); (err != nil) != tt.wantErr {
				t.Errorf("Output.Write() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				st, err := os.Stat(o.Path)
				if err != nil {
					t.Errorf("os.Stat(%s) error = %v", o.Path, err)
				} else {
					if o.Type == Directory {
						assert.True(t, st.IsDir())
						assert.Equals(t, os.ModeDir|os.FileMode(0700), st.Mode())
					} else {
						assert.False(t, st.IsDir())
						assert.Equals(t, os.FileMode(0600), st.Mode())
					}
				}
			}
		})
	}
}

func TestTemplate_ValidateRequiredData(t *testing.T) {
	data := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	type fields struct {
		RequiredData []string
	}
	type args struct {
		data map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok nil", fields{nil}, args{nil}, false},
		{"ok empty", fields{[]string{}}, args{data}, false},
		{"ok one", fields{[]string{"key1"}}, args{data}, false},
		{"ok multiple", fields{[]string{"key1", "key2"}}, args{data}, false},
		{"fail nil", fields{[]string{"missing"}}, args{nil}, true},
		{"fail missing", fields{[]string{"missing"}}, args{data}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &Template{
				RequiredData: tt.fields.RequiredData,
			}
			if err := tmpl.ValidateRequiredData(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("Template.ValidateRequiredData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
