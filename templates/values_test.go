package templates

import (
	"reflect"
	"testing"
)

func TestDefaultTemplates(t *testing.T) {
	sshTemplates := DefaultSSHTemplates
	sshTemplatesData := DefaultSSHTemplateData
	t.Cleanup(func() {
		DefaultSSHTemplates = sshTemplates
		DefaultSSHTemplateData = sshTemplatesData
	})

	DefaultSSHTemplates = SSHTemplates{
		User: []Template{
			{Name: "foo.tpl", Type: Snippet, TemplatePath: "templates/ssh/foo.tpl", Path: "/tmp/foo", Comment: "#"},
		},
		Host: []Template{
			{Name: "bar.tpl", Type: Snippet, TemplatePath: "templates/ssh/bar.tpl", Path: "/tmp/bar", Comment: "#"},
		},
	}
	DefaultSSHTemplateData = map[string]string{
		"foo.tpl": "foo",
		"bar.tpl": "bar",
	}

	tests := []struct {
		name string
		want *Templates
	}{
		{"ok", &Templates{
			SSH: &SSHTemplates{
				User: []Template{
					{Name: "foo.tpl", Type: Snippet, Content: []byte("foo"), Path: "/tmp/foo", Comment: "#"},
				},
				Host: []Template{
					{Name: "bar.tpl", Type: Snippet, Content: []byte("bar"), Path: "/tmp/bar", Comment: "#"},
				},
			},
			Data: map[string]interface{}{},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DefaultTemplates(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DefaultTemplates() = %v, want %v", got, tt.want)
			}
		})
	}
}
