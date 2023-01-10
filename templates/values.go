package templates

import (
	"golang.org/x/crypto/ssh"
)

// SSHTemplateVersionKey is a key that can be submitted by a client to select
// the template version that will be returned by the server.
var SSHTemplateVersionKey = "StepSSHTemplateVersion"

// Step represents the default variables available in the CA.
type Step struct {
	SSH StepSSH
}

// StepSSH holds SSH-related values for the CA.
type StepSSH struct {
	HostKey           ssh.PublicKey
	UserKey           ssh.PublicKey
	HostFederatedKeys []ssh.PublicKey
	UserFederatedKeys []ssh.PublicKey
}

// DefaultSSHTemplates contains the configuration of default templates used on ssh.
// Relative paths are relative to the StepPath.
var DefaultSSHTemplates = SSHTemplates{
	User: []Template{
		{
			Name:         "config.tpl",
			Type:         Snippet,
			TemplatePath: "templates/ssh/config.tpl",
			Path:         "~/.ssh/config",
			Comment:      "#",
		},
		{
			Name:         "step_includes.tpl",
			Type:         PrependLine,
			TemplatePath: "templates/ssh/step_includes.tpl",
			Path:         "${STEPPATH}/ssh/includes",
			Comment:      "#",
		},
		{
			Name:         "step_config.tpl",
			Type:         File,
			TemplatePath: "templates/ssh/step_config.tpl",
			Path:         "ssh/config",
			Comment:      "#",
		},
		{
			Name:         "known_hosts.tpl",
			Type:         File,
			TemplatePath: "templates/ssh/known_hosts.tpl",
			Path:         "ssh/known_hosts",
			Comment:      "#",
		},
	},
	Host: []Template{
		{
			Name:         "sshd_config.tpl",
			Type:         Snippet,
			TemplatePath: "templates/ssh/sshd_config.tpl",
			Path:         "/etc/ssh/sshd_config",
			Comment:      "#",
			RequiredData: []string{"Certificate", "Key"},
		},
		{
			Name:         "ca.tpl",
			Type:         Snippet,
			TemplatePath: "templates/ssh/ca.tpl",
			Path:         "/etc/ssh/ca.pub",
			Comment:      "#",
		},
	},
}

// DefaultSSHTemplateData contains the data of the default templates used on ssh.
var DefaultSSHTemplateData = map[string]string{
	// config.tpl adds the step ssh config file.
	//
	// Note: on windows `Include C:\...` is treated as a relative path.
	"config.tpl": `Host *
{{- if or .User.GOOS "none" | eq "windows" }}
{{- if .User.StepBasePath }}
	Include "{{ .User.StepBasePath | replace "\\" "/" | trimPrefix "C:" }}/ssh/includes"
{{- else }}
	Include "{{ .User.StepPath | replace "\\" "/" | trimPrefix "C:" }}/ssh/includes"
{{- end }}
{{- else }}
{{- if .User.StepBasePath }}
	Include "{{.User.StepBasePath}}/ssh/includes"
{{- else }}
	Include "{{.User.StepPath}}/ssh/includes"
{{- end }}
{{- end }}`,

	// step_includes.tpl adds the step ssh config file.
	//
	// Note: on windows `Include C:\...` is treated as a relative path.
	"step_includes.tpl": `{{- if or .User.GOOS "none" | eq "windows" }}Include "{{ .User.StepPath | replace "\\" "/" | trimPrefix "C:" }}/ssh/config"{{- else }}Include "{{.User.StepPath}}/ssh/config"{{- end }}`,

	// step_config.tpl is the step ssh config file, it includes the Match rule and
	// references the step known_hosts file.
	//
	// Note: on windows ProxyCommand requires the full path
	"step_config.tpl": `Match exec "step ssh check-host{{- if .User.Context }} --context {{ .User.Context }}{{- end }} %h"
{{- if .User.User }}
	User {{.User.User}}
{{- end }}
{{- if or .User.GOOS "none" | eq "windows" }}
	UserKnownHostsFile "{{.User.StepPath}}\ssh\known_hosts"
	ProxyCommand C:\Windows\System32\cmd.exe /c step ssh proxycommand{{- if .User.Context }} --context {{ .User.Context }}{{- end }}{{- if .User.Provisioner }} --provisioner {{ .User.Provisioner }}{{- end }} %r %h %p
{{- else }}
	UserKnownHostsFile "{{.User.StepPath}}/ssh/known_hosts"
	ProxyCommand step ssh proxycommand{{- if .User.Context }} --context {{ .User.Context }}{{- end }}{{- if .User.Provisioner }} --provisioner {{ .User.Provisioner }}{{- end }} %r %h %p
{{- end }}
`,

	// known_hosts.tpl authorizes the ssh hosts key
	"known_hosts.tpl": `@cert-authority * {{.Step.SSH.HostKey.Type}} {{.Step.SSH.HostKey.Marshal | toString | b64enc}}
{{- range .Step.SSH.HostFederatedKeys}}
@cert-authority * {{.Type}} {{.Marshal | toString | b64enc}}
{{- end }}
`,

	// sshd_config.tpl adds the configuration to support certificates
	"sshd_config.tpl": `Match all
	TrustedUserCAKeys /etc/ssh/ca.pub
	HostCertificate /etc/ssh/{{.User.Certificate}}
	HostKey /etc/ssh/{{.User.Key}}`,

	// ca.tpl contains the public key used to authorized clients
	"ca.tpl": `{{.Step.SSH.UserKey.Type}} {{.Step.SSH.UserKey.Marshal | toString | b64enc}}
{{- range .Step.SSH.UserFederatedKeys}}
{{.Type}} {{.Marshal | toString | b64enc}}
{{- end }}
`,
}

// DefaultTemplates returns the default templates.
func DefaultTemplates() *Templates {
	sshTemplates := DefaultSSHTemplates
	for i, t := range sshTemplates.User {
		sshTemplates.User[i].TemplatePath = ""
		sshTemplates.User[i].Content = []byte(DefaultSSHTemplateData[t.Name])
	}
	for i, t := range sshTemplates.Host {
		sshTemplates.Host[i].TemplatePath = ""
		sshTemplates.Host[i].Content = []byte(DefaultSSHTemplateData[t.Name])
	}
	return &Templates{
		SSH:  &sshTemplates,
		Data: map[string]interface{}{},
	}
}
