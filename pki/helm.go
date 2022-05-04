package pki

import (
	"io"
	"text/template"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority"
	authconfig "github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/templates"
	"go.step.sm/linkedca"
)

type helmVariables struct {
	*linkedca.Configuration
	Defaults     *linkedca.Defaults
	Password     string
	EnableSSH    bool
	TLS          authconfig.TLSOptions
	Provisioners []provisioner.Interface
}

// WriteHelmTemplate a helm template to configure the
// smallstep/step-certificates helm chart.
func (p *PKI) WriteHelmTemplate(w io.Writer) error {
	tmpl, err := template.New("helm").Funcs(templates.StepFuncMap()).Parse(helmTemplate)
	if err != nil {
		return errors.Wrap(err, "error writing helm template")
	}

	// Delete ssh section if it is not enabled
	if !p.options.enableSSH {
		p.Ssh = nil
	}

	// Convert provisioner to ca.json
	provisioners := make([]provisioner.Interface, len(p.Authority.Provisioners))
	for i, p := range p.Authority.Provisioners {
		pp, err := authority.ProvisionerToCertificates(p)
		if err != nil {
			return err
		}
		provisioners[i] = pp
	}

	if err := tmpl.Execute(w, helmVariables{
		Configuration: &p.Configuration,
		Defaults:      &p.Defaults,
		Password:      "",
		EnableSSH:     p.options.enableSSH,
		TLS:           authconfig.DefaultTLSOptions,
		Provisioners:  provisioners,
	}); err != nil {
		return errors.Wrap(err, "error executing helm template")
	}
	return nil
}

const helmTemplate = `# Helm template
inject:
  enabled: true
  # Config contains the configuration files ca.json and defaults.json
  config:
    files:
      ca.json:
        root: {{ first .Root }}
        federateRoots: []
        crt: {{ .Intermediate }}
        key: {{ .IntermediateKey }}
	{{- if .Kms }}
	kms:
	  type: {{ lower (.Kms.Type | toString) }}
	{{- end }}
        {{- if .EnableSSH }}
        ssh:
          hostKey: {{ .Ssh.HostKey }}
          userKey: {{ .Ssh.UserKey }}
        {{- end }}
        address: {{ .Address }}
        dnsNames:
        {{- range .DnsNames }}
          - {{ . }}
        {{- end }}
        logger:
          format: json
        db:
          type: badgerv2
          dataSource: /home/step/db
        authority:
          provisioners:
          {{- range .Provisioners }}
            - {{ . | toJson }}
          {{- end }}
        tls:
          cipherSuites:
          {{- range .TLS.CipherSuites }}
            - {{ . }}
          {{- end }}
          minVersion: {{ .TLS.MinVersion }}
          maxVersion: {{ .TLS.MaxVersion }}
          renegotiation: {{ .TLS.Renegotiation }}

      defaults.json:
        ca-url: {{ .Defaults.CaUrl }}
        ca-config: {{ .Defaults.CaConfig }}
        fingerprint: {{ .Defaults.Fingerprint }}
        root: {{ .Defaults.Root }}

  # Certificates contains the root and intermediate certificate and 
  # optionally the SSH host and user public keys
  certificates:
    # intermediate_ca contains the text of the intermediate CA Certificate
    intermediate_ca: |
      {{- index .Files .Intermediate | toString | nindent 6 }}
      
    # root_ca contains the text of the root CA Certificate
    root_ca: |
      {{- first .Root | index .Files | toString | nindent 6 }}

    {{- if .Ssh }}
    # ssh_host_ca contains the text of the public ssh key for the SSH root CA
    ssh_host_ca: {{ index .Files .Ssh.HostPublicKey | toString }}

    # ssh_user_ca contains the text of the public ssh key for the SSH root CA
    ssh_user_ca: {{ index .Files .Ssh.UserPublicKey | toString }}
    {{- end }}

  # Secrets contains the root and intermediate keys and optionally the SSH
  # private keys
  secrets:
    # ca_password contains the password used to encrypt x509.intermediate_ca_key, ssh.host_ca_key and ssh.user_ca_key
    # This value must be base64 encoded.
    ca_password: {{ .Password | b64enc }}
    provisioner_password: {{ .Password | b64enc}}

    x509:
      # intermediate_ca_key contains the contents of your encrypted intermediate CA key
      intermediate_ca_key: |
        {{- index .Files .IntermediateKey | toString | nindent 8 }}

      # root_ca_key contains the contents of your encrypted root CA key
      # Note that this value can be omitted without impacting the functionality of step-certificates
      # If supplied, this should be encrypted using a unique password that is not used for encrypting
      # the intermediate_ca_key, ssh.host_ca_key or ssh.user_ca_key.
      root_ca_key: |
        {{- first .RootKey | index .Files | toString | nindent 8 }}

    {{- if .Ssh }}
    ssh:
      # ssh_host_ca_key contains the contents of your encrypted SSH Host CA key
      host_ca_key: |
        {{- index .Files .Ssh.HostKey | toString | nindent 8 }}

      # ssh_user_ca_key contains the contents of your encrypted SSH User CA key
      user_ca_key: |
        {{- index .Files .Ssh.UserKey | toString | nindent 8 }}
    {{- end }}
`
