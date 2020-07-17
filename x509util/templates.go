package x509util

import (
	"crypto/x509"
)

const (
	SubjectKey            = "Subject"
	SANsKey               = "SANs"
	TokenKey              = "Token"
	InsecureKey           = "Insecure"
	UserKey               = "User"
	CertificateRequestKey = "CR"
)

// TemplateError represents an error in a template produced by the fail
// function.
type TemplateError struct {
	Message string
}

// Error implements the error interface and returns the error string when a
// template executes the `fail "message"` function.
func (e *TemplateError) Error() string {
	return e.Message
}

// TemplateData is an alias for map[string]interface{}. It represents the data
// passed to the templates.
type TemplateData map[string]interface{}

// NewTemplateData creates a new map for templates data.
func NewTemplateData() TemplateData {
	return TemplateData{}
}

// CreateTemplateData creates a new TemplateData with the given common name and SANs.
func CreateTemplateData(commonName string, sans []string) TemplateData {
	return TemplateData{
		SubjectKey: Subject{
			CommonName: commonName,
		},
		SANsKey: CreateSANs(sans),
	}
}

func (t TemplateData) Set(key string, v interface{}) {
	t[key] = v
}

func (t TemplateData) SetInsecure(key string, v interface{}) {
	if m, ok := t[InsecureKey].(TemplateData); ok {
		m[key] = v
	} else {
		t[InsecureKey] = TemplateData{key: v}
	}
}

func (t TemplateData) SetSubject(v Subject) {
	t.Set(SubjectKey, v)
}

func (t TemplateData) SetCommonName(cn string) {
	s, _ := t[SubjectKey].(Subject)
	s.CommonName = cn
	t[SubjectKey] = s
}

func (t TemplateData) SetSANs(sans []string) {
	t.Set(SANsKey, CreateSANs(sans))
}

func (t TemplateData) SetToken(v interface{}) {
	t.Set(TokenKey, v)
}

func (t TemplateData) SetUserData(v interface{}) {
	t.SetInsecure(UserKey, v)
}

func (t TemplateData) SetCertificateRequest(cr *x509.CertificateRequest) {
	t.SetInsecure(CertificateRequestKey, newCertificateRequest(cr))
}

// DefaultLeafTemplate is the default template used to generate a leaf
// certificate.
const DefaultLeafTemplate = `{
	"subject": {{ toJson .Subject }},
	"sans": {{ toJson .SANs }},
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
	"keyUsage": ["digitalSignature"],
{{- end }}
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`

// DefaultIIDLeafTemplate is the template used by default on instance identity
// provisioners like AWS, GCP or Azure. By default, those provisioners allow the
// SANs provided in the certificate request, but the option `DisableCustomSANs`
// can be provided to force only the verified domains, if the option is true
// `.SANs` will be set with the verified domains.
const DefaultIIDLeafTemplate = `{
	"subject": {"commonName": "{{ .Insecure.CR.Subject.CommonName }}"},
{{- if .SANs }}
	"sans": {{ toJson .SANs }},
{{- else }}
	"dnsNames": {{ toJson .Insecure.CR.DNSNames }},
	"emailAddresses": {{ toJson .Insecure.CR.EmailAddresses }},
	"ipAddresses": {{ toJson .Insecure.CR.IPAddresses }},
	"uris": {{ toJson .Insecure.CR.URIs }},
{{- end }}
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
	"keyUsage": ["digitalSignature"],
{{- end }}
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`

// DefaultIntermediateTemplate is a template that can be used to generate an
// intermediate certificate.
const DefaultIntermediateTemplate = `{
	"subject": {{ toJson .Subject }},
	"keyUsage": ["certSign", "crlSign"],
	"basicConstraints": {
		"isCA": true,
		"maxPathLen": 0
	}
}`

// DefaultRootTemplate is a template that can be used to generate a root
// certificate.
const DefaultRootTemplate = `{
	"subject": {{ toJson .Subject }},
	"issuer": {{ toJson .Subject }},
	"keyUsage": ["certSign", "crlSign"],
	"basicConstraints": {
		"isCA": true,
		"maxPathLen": 1
	}
}`

// CertificateRequestTemplate is a template that will sign the given certificate
// request.
const CertificateRequestTemplate = `{{ toJson .Insecure.CR }}`
