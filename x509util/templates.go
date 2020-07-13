package x509util

import "crypto/x509"

const (
	UserKey               = "User"
	SubjectKey            = "Subject"
	SANsKey               = "SANs"
	TokenKey              = "Token"
	CertificateRequestKey = "CR"
)

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

func (t TemplateData) SetUserData(v Subject) {
	t[UserKey] = v
}

func (t TemplateData) SetSubject(v Subject) {
	t[SubjectKey] = v
}

func (t TemplateData) SetCommonName(cn string) {
	s, _ := t[SubjectKey].(Subject)
	s.CommonName = cn
	t[SubjectKey] = s
}

func (t TemplateData) SetSANs(sans []string) {
	t[SANsKey] = CreateSANs(sans)
}

func (t TemplateData) SetToken(v interface{}) {
	t[TokenKey] = v
}

func (t TemplateData) SetCertificateRequest(cr *x509.CertificateRequest) {
	t[CertificateRequestKey] = newCertificateRequest(cr)
}

// DefaultLeafTemplate is the default templated used to generate a leaf
// certificate. The keyUsage "keyEncipherment" is special and it will be only
// used for RSA keys.
const DefaultLeafTemplate = `{
	"subject": {{ toJson .Subject }},
	"sans": {{ toJson .SANs }},
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`

// DefaultIIDLeafTemplate is the template used by default on instance identity
// provisioners like AWS, GCP or Azure. By default, those provisioners allow the
// SANs provided in the certificate request, but the option `DisableCustomSANs`
// can be provided to force only the verified domains, if the option is true
// `.SANs` will be set with the verified domains.
//
// The keyUsage "keyEncipherment" is special and it will be only used for RSA
// keys.
const DefaultIIDLeafTemplate = `{
	"subject": {{ toJson .Subject }},
	{{- if .SANs }}
	"sans": {{ toJson .SANs }},
	{{- else }}
	"dnsNames": {{ toJson .CR.DNSNames }},
	"emailAddresses": {{ toJson .CR.EmailAddresses }},
	"ipAddresses": {{ toJson .CR.IPAddresses }},
	"uris": {{ toJson .CR.URIs }},
	{{- end }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
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
const CertificateRequestTemplate = `{{ toJson .CR }}`
