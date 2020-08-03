package sshutil

// Variables used to hold template data.
const (
	TypeKey               = "Type"
	KeyIDKey              = "KeyID"
	PrincipalsKey         = "Principals"
	ExtensionsKey         = "Extensions"
	CriticalOptionsKey    = "CriticalOptions"
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

// CreateTemplateData returns a TemplateData with the given certificate type,
// key id, principals, and the default extensions.
func CreateTemplateData(ct CertType, keyID string, principals []string) TemplateData {
	return TemplateData{
		TypeKey:       ct.String(),
		KeyIDKey:      keyID,
		PrincipalsKey: principals,
		ExtensionsKey: DefaultExtensions(ct),
	}
}

// DefaultExtensions returns the default extensions set in an SSH certificate.
func DefaultExtensions(ct CertType) map[string]interface{} {
	switch ct {
	case UserCert:
		return map[string]interface{}{
			"permit-X11-forwarding":   "",
			"permit-agent-forwarding": "",
			"permit-port-forwarding":  "",
			"permit-pty":              "",
			"permit-user-rc":          "",
		}
	default:
		return nil
	}
}

// NewTemplateData creates a new map for templates data.
func NewTemplateData() TemplateData {
	return TemplateData{}
}

// AddExtension adds one extension to the templates data.
func (t TemplateData) AddExtension(key, value string) {
	if m, ok := t[ExtensionsKey].(map[string]interface{}); ok {
		m[key] = value
	} else {
		t[ExtensionsKey] = map[string]interface{}{
			key: value,
		}
	}
}

// AddCriticalOption adds one critical option to the templates data.
func (t TemplateData) AddCriticalOption(key, value string) {
	if m, ok := t[CriticalOptionsKey].(map[string]interface{}); ok {
		m[key] = value
	} else {
		t[CriticalOptionsKey] = map[string]interface{}{
			key: value,
		}
	}
}

// Set sets a key-value pair in the template data.
func (t TemplateData) Set(key string, v interface{}) {
	t[key] = v
}

// SetInsecure sets a key-value pair in the insecure template data.
func (t TemplateData) SetInsecure(key string, v interface{}) {
	if m, ok := t[InsecureKey].(TemplateData); ok {
		m[key] = v
	} else {
		t[InsecureKey] = TemplateData{key: v}
	}
}

// SetType sets the certificate type in the template data.
func (t TemplateData) SetType(typ CertType) {
	t.Set(TypeKey, typ.String())
}

// SetKeyID sets the certificate key id in the template data.
func (t TemplateData) SetKeyID(id string) {
	t.Set(KeyIDKey, id)
}

// SetPrincipals sets the certificate principals in the template data.
func (t TemplateData) SetPrincipals(p []string) {
	t.Set(PrincipalsKey, p)
}

// SetExtensions sets the certificate extensions in the template data.
func (t TemplateData) SetExtensions(e map[string]interface{}) {
	t.Set(ExtensionsKey, e)
}

// SetCriticalOptions sets the certificate critical options in the template
// data.
func (t TemplateData) SetCriticalOptions(o map[string]interface{}) {
	t.Set(CriticalOptionsKey, o)
}

// SetToken sets the given token in the template data.
func (t TemplateData) SetToken(v interface{}) {
	t.Set(TokenKey, v)
}

// SetUserData sets the given user provided object in the insecure template
// data.
func (t TemplateData) SetUserData(v interface{}) {
	t.SetInsecure(UserKey, v)
}

// SetCertificateRequest sets the simulated ssh certificate request the insecure
// template data.
func (t TemplateData) SetCertificateRequest(cr CertificateRequest) {
	t.SetInsecure(CertificateRequestKey, cr)
}

// DefaultCertificate is the default template for an SSH certificate.
const DefaultCertificate = `{
	"type": "{{ .Type }}",
	"keyId": "{{ .KeyID }}",
	"principals": {{ toJson .Principals }},
	"extensions": {{ toJson .Extensions }},
	"criticalOptions": {{ toJson .CriticalOptions }}
}`

// DefaultAdminCertificate is the template used by an admin user in a OIDC
// provisioner.
const DefaultAdminCertificate = `{
	"type": "{{ .Insecure.CR.Type }}",
	"keyId": "{{ .Insecure.CR.KeyID }}",
	"principals": {{ toJson .Insecure.CR.Principals }}
{{- if eq .Insecure.CR.Type "user" }}
	, "extensions": {{ toJson .Extensions }},
	"criticalOptions": {{ toJson .CriticalOptions }}
{{- end }}
}`

// DefaultIIDCertificate is the default template for IID provisioners. By
// default certificate type will be set always to host, key id to the instance
// id. Principals will be only enforced by the provisioner if disableCustomSANs
// is set to true.
const DefaultIIDCertificate = `{
	"type": "{{ .Type }}",
	"keyId": "{{ .KeyID }}",
{{- if .Insecure.CR.Principals }}
	"principals": {{ toJson .Insecure.CR.Principals }},
{{- else }}
	"principals": {{ toJson .Principals }},
{{- end }}
	"extensions": {{ toJson .Extensions }}
}`

// CertificateRequestTemplate is the template used for provisioners that accepts
// any certificate request. The provisioner must validate that type, keyId and
// principals are passed in the request.
const CertificateRequestTemplate = `{
	"type": "{{ .Insecure.CR.Type }}",
	"keyId": "{{ .Insecure.CR.KeyID }}",
	"principals": {{ toJson .Insecure.CR.Principals }}
{{- if eq .Insecure.CR.Type "user" }}
	, "extensions": {
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          ""
	}
{{- end }}
}`
