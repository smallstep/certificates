package x509util

const (
	UserKey    = "User"
	SubjectKey = "Subject"
	SANsKey    = "SANs"
	TokenKey   = "Token"
)

// TemplateData is an alias for map[string]interface{}. It represents the data
// passed to the templates.
type TemplateData map[string]interface{}

func (t TemplateData) Set(key string, v interface{}) {
	t[key] = v
}

func (t TemplateData) SetUserData(v Subject) {
	t[UserKey] = v
}

func (t TemplateData) SetSubject(v Subject) {
	t[SubjectKey] = v
}

func (t TemplateData) SetSANs(sans []string) {
	t[SANsKey] = CreateSANs(sans)
}

func (t TemplateData) SetToken(v interface{}) {
	t[TokenKey] = v
}

const DefaultLeafTemplate = `{
	"subject": {{ toJson .Subject }},
	"sans": {{ toJson .SANs }},
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`

const DefaultIntermediateTemplate = `{
	"subject": {{ toJson .Subject }},
	"keyUsage": ["certSign", "crlSign"],
	"basicConstraints": {
		"isCA": true,
		"maxPathLen": 0
	}
}`

const DefaultRootTemplate = `{
	"subject": {{ toJson .Subject }},
	"issuer": {{ toJson .Subject }},
	"keyUsage": ["certSign", "crlSign"],
	"basicConstraints": {
		"isCA": true,
		"maxPathLen": 1
	}
}`
