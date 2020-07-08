package x509util

const (
	UserKey    = "User"
	SubjectKey = "Subject"
	SANsKey    = "SANs"
)

const DefaultLeafTemplate = `{
	"subject": {{ toJson .Subject }},
	"sans": {{ toJson .SANs }},
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`
