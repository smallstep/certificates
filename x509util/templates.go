package x509util

const DefaultLeafTemplate = `{
	"subject": {{ toJson .Subject }},
	"sans": [
	{{- range $index, $san := initial .SANs }}
		{"type": "{{ $san.Type }}", "value": "{{ $san.Value }}"},
	{{- end }}
	{{- with last .SANs }}
		{"type": "{{ .Type }}", "value": "{{ .Value }}"}
	{{- end }}
	],
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	"extKeyUsage": ["serverAuth", "clientAuth"]
}`
