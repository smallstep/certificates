{
	"subject": {{ toJson .Insecure.CR.Subject }},
	"sans": {{ toJson .SANs }},
{{- if .Insecure.CR.EmailAddresses }}
	"emailAddresses": {{ toJson .Insecure.CR.EmailAddresses }},
{{- end }}
{{- if .Token }}
	"uris": "{{ .Token.iss }}#{{ .Token.sub }}",
{{- end }}
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	{{- if lt .Insecure.CR.PublicKey.Size 384 }}
		{{ fail "Key length must be at least 3072 bits" }}
	{{- end }}
{{- end }}
{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
{{- else }}
	"keyUsage": ["digitalSignature"],
{{- end }}
	"extKeyUsage": ["serverAuth", "clientAuth"]
}