{
	"type": "{{ .Type }}",
	"keyId": "{{ .KeyID }}",
	"principals": {{ toJson .Principals }},
{{- if .Insecure.User.username }}
	"extensions": {{ set .Extensions "login@github.com" .Insecure.User.username | toJson }}
{{- else }}
    "extensions": {{ toJson .Extensions }}
{{- end }}
}