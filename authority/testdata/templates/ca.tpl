{{.Step.SSH.UserKey.Type}} {{.Step.SSH.UserKey.Marshal | toString | b64enc}}
{{- range .Step.SSH.UserFederatedKeys}}
{{.Type}} {{.Marshal | toString | b64enc}}
{{- end}}