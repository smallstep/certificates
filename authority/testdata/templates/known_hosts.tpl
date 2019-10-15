@cert-authority * {{.Step.SSH.HostKey.Type}} {{.Step.SSH.HostKey.Marshal | toString | b64enc}}
{{- range .Step.SSH.HostFederatedKeys}}
@cert-authority * {{.Type}} {{.Marshal | toString | b64enc}}
{{- end}}