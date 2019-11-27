Host *
{{- if or .User.GOOS "linux" | eq "windows" }}
	Include {{ .User.StepPath | replace "\\" "/" | trimPrefix "C:" }}/ssh/config
{{- else }}
	Include {{.User.StepPath}}/ssh/config
{{- end }}