Match exec "step ssh check-host %h"
{{- if .User.User }}
	User {{.User.User}}
{{- end }}
{{- if or .User.GOOS "none" | eq "windows" }}
	UserKnownHostsFile {{.User.StepPath}}\ssh\known_hosts
	ProxyCommand C:\Windows\System32\cmd.exe /c step ssh proxycommand %r %h %p
{{- else }}
	UserKnownHostsFile {{.User.StepPath}}/ssh/known_hosts
	ProxyCommand step ssh proxycommand %r %h %p
{{- end }}
