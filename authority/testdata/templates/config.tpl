Match exec "step ssh check-host %h"
	ForwardAgent yes
	UserKnownHostsFile {{.User.StepPath}}/ssh/known_hosts