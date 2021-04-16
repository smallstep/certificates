Match all
	TrustedUserCAKeys /etc/ssh/ca.pub
	HostCertificate /etc/ssh/{{.User.Certificate}}
	HostKey /etc/ssh/{{.User.Key}}