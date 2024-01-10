package authority

// Hooks wraps the set of defined callbacks for various events.
type Hooks interface {
	X509CertificateIssued(provisioner string)
	SSHCertificateIssued(provisioner string)
}
