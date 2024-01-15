package authority

// Meter wraps the set of defined callbacks for metrics gatherers.
type Meter interface {
	// X509Signatures is called whenever a X509 CSR is signed.
	X509Signatures(provisioner string)

	// SSHSignatures is called whenever a SSH CSR is issued.
	SSHSignatures(provisioner string)
}
