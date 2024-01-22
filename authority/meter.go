package authority

// Meter wraps the set of defined callbacks for metrics gatherers.
type Meter interface {
	// X509Signed is called whenever a X509 CSR is signed.
	X509Signed(provisioner string, success bool)

	// X509Renewed is called whenever a X509 certificate is renewed.
	X509Renewed(provisioner string, success bool)

	// X509Rekeyed is called whenever a X509 certificate is rekeyed.
	X509Rekeyed(provisioner string, success bool)

	// X509Authorized is called whenever a X509 authoring webhook is called.
	X509Authorized(provisioner string, success bool)

	// X509Enriched is called whenever a X509 enriching webhook is called.
	X509Enriched(provisioner string, success bool)

	// SSHSigned is called whenever a SSH CSR is signed.
	SSHSigned(provisioner string, success bool)

	// SSHRenewed is called whenever a SSH certificate is renewed.
	SSHRenewed(provisioner string, success bool)

	// SSHRekeyed is called whenever a SSH certificate is rekeyed.
	SSHRekeyed(provisioner string, success bool)

	// SSHAuthorized is called whenever a SSH authoring webhook is called.
	SSHAuthorized(provisioner string, success bool)

	// SSHEnriched is called whenever a SSH enriching webhook is called.
	SSHEnriched(provisioner string, success bool)

	// KMSSigned is called per KMS signer signature.
	KMSSigned()

	// KMSSigned is called per KMS signer signature error.
	KMSError()
}

// noopMeter implements a noop [Meter].
type noopMeter struct{}

func (noopMeter) SSHRekeyed(string, bool)     {}
func (noopMeter) SSHRenewed(string, bool)     {}
func (noopMeter) SSHSigned(string, bool)      {}
func (noopMeter) SSHAuthorized(string, bool)  {}
func (noopMeter) SSHEnriched(string, bool)    {}
func (noopMeter) X509Rekeyed(string, bool)    {}
func (noopMeter) X509Renewed(string, bool)    {}
func (noopMeter) X509Signed(string, bool)     {}
func (noopMeter) X509Authorized(string, bool) {}
func (noopMeter) X509Enriched(string, bool)   {}
func (noopMeter) KMSSigned()                  {}
func (noopMeter) KMSError()                   {}
