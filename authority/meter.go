package authority

// Meter wraps the set of defined callbacks for metrics gatherers.
type Meter interface {
	// X509Signed is called whenever a X509 CSR is signed.
	X509Signed(provisioner string, success bool)

	// X509Renewed is called whenever a X509 certificate is renewed.
	X509Renewed(provisioner string, success bool)

	// X509Rekeyed is called whenever a X509 certificate is rekeyed.
	X509Rekeyed(provisioner string, success bool)

	// SSHSigned is called whenever a SSH CSR is signed.
	SSHSigned(provisioner string, success bool)

	// SSHRenewed is called whenever a SSH certificate is renewed.
	SSHRenewed(provisioner string, success bool)

	// SSHRekeyed is called whenever a SSH certificate is rekeyed.
	SSHRekeyed(provisioner string, success bool)
}

// noopMeter implements a noop [Meter].
type noopMeter struct{}

func (noopMeter) X509Signed(string, bool) {}

func (noopMeter) X509Renewed(string, bool) {}

func (noopMeter) SSHSigned(string, bool) {}

func (noopMeter) SSHRenewed(string, bool) {}

func (noopMeter) SSHRekeyed(string, bool) {}
