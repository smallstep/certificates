package authority

// Meter wraps the set of defined callbacks for metrics gatherers.
type Meter interface {
	// X509Signed is called whenever a X509 CSR is signed.
	X509Signed(provisioner string)

	// X509Renewed is called whenever a X509 certificate is renewed.
	X509Renewed(provisioner string)

	// SSHSigned is called whenever a SSH CSR is signed.
	SSHSigned(provisioner string)

	// SSHRenewedf is called whenever a SSH certificate is renewed.
	SSHRenewed(provisioner string)
}

// noopMeter implements a noop [Meter].
type noopMeter struct{}

func (noopMeter) X509Signed(string) {}

func (noopMeter) X509Renewed(string) {}

func (noopMeter) SSHSigned(string) {}

func (noopMeter) SSHRenewed(string) {}
