package authority

// Meter wraps the set of defined callbacks for metrics gatherers.
type Meter interface {
	// X509Signed is called whenever an X509 certificate is signed.
	X509Signed(provisioner string, success bool)

	// X509Renewed is called whenever an X509 certificate is renewed.
	X509Renewed(provisioner string, success bool)

	// X509Rekeyed is called whenever an X509 certificate is rekeyed.
	X509Rekeyed(provisioner string, success bool)

	// X509WebhookAuthorized is called whenever an X509 authoring webhook is called.
	X509WebhookAuthorized(provisioner string, success bool)

	// X509WebhookEnriched is called whenever an X509 enriching webhook is called.
	X509WebhookEnriched(provisioner string, success bool)

	// SSHSigned is called whenever an SSH certificate is signed.
	SSHSigned(provisioner string, success bool)

	// SSHRenewed is called whenever an SSH certificate is renewed.
	SSHRenewed(provisioner string, success bool)

	// SSHRekeyed is called whenever an SSH certificate is rekeyed.
	SSHRekeyed(provisioner string, success bool)

	// SSHWebhookAuthorized is called whenever an SSH authoring webhook is called.
	SSHWebhookAuthorized(provisioner string, success bool)

	// SSHWebhookEnriched is called whenever an SSH enriching webhook is called.
	SSHWebhookEnriched(provisioner string, success bool)

	// KMSSigned is called per KMS signer signature.
	KMSSigned()

	// KMSSigned is called per KMS signer signature error.
	KMSError()
}

// noopMeter implements a noop [Meter].
type noopMeter struct{}

func (noopMeter) SSHRekeyed(string, bool)            {}
func (noopMeter) SSHRenewed(string, bool)            {}
func (noopMeter) SSHSigned(string, bool)             {}
func (noopMeter) SSHWebhookAuthorized(string, bool)  {}
func (noopMeter) SSHWebhookEnriched(string, bool)    {}
func (noopMeter) X509Rekeyed(string, bool)           {}
func (noopMeter) X509Renewed(string, bool)           {}
func (noopMeter) X509Signed(string, bool)            {}
func (noopMeter) X509WebhookAuthorized(string, bool) {}
func (noopMeter) X509WebhookEnriched(string, bool)   {}
func (noopMeter) KMSSigned()                         {}
func (noopMeter) KMSError()                          {}
