package authority

import (
	"crypto"
	"io"

	"go.step.sm/crypto/kms"
	kmsapi "go.step.sm/crypto/kms/apiv1"

	"github.com/smallstep/certificates/authority/provisioner"
)

// Meter wraps the set of defined callbacks for metrics gatherers.
type Meter interface {
	// X509Signed is called whenever an X509 certificate is signed.
	X509Signed(provisioner.Interface, error)

	// X509Renewed is called whenever an X509 certificate is renewed.
	X509Renewed(provisioner.Interface, error)

	// X509Rekeyed is called whenever an X509 certificate is rekeyed.
	X509Rekeyed(provisioner.Interface, error)

	// X509WebhookAuthorized is called whenever an X509 authoring webhook is called.
	X509WebhookAuthorized(provisioner.Interface, error)

	// X509WebhookEnriched is called whenever an X509 enriching webhook is called.
	X509WebhookEnriched(provisioner.Interface, error)

	// SSHSigned is called whenever an SSH certificate is signed.
	SSHSigned(provisioner.Interface, error)

	// SSHRenewed is called whenever an SSH certificate is renewed.
	SSHRenewed(provisioner.Interface, error)

	// SSHRekeyed is called whenever an SSH certificate is rekeyed.
	SSHRekeyed(provisioner.Interface, error)

	// SSHWebhookAuthorized is called whenever an SSH authoring webhook is called.
	SSHWebhookAuthorized(provisioner.Interface, error)

	// SSHWebhookEnriched is called whenever an SSH enriching webhook is called.
	SSHWebhookEnriched(provisioner.Interface, error)

	// KMSSigned is called per KMS signer signature.
	KMSSigned(error)
}

// noopMeter implements a noop [Meter].
type noopMeter struct{}

func (noopMeter) SSHRekeyed(provisioner.Interface, error)            {}
func (noopMeter) SSHRenewed(provisioner.Interface, error)            {}
func (noopMeter) SSHSigned(provisioner.Interface, error)             {}
func (noopMeter) SSHWebhookAuthorized(provisioner.Interface, error)  {}
func (noopMeter) SSHWebhookEnriched(provisioner.Interface, error)    {}
func (noopMeter) X509Rekeyed(provisioner.Interface, error)           {}
func (noopMeter) X509Renewed(provisioner.Interface, error)           {}
func (noopMeter) X509Signed(provisioner.Interface, error)            {}
func (noopMeter) X509WebhookAuthorized(provisioner.Interface, error) {}
func (noopMeter) X509WebhookEnriched(provisioner.Interface, error)   {}
func (noopMeter) KMSSigned(error)                                    {}

type instrumentedKeyManager struct {
	kms.KeyManager
	meter Meter
}

type instrumentedKeyAndDecrypterManager struct {
	kms.KeyManager
	decrypter kmsapi.Decrypter
	meter     Meter
}

func newInstrumentedKeyManager(k kms.KeyManager, m Meter) kms.KeyManager {
	decrypter, isDecrypter := k.(kmsapi.Decrypter)
	switch {
	case isDecrypter:
		return &instrumentedKeyAndDecrypterManager{&instrumentedKeyManager{k, m}, decrypter, m}
	default:
		return &instrumentedKeyManager{k, m}
	}
}

func (i *instrumentedKeyManager) CreateSigner(req *kmsapi.CreateSignerRequest) (s crypto.Signer, err error) {
	if s, err = i.KeyManager.CreateSigner(req); err == nil {
		s = &instrumentedKMSSigner{s, i.meter}
	}

	return
}

func (i *instrumentedKeyAndDecrypterManager) CreateDecrypter(req *kmsapi.CreateDecrypterRequest) (s crypto.Decrypter, err error) {
	return i.decrypter.CreateDecrypter(req)
}

type instrumentedKMSSigner struct {
	crypto.Signer
	meter Meter
}

func (i *instrumentedKMSSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	signature, err = i.Signer.Sign(rand, digest, opts)
	i.meter.KMSSigned(err)

	return
}

var _ kms.KeyManager = (*instrumentedKeyManager)(nil)
var _ kms.KeyManager = (*instrumentedKeyAndDecrypterManager)(nil)
var _ kmsapi.Decrypter = (*instrumentedKeyAndDecrypterManager)(nil)
