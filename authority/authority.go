package authority

import (
	"crypto/sha256"
	realx509 "crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
)

const legacyAuthority = "step-certificate-authority"

// Authority implements the Certificate Authority internal interface.
type Authority struct {
	config                 *Config
	rootX509Crt            *realx509.Certificate
	intermediateIdentity   *x509util.Identity
	validateOnce           bool
	certificates           *sync.Map
	ottMap                 *sync.Map
	startTime              time.Time
	provisionerIDIndex     *sync.Map
	encryptedKeyIndex      *sync.Map
	provisionerKeySetIndex *sync.Map
	audiences              []string
	// Do not re-initialize
	initOnce bool
}

// New creates and initiates a new Authority type.
func New(config *Config) (*Authority, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	var a = &Authority{
		config:                 config,
		certificates:           new(sync.Map),
		ottMap:                 new(sync.Map),
		provisionerIDIndex:     new(sync.Map),
		encryptedKeyIndex:      new(sync.Map),
		provisionerKeySetIndex: new(sync.Map),
	}
	if err := a.init(); err != nil {
		return nil, err
	}
	return a, nil
}

// init performs validation and initializes the fields of an Authority struct.
func (a *Authority) init() error {
	// Check if handler has already been validated/initialized.
	if a.initOnce {
		return nil
	}

	var err error
	// First load the root using our modified pem/x509 package.
	a.rootX509Crt, err = pemutil.ReadCertificate(a.config.Root)
	if err != nil {
		return err
	}

	// Add root certificate to the certificate map
	sum := sha256.Sum256(a.rootX509Crt.Raw)
	a.certificates.Store(hex.EncodeToString(sum[:]), a.rootX509Crt)

	// Define audiences: legacy + possible urls
	_, port, err := net.SplitHostPort(a.config.Address)
	if err != nil {
		return errors.Wrapf(err, "error parsing %s", a.config.Address)
	}
	audiences := []string{legacyAuthority}
	for _, name := range a.config.DNSNames {
		if port == "443" {
			audiences = append(audiences, fmt.Sprintf("https://%s/sign", name), fmt.Sprintf("https://%s/1.0/sign", name))
		}
		audiences = append(audiences, fmt.Sprintf("https://%s:%s/sign", name, port), fmt.Sprintf("https://%s:%s/1.0/sign", name, port))

	}
	a.audiences = audiences

	// Decrypt and load intermediate public / private key pair.
	if len(a.config.Password) > 0 {
		a.intermediateIdentity, err = x509util.LoadIdentityFromDisk(
			a.config.IntermediateCert,
			a.config.IntermediateKey,
			pemutil.WithPassword([]byte(a.config.Password)),
		)
		if err != nil {
			return err
		}
	} else {
		a.intermediateIdentity, err = x509util.LoadIdentityFromDisk(a.config.IntermediateCert, a.config.IntermediateKey)
		if err != nil {
			return err
		}
	}

	for _, p := range a.config.AuthorityConfig.Provisioners {
		a.provisionerIDIndex.Store(p.Key.KeyID, p)
		if len(p.EncryptedKey) != 0 {
			a.encryptedKeyIndex.Store(p.Key.KeyID, p.EncryptedKey)
		}
	}

	a.startTime = time.Now()
	// Set flag indicating that initialization has been completed, and should
	// not be repeated.
	a.initOnce = true

	return nil
}
