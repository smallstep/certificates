package authority

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/smallstep/certificates/ct"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
)

const legacyAuthority = "step-certificate-authority"

// Authority implements the Certificate Authority internal interface.
type Authority struct {
	config                 *Config
	rootX509Certs          []*x509.Certificate
	intermediateIdentity   *x509util.Identity
	validateOnce           bool
	certificates           *sync.Map
	ottMap                 *sync.Map
	startTime              time.Time
	provisionerIDIndex     *sync.Map
	encryptedKeyIndex      *sync.Map
	provisionerKeySetIndex *sync.Map
	sortedProvisioners     provisionerSlice
	audiences              []string
	ctClient               ct.Client
	// Do not re-initialize
	initOnce bool
}

// New creates and initiates a new Authority type.
func New(config *Config) (*Authority, error) {
	err := config.Validate()
	if err != nil {
		return nil, err
	}

	// Get sorted provisioners
	var sorted provisionerSlice
	if config.AuthorityConfig != nil {
		sorted, err = newSortedProvisioners(config.AuthorityConfig.Provisioners)
		if err != nil {
			return nil, err
		}
	}

	// Define audiences: legacy + possible urls without the ports.
	// The CA might have proxies in front so we cannot rely on the port.
	audiences := []string{legacyAuthority}
	for _, name := range config.DNSNames {
		audiences = append(audiences, fmt.Sprintf("https://%s/sign", name), fmt.Sprintf("https://%s/1.0/sign", name))
	}

	var ctClient ct.Client
	// only first one is supported at the moment.
	if len(config.CTs) > 0 {
		if ctClient, err = ct.New(config.CTs[0]); err != nil {
			return nil, err
		}
	}

	var a = &Authority{
		config:                 config,
		certificates:           new(sync.Map),
		ottMap:                 new(sync.Map),
		provisionerIDIndex:     new(sync.Map),
		encryptedKeyIndex:      new(sync.Map),
		provisionerKeySetIndex: new(sync.Map),
		sortedProvisioners:     sorted,
		audiences:              audiences,
		ctClient:               ctClient,
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

	// Load the root certificates and add them to the certificate store
	a.rootX509Certs = make([]*x509.Certificate, len(a.config.Root))
	for i, path := range a.config.Root {
		crt, err := pemutil.ReadCertificate(path)
		if err != nil {
			return err
		}
		// Add root certificate to the certificate map
		sum := sha256.Sum256(crt.Raw)
		a.certificates.Store(hex.EncodeToString(sum[:]), crt)
		a.rootX509Certs[i] = crt
	}

	// Add federated roots
	for _, path := range a.config.FederatedRoots {
		crt, err := pemutil.ReadCertificate(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(crt.Raw)
		a.certificates.Store(hex.EncodeToString(sum[:]), crt)
	}

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
		a.provisionerIDIndex.Store(p.ID(), p)
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
