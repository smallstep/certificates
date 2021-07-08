package config

import (
	"crypto/tls"
	"fmt"

	"github.com/pkg/errors"
)

var (
	// DefaultTLSMinVersion default minimum version of TLS.
	DefaultTLSMinVersion = TLSVersion(1.2)
	// DefaultTLSMaxVersion default maximum version of TLS.
	DefaultTLSMaxVersion = TLSVersion(1.3)
	// DefaultTLSRenegotiation default TLS connection renegotiation policy.
	DefaultTLSRenegotiation = false // Never regnegotiate.
	// DefaultTLSCipherSuites specifies default step ciphersuite(s).
	DefaultTLSCipherSuites = CipherSuites{
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	}
	// ApprovedTLSCipherSuites smallstep approved ciphersuites.
	ApprovedTLSCipherSuites = CipherSuites{
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
	}
	// DefaultTLSOptions represents the default TLS version as well as the cipher
	// suites used in the TLS certificates.
	DefaultTLSOptions = TLSOptions{
		CipherSuites: CipherSuites{
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		},
		MinVersion:    1.2,
		MaxVersion:    1.2,
		Renegotiation: false,
	}
)

// TLSVersion represents a TLS version number.
type TLSVersion float64

// Validate implements models.Validator and checks that a cipher suite is
// valid.
func (v TLSVersion) Validate() error {
	if _, ok := tlsVersions[v]; ok {
		return nil
	}
	return errors.Errorf("%f is not a valid tls version", v)
}

// Value returns the Go constant for the TLSVersion.
func (v TLSVersion) Value() uint16 {
	return tlsVersions[v]
}

// String returns the Go constant for the TLSVersion.
func (v TLSVersion) String() string {
	k := v.Value()
	switch k {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("unexpected value: %f", v)
	}
}

// tlsVersions has the list of supported tls version.
var tlsVersions = map[TLSVersion]uint16{
	// Defaults to TLS 1.3
	0: tls.VersionTLS13,
	// Options
	1.0: tls.VersionTLS10,
	1.1: tls.VersionTLS11,
	1.2: tls.VersionTLS12,
	1.3: tls.VersionTLS13,
}

// CipherSuites represents an array of string codes representing the cipher
// suites.
type CipherSuites []string

// Validate implements models.Validator and checks that a cipher suite is
// valid.
func (c CipherSuites) Validate() error {
	for _, s := range c {
		if _, ok := cipherSuites[s]; !ok {
			return errors.Errorf("%s is not a valid cipher suite", s)
		}
	}
	return nil
}

// Value returns an []uint16 for the cipher suites.
func (c CipherSuites) Value() []uint16 {
	values := make([]uint16, len(c))
	for i, s := range c {
		values[i] = cipherSuites[s]
	}
	return values
}

// cipherSuites has the list of supported cipher suites.
var cipherSuites = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

// TLSOptions represents the TLS options that can be specified on *tls.Config
// types to configure HTTPS servers and clients.
type TLSOptions struct {
	CipherSuites  CipherSuites `json:"cipherSuites"`
	MinVersion    TLSVersion   `json:"minVersion"`
	MaxVersion    TLSVersion   `json:"maxVersion"`
	Renegotiation bool         `json:"renegotiation"`
}

// TLSConfig returns the tls.Config equivalent of the TLSOptions.
func (t *TLSOptions) TLSConfig() *tls.Config {
	var rs tls.RenegotiationSupport
	if t.Renegotiation {
		rs = tls.RenegotiateFreelyAsClient
	} else {
		rs = tls.RenegotiateNever
	}

	return &tls.Config{
		CipherSuites:  t.CipherSuites.Value(),
		MinVersion:    t.MinVersion.Value(),
		MaxVersion:    t.MaxVersion.Value(),
		Renegotiation: rs,
	}
}
