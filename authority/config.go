package authority

import "github.com/smallstep/certificates/authority/config"

// Config is an alias to support older APIs.
type Config = config.Config

// LoadConfiguration is an alias to support older APIs.
var LoadConfiguration = config.LoadConfiguration

// AuthConfig is an alias to support older APIs.
type AuthConfig = config.AuthConfig

// TLS

// ASN1DN is an alias to support older APIs.
type ASN1DN = config.ASN1DN

// DefaultTLSOptions is an alias to support older APIs.
var DefaultTLSOptions = config.DefaultTLSOptions

// TLSOptions is an alias to support older APIs.
type TLSOptions = config.TLSOptions

// CipherSuites is an alias to support older APIs.
type CipherSuites = config.CipherSuites

// SSH

// SSHConfig is an alias to support older APIs.
type SSHConfig = config.SSHConfig

// Bastion is an alias to support older APIs.
type Bastion = config.Bastion

// HostTag is an alias to support older APIs.
type HostTag = config.HostTag

// Host is an alias to support older APIs.
type Host = config.Host

// SSHPublicKey is an alias to support older APIs.
type SSHPublicKey = config.SSHPublicKey

// SSHKeys is an alias to support older APIs.
type SSHKeys = config.SSHKeys
