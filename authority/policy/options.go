package policy

type Options struct {
	X509 *X509PolicyOptions `json:"x509,omitempty"`
	SSH  *SSHPolicyOptions  `json:"ssh,omitempty"`
}

func (o *Options) GetX509Options() *X509PolicyOptions {
	if o == nil {
		return nil
	}
	return o.X509
}

func (o *Options) GetSSHOptions() *SSHPolicyOptions {
	if o == nil {
		return nil
	}
	return o.SSH
}

type X509PolicyOptionsInterface interface {
	GetAllowedNameOptions() *X509NameOptions
	GetDeniedNameOptions() *X509NameOptions
}

type X509PolicyOptions struct {
	// AllowedNames ...
	AllowedNames *X509NameOptions `json:"allow,omitempty"`

	// DeniedNames ...
	DeniedNames *X509NameOptions `json:"deny,omitempty"`
}

// X509NameOptions models the X509 name policy configuration.
type X509NameOptions struct {
	DNSDomains     []string `json:"dns,omitempty"`
	IPRanges       []string `json:"ip,omitempty"`
	EmailAddresses []string `json:"email,omitempty"`
	URIDomains     []string `json:"uri,omitempty"`
}

// HasNames checks if the AllowedNameOptions has one or more
// names configured.
func (o *X509NameOptions) HasNames() bool {
	return len(o.DNSDomains) > 0 ||
		len(o.IPRanges) > 0 ||
		len(o.EmailAddresses) > 0 ||
		len(o.URIDomains) > 0
}

type SSHPolicyOptionsInterface interface {
	GetAllowedUserNameOptions() *SSHNameOptions
	GetDeniedUserNameOptions() *SSHNameOptions
	GetAllowedHostNameOptions() *SSHNameOptions
	GetDeniedHostNameOptions() *SSHNameOptions
}

type SSHPolicyOptions struct {
	// User contains SSH user certificate options.
	User *SSHUserCertificateOptions `json:"user,omitempty"`

	// Host contains SSH host certificate options.
	Host *SSHHostCertificateOptions `json:"host,omitempty"`
}

// GetAllowedNameOptions returns AllowedNames, which models the
// SANs that ...
func (o *X509PolicyOptions) GetAllowedNameOptions() *X509NameOptions {
	if o == nil {
		return nil
	}
	return o.AllowedNames
}

// GetDeniedNameOptions returns the DeniedNames, which models the
// SANs that ...
func (o *X509PolicyOptions) GetDeniedNameOptions() *X509NameOptions {
	if o == nil {
		return nil
	}
	return o.DeniedNames
}

func (o *SSHPolicyOptions) GetAllowedUserNameOptions() *SSHNameOptions {
	if o == nil {
		return nil
	}
	if o.User == nil {
		return nil
	}
	return o.User.AllowedNames
}

func (o *SSHPolicyOptions) GetDeniedUserNameOptions() *SSHNameOptions {
	if o == nil {
		return nil
	}
	if o.User == nil {
		return nil
	}
	return o.User.DeniedNames
}

func (o *SSHPolicyOptions) GetAllowedHostNameOptions() *SSHNameOptions {
	if o == nil {
		return nil
	}
	if o.Host == nil {
		return nil
	}
	return o.Host.AllowedNames
}

func (o *SSHPolicyOptions) GetDeniedHostNameOptions() *SSHNameOptions {
	if o == nil {
		return nil
	}
	if o.Host == nil {
		return nil
	}
	return o.Host.DeniedNames
}

// SSHUserCertificateOptions is a collection of SSH user certificate options.
type SSHUserCertificateOptions struct {
	// AllowedNames contains the names the provisioner is authorized to sign
	AllowedNames *SSHNameOptions `json:"allow,omitempty"`
	// DeniedNames contains the names the provisioner is not authorized to sign
	DeniedNames *SSHNameOptions `json:"deny,omitempty"`
}

// SSHHostCertificateOptions is a collection of SSH host certificate options.
// It's an alias of SSHUserCertificateOptions, as the options are the same
// for both types of certificates.
type SSHHostCertificateOptions SSHUserCertificateOptions

// SSHNameOptions models the SSH name policy configuration.
type SSHNameOptions struct {
	DNSDomains     []string `json:"dns,omitempty"`
	IPRanges       []string `json:"ip,omitempty"`
	EmailAddresses []string `json:"email,omitempty"`
	Principals     []string `json:"principal,omitempty"`
}

// GetAllowedNameOptions returns the AllowedSSHNameOptions, which models the
// names that a provisioner is authorized to sign SSH certificates for.
func (o *SSHUserCertificateOptions) GetAllowedNameOptions() *SSHNameOptions {
	if o == nil {
		return nil
	}
	return o.AllowedNames
}

// GetDeniedNameOptions returns the DeniedSSHNameOptions, which models the
// names that a provisioner is NOT authorized to sign SSH certificates for.
func (o *SSHUserCertificateOptions) GetDeniedNameOptions() *SSHNameOptions {
	if o == nil {
		return nil
	}
	return o.DeniedNames
}

// HasNames checks if the SSHNameOptions has one or more
// names configured.
func (o *SSHNameOptions) HasNames() bool {
	return len(o.DNSDomains) > 0 ||
		len(o.EmailAddresses) > 0 ||
		len(o.Principals) > 0
}
