package policy

// Options is a container for authority level x509 and SSH
// policy configuration.
type Options struct {
	X509 *X509PolicyOptions `json:"x509,omitempty"`
	SSH  *SSHPolicyOptions  `json:"ssh,omitempty"`
}

// GetX509Options returns the x509 authority level policy
// configuration
func (o *Options) GetX509Options() *X509PolicyOptions {
	if o == nil {
		return nil
	}
	return o.X509
}

// GetSSHOptions returns the SSH authority level policy
// configuration
func (o *Options) GetSSHOptions() *SSHPolicyOptions {
	if o == nil {
		return nil
	}
	return o.SSH
}

// X509PolicyOptionsInterface is an interface for providers
// of x509 allowed and denied names.
type X509PolicyOptionsInterface interface {
	GetAllowedNameOptions() *X509NameOptions
	GetDeniedNameOptions() *X509NameOptions
	IsWildcardLiteralAllowed() bool
	ShouldVerifySubjectCommonName() bool
}

// X509PolicyOptions is a container for x509 allowed and denied
// names.
type X509PolicyOptions struct {
	// AllowedNames contains the x509 allowed names
	AllowedNames *X509NameOptions `json:"allow,omitempty"`
	// DeniedNames contains the x509 denied names
	DeniedNames *X509NameOptions `json:"deny,omitempty"`
	// AllowWildcardLiteral indicates if literal wildcard names
	// such as *.example.com and @example.com are allowed. Defaults
	// to false.
	AllowWildcardLiteral *bool `json:"allow_wildcard_literal,omitempty"`
	// VerifySubjectCommonName indicates if the Subject Common Name
	// is verified in addition to the SANs. Defaults to true.
	VerifySubjectCommonName *bool `json:"verify_subject_common_name,omitempty"`
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

// GetDeniedNameOptions returns the x509 denied name policy configuration
func (o *X509PolicyOptions) GetDeniedNameOptions() *X509NameOptions {
	if o == nil {
		return nil
	}
	return o.DeniedNames
}

// GetAllowedUserNameOptions returns the SSH allowed user name policy
// configuration.
func (o *SSHPolicyOptions) GetAllowedUserNameOptions() *SSHNameOptions {
	if o == nil {
		return nil
	}
	if o.User == nil {
		return nil
	}
	return o.User.AllowedNames
}

func (o *X509PolicyOptions) IsWildcardLiteralAllowed() bool {
	if o == nil {
		return true
	}
	return o.AllowWildcardLiteral != nil && *o.AllowWildcardLiteral
}

func (o *X509PolicyOptions) ShouldVerifySubjectCommonName() bool {
	if o == nil {
		return false
	}
	if o.VerifySubjectCommonName == nil {
		return true
	}
	return *o.VerifySubjectCommonName
}

// SSHPolicyOptionsInterface is an interface for providers of
// SSH user and host name policy configuration.
type SSHPolicyOptionsInterface interface {
	GetAllowedUserNameOptions() *SSHNameOptions
	GetDeniedUserNameOptions() *SSHNameOptions
	GetAllowedHostNameOptions() *SSHNameOptions
	GetDeniedHostNameOptions() *SSHNameOptions
}

// SSHPolicyOptions is a container for SSH user and host policy
// configuration
type SSHPolicyOptions struct {
	// User contains SSH user certificate options.
	User *SSHUserCertificateOptions `json:"user,omitempty"`
	// Host contains SSH host certificate options.
	Host *SSHHostCertificateOptions `json:"host,omitempty"`
}

// GetAllowedNameOptions returns x509 allowed name policy configuration
func (o *X509PolicyOptions) GetAllowedNameOptions() *X509NameOptions {
	if o == nil {
		return nil
	}
	return o.AllowedNames
}

// GetDeniedUserNameOptions returns the SSH denied user name policy
// configuration.
func (o *SSHPolicyOptions) GetDeniedUserNameOptions() *SSHNameOptions {
	if o == nil {
		return nil
	}
	if o.User == nil {
		return nil
	}
	return o.User.DeniedNames
}

// GetAllowedHostNameOptions returns the SSH allowed host name policy
// configuration.
func (o *SSHPolicyOptions) GetAllowedHostNameOptions() *SSHNameOptions {
	if o == nil {
		return nil
	}
	if o.Host == nil {
		return nil
	}
	return o.Host.AllowedNames
}

// GetDeniedHostNameOptions returns the SSH denied host name policy
// configuration.
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
		len(o.IPRanges) > 0 ||
		len(o.EmailAddresses) > 0 ||
		len(o.Principals) > 0
}
