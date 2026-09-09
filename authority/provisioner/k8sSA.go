package provisioner

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"

	"github.com/pkg/errors"

	"github.com/smallstep/linkedca"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/sshutil"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/errs"
)

// NOTE: There can be at most one kubernetes service account provisioner configured
// per instance of step-ca. This is due to a lack of distinguishing information
// contained in kubernetes service account tokens.

const (
	// K8sSAName is the default name used for kubernetes service account provisioners.
	K8sSAName = "k8sSA-default"
	// K8sSAID is the default ID for kubernetes service account provisioners.
	K8sSAID     = "k8ssa/" + K8sSAName
	k8sSAIssuer = "kubernetes/serviceaccount"
)

// jwtPayload extends jwt.Claims with step attributes.
type k8sSAPayload struct {
	jose.Claims
	Namespace          string `json:"kubernetes.io/serviceaccount/namespace,omitempty"`
	SecretName         string `json:"kubernetes.io/serviceaccount/secret.name,omitempty"`
	ServiceAccountName string `json:"kubernetes.io/serviceaccount/service-account.name,omitempty"`
	ServiceAccountUID  string `json:"kubernetes.io/serviceaccount/service-account.uid,omitempty"`
}

// K8sSA represents a Kubernetes ServiceAccount provisioner; an
// entity trusted to make signature requests.
type K8sSA struct {
	*base
	ID            string   `json:"-"`
	Type          string   `json:"type"`
	Name          string   `json:"name"`
	PubKeys       []byte   `json:"publicKeys,omitempty"`
	Claims        *Claims  `json:"claims,omitempty"`
	Options       *Options `json:"options,omitempty"`
	pubKeys       []interface{}
	tokenReviewer k8sSATokenReviewer
	ctl           *Controller
}

// GetID returns the provisioner unique identifier. The name and credential id
// should uniquely identify any K8sSA provisioner.
func (p *K8sSA) GetID() string {
	if p.ID != "" {
		return p.ID
	}
	return p.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner
// from a token.
func (p *K8sSA) GetIDForToken() string {
	return K8sSAID
}

// GetTokenID returns an unimplemented error and does not use the input ott.
func (p *K8sSA) GetTokenID(string) (string, error) {
	return "", ErrNotImplemented
}

// GetName returns the name of the provisioner.
func (p *K8sSA) GetName() string {
	return p.Name
}

// GetType returns the type of provisioner.
func (p *K8sSA) GetType() Type {
	return TypeK8sSA
}

// GetEncryptedKey returns false, because the kubernetes provisioner does not
// have access to the private key.
func (p *K8sSA) GetEncryptedKey() (string, string, bool) {
	return "", "", false
}

// Init initializes and validates the fields of a K8sSA type.
func (p *K8sSA) Init(config Config) (err error) {
	switch {
	case p.Type == "":
		return errors.New("provisioner type cannot be empty")
	case p.Name == "":
		return errors.New("provisioner name cannot be empty")
	}

	if len(p.PubKeys) > 0 {
		var (
			block *pem.Block
			rest  = p.PubKeys
		)
		for rest != nil {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			key, err := pemutil.ParseKey(pem.EncodeToMemory(block))
			if err != nil {
				return errors.Wrapf(err, "error parsing public key in provisioner '%s'", p.GetName())
			}
			switch q := key.(type) {
			case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			default:
				return errors.Errorf("Unexpected public key type %T in provisioner '%s'", q, p.GetName())
			}
			p.pubKeys = append(p.pubKeys, key)
		}
	} else if p.tokenReviewer == nil {
		p.tokenReviewer, err = newInClusterK8sSATokenReviewer()
		if err != nil {
			return errors.Wrap(err, "error initializing Kubernetes TokenReview client")
		}
	}

	p.ctl, err = NewController(p, p.Claims, config, p.Options)
	return
}

// authorizeToken performs common jwt authorization actions and returns the
// claims for case specific downstream parsing.
// e.g. a Sign request will auth/validate different fields than a Revoke request.
func (p *K8sSA) authorizeToken(ctx context.Context, token string, audiences []string) (*k8sSAPayload, error) {
	jwt, err := jose.ParseSigned(token)
	if err != nil {
		return nil, errs.Wrap(http.StatusUnauthorized, err,
			"k8ssa.authorizeToken; error parsing k8sSA token")
	}

	var claims k8sSAPayload
	if p.tokenReviewer != nil {
		status, err := p.tokenReviewer.Review(ctx, token, audiences)
		if err != nil {
			return nil, errs.Wrap(http.StatusInternalServerError, err,
				"k8ssa.authorizeToken; error using Kubernetes TokenReview API")
		}
		if status == nil {
			return nil, errs.InternalServer("k8ssa.authorizeToken; Kubernetes TokenReview API returned an empty response")
		}
		if status.Error != "" {
			return nil, errs.Unauthorized("k8ssa.authorizeToken; Kubernetes TokenReview API returned an error: %s", status.Error)
		}
		if !status.Authenticated {
			return nil, errs.Unauthorized("k8ssa.authorizeToken; Kubernetes TokenReview API did not authenticate token")
		}
		if len(audiences) > 0 && !matchesK8sSAAudience(audiences, status.Audiences) {
			return nil, errs.Unauthorized("k8ssa.authorizeToken; Kubernetes TokenReview API did not validate the expected audience")
		}

		namespace, serviceAccount, ok := parseK8sSAUsername(status.User.Username)
		if !ok {
			return nil, errs.Unauthorized("k8ssa.authorizeToken; Kubernetes TokenReview API returned invalid service account username %q", status.User.Username)
		}
		claims.Claims.Subject = status.User.Username
		claims.Namespace = namespace
		claims.ServiceAccountName = serviceAccount
		claims.ServiceAccountUID = status.User.UID
	} else {
		valid := false
		for _, pk := range p.pubKeys {
			if err = jwt.Claims(pk, &claims); err == nil {
				valid = true
				break
			}
		}
		if !valid {
			return nil, errs.Unauthorized("k8ssa.authorizeToken; error validating k8sSA token and extracting claims")
		}

		// According to "rfc7519 JSON Web Token" acceptable skew should be no
		// more than a few minutes.
		if err = claims.Validate(jose.Expected{
			Issuer: k8sSAIssuer,
		}); err != nil {
			return nil, errs.Wrap(http.StatusUnauthorized, err, "k8ssa.authorizeToken; invalid k8sSA token claims")
		}
	}

	if claims.Subject == "" {
		return nil, errs.Unauthorized("k8ssa.authorizeToken; k8sSA token subject cannot be empty")
	}

	return &claims, nil
}

// AuthorizeRevoke returns an error if the provisioner does not have rights to
// revoke the certificate with serial number in the `sub` property.
func (p *K8sSA) AuthorizeRevoke(ctx context.Context, token string) error {
	_, err := p.authorizeToken(ctx, token, p.ctl.Audiences.Revoke)
	return errs.Wrap(http.StatusInternalServerError, err, "k8ssa.AuthorizeRevoke")
}

// AuthorizeSign validates the given token.
func (p *K8sSA) AuthorizeSign(ctx context.Context, token string) ([]SignOption, error) {
	claims, err := p.authorizeToken(ctx, token, p.ctl.Audiences.Sign)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "k8ssa.AuthorizeSign")
	}

	// Add some values to use in custom templates.
	data := x509util.NewTemplateData()
	data.SetCommonName(claims.ServiceAccountName)
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	// Certificate templates: on K8sSA the default template is the certificate
	// request.
	templateOptions, err := CustomTemplateOptions(p.Options, data, x509util.DefaultAdminLeafTemplate)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "k8ssa.AuthorizeSign")
	}

	return []SignOption{
		p,
		templateOptions,
		// modifiers / withOptions
		newProvisionerExtensionOption(TypeK8sSA, p.Name, "").WithControllerOptions(p.ctl),
		profileDefaultDuration(p.ctl.Claimer.DefaultTLSCertDuration()),
		// validators
		defaultPublicKeyValidator{},
		newValidityValidator(p.ctl.Claimer.MinTLSCertDuration(), p.ctl.Claimer.MaxTLSCertDuration()),
		newX509NamePolicyValidator(p.ctl.getPolicy().getX509()),
		p.ctl.newWebhookController(data, linkedca.Webhook_X509),
	}, nil
}

// AuthorizeRenew returns an error if the renewal is disabled.
func (p *K8sSA) AuthorizeRenew(ctx context.Context, cert *x509.Certificate) error {
	return p.ctl.AuthorizeRenew(ctx, cert)
}

// AuthorizeSSHSign validates an request for an SSH certificate.
func (p *K8sSA) AuthorizeSSHSign(ctx context.Context, token string) ([]SignOption, error) {
	if !p.ctl.Claimer.IsSSHCAEnabled() {
		return nil, errs.Unauthorized("k8ssa.AuthorizeSSHSign; sshCA is disabled for k8sSA provisioner '%s'", p.GetName())
	}
	claims, err := p.authorizeToken(ctx, token, p.ctl.Audiences.SSHSign)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "k8ssa.AuthorizeSSHSign")
	}

	// Certificate templates.
	// Set some default variables to be used in the templates.
	data := sshutil.CreateTemplateData(sshutil.HostCert, claims.ServiceAccountName, []string{claims.ServiceAccountName})
	if v, err := unsafeParseSigned(token); err == nil {
		data.SetToken(v)
	}

	templateOptions, err := CustomSSHTemplateOptions(p.Options, data, sshutil.CertificateRequestTemplate)
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "k8ssa.AuthorizeSSHSign")
	}
	signOptions := []SignOption{templateOptions}

	return append(signOptions,
		p,
		// Require type, key-id and principals in the SignSSHOptions.
		&sshCertOptionsRequireValidator{CertType: true, KeyID: true, Principals: true},
		// Set the validity bounds if not set.
		&sshDefaultDuration{p.ctl.Claimer},
		// Validate public key
		&sshDefaultPublicKeyValidator{},
		// Validate the validity period.
		&sshCertValidityValidator{p.ctl.Claimer},
		// Require and validate all the default fields in the SSH certificate.
		&sshCertDefaultValidator{},
		// Ensure that all principal names are allowed
		newSSHNamePolicyValidator(p.ctl.getPolicy().getSSHHost(), p.ctl.getPolicy().getSSHUser()),
		// Call webhooks
		p.ctl.newWebhookController(data, linkedca.Webhook_SSH),
	), nil
}
