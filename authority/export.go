package authority

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"go.step.sm/cli-utils/step"
	"go.step.sm/linkedca"
	"google.golang.org/protobuf/types/known/structpb"
)

// Export creates a linkedca configuration form the current ca.json and loaded
// authorities.
//
// Note that export will not export neither the pki password nor the certificate
// issuer password.
func (a *Authority) Export() (c *linkedca.Configuration, err error) {
	// Recover from panics
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	files := make(map[string][]byte)

	// The exported configuration should not include the password in it.
	c = &linkedca.Configuration{
		Version:         "1.0",
		Root:            mustReadFilesOrURIs(a.config.Root, files),
		FederatedRoots:  mustReadFilesOrURIs(a.config.FederatedRoots, files),
		Intermediate:    mustReadFileOrURI(a.config.IntermediateCert, files),
		IntermediateKey: mustReadFileOrURI(a.config.IntermediateKey, files),
		Address:         a.config.Address,
		InsecureAddress: a.config.InsecureAddress,
		DnsNames:        a.config.DNSNames,
		Db:              mustMarshalToStruct(a.config.DB),
		Logger:          mustMarshalToStruct(a.config.Logger),
		Monitoring:      mustMarshalToStruct(a.config.Monitoring),
		Authority: &linkedca.Authority{
			Id:                   a.config.AuthorityConfig.AuthorityID,
			EnableAdmin:          a.config.AuthorityConfig.EnableAdmin,
			DisableIssuedAtCheck: a.config.AuthorityConfig.DisableIssuedAtCheck,
			Backdate:             mustDuration(a.config.AuthorityConfig.Backdate),
			DeploymentType:       a.config.AuthorityConfig.DeploymentType,
		},
		Files: files,
	}

	// SSH
	if v := a.config.SSH; v != nil {
		c.Ssh = &linkedca.SSH{
			HostKey:          mustReadFileOrURI(v.HostKey, files),
			UserKey:          mustReadFileOrURI(v.UserKey, files),
			AddUserPrincipal: v.AddUserPrincipal,
			AddUserCommand:   v.AddUserCommand,
		}
		for _, k := range v.Keys {
			typ, ok := linkedca.SSHPublicKey_Type_value[strings.ToUpper(k.Type)]
			if !ok {
				return nil, errors.Errorf("unsupported ssh key type %s", k.Type)
			}
			c.Ssh.Keys = append(c.Ssh.Keys, &linkedca.SSHPublicKey{
				Type:      linkedca.SSHPublicKey_Type(typ),
				Federated: k.Federated,
				Key:       mustMarshalToStruct(k),
			})
		}
		if b := v.Bastion; b != nil {
			c.Ssh.Bastion = &linkedca.Bastion{
				Hostname: b.Hostname,
				User:     b.User,
				Port:     b.Port,
				Command:  b.Command,
				Flags:    b.Flags,
			}
		}
	}

	// KMS
	if v := a.config.KMS; v != nil {
		var typ int32
		var ok bool
		if v.Type == "" {
			typ = int32(linkedca.KMS_SOFTKMS)
		} else {
			typ, ok = linkedca.KMS_Type_value[strings.ToUpper(string(v.Type))]
			if !ok {
				return nil, errors.Errorf("unsupported kms type %s", v.Type)
			}
		}
		c.Kms = &linkedca.KMS{
			Type:            linkedca.KMS_Type(typ),
			CredentialsFile: v.CredentialsFile,
			Uri:             v.URI,
			Pin:             v.Pin,
			ManagementKey:   v.ManagementKey,
			Region:          v.Region,
			Profile:         v.Profile,
		}
	}

	// Authority
	// cas options
	if v := a.config.AuthorityConfig.Options; v != nil {
		c.Authority.Type = 0
		c.Authority.CertificateAuthority = v.CertificateAuthority
		c.Authority.CertificateAuthorityFingerprint = v.CertificateAuthorityFingerprint
		c.Authority.CredentialsFile = v.CredentialsFile
		if iss := v.CertificateIssuer; iss != nil {
			typ, ok := linkedca.CertificateIssuer_Type_value[strings.ToUpper(iss.Type)]
			if !ok {
				return nil, errors.Errorf("unknown certificate issuer type %s", iss.Type)
			}
			// The exported certificate issuer should not include the password.
			c.Authority.CertificateIssuer = &linkedca.CertificateIssuer{
				Type:        linkedca.CertificateIssuer_Type(typ),
				Provisioner: iss.Provisioner,
				Certificate: mustReadFileOrURI(iss.Certificate, files),
				Key:         mustReadFileOrURI(iss.Key, files),
			}
		}
	}
	// admins
	for {
		list, cursor := a.admins.Find("", 100)
		c.Authority.Admins = append(c.Authority.Admins, list...)
		if cursor == "" {
			break
		}
	}
	// provisioners
	for {
		list, cursor := a.provisioners.Find("", 100)
		for _, p := range list {
			lp, err := ProvisionerToLinkedca(p)
			if err != nil {
				return nil, err
			}
			c.Authority.Provisioners = append(c.Authority.Provisioners, lp)
		}
		if cursor == "" {
			break
		}
	}
	// global claims
	c.Authority.Claims = claimsToLinkedca(a.config.AuthorityConfig.Claims)
	// Distinguished names template
	if v := a.config.AuthorityConfig.Template; v != nil {
		c.Authority.Template = &linkedca.DistinguishedName{
			Country:            v.Country,
			Organization:       v.Organization,
			OrganizationalUnit: v.OrganizationalUnit,
			Locality:           v.Locality,
			Province:           v.Province,
			StreetAddress:      v.StreetAddress,
			SerialNumber:       v.SerialNumber,
			CommonName:         v.CommonName,
		}
	}

	// TLS
	if v := a.config.TLS; v != nil {
		c.Tls = &linkedca.TLS{
			MinVersion:    v.MinVersion.String(),
			MaxVersion:    v.MaxVersion.String(),
			Renegotiation: v.Renegotiation,
		}
		for _, cs := range v.CipherSuites.Value() {
			c.Tls.CipherSuites = append(c.Tls.CipherSuites, linkedca.TLS_CiperSuite(cs))
		}
	}

	// Templates
	if v := a.config.Templates; v != nil {
		c.Templates = &linkedca.ConfigTemplates{
			Ssh:  &linkedca.SSHConfigTemplate{},
			Data: mustMarshalToStruct(v.Data),
		}
		// Remove automatically loaded vars
		if c.Templates.Data != nil && c.Templates.Data.Fields != nil {
			delete(c.Templates.Data.Fields, "Step")
		}
		for _, t := range v.SSH.Host {
			typ, ok := linkedca.ConfigTemplate_Type_value[strings.ToUpper(string(t.Type))]
			if !ok {
				return nil, errors.Errorf("unsupported template type %s", t.Type)
			}
			c.Templates.Ssh.Hosts = append(c.Templates.Ssh.Hosts, &linkedca.ConfigTemplate{
				Type:     linkedca.ConfigTemplate_Type(typ),
				Name:     t.Name,
				Template: mustReadFileOrURI(t.TemplatePath, files),
				Path:     t.Path,
				Comment:  t.Comment,
				Requires: t.RequiredData,
				Content:  t.Content,
			})
		}
		for _, t := range v.SSH.User {
			typ, ok := linkedca.ConfigTemplate_Type_value[strings.ToUpper(string(t.Type))]
			if !ok {
				return nil, errors.Errorf("unsupported template type %s", t.Type)
			}
			c.Templates.Ssh.Users = append(c.Templates.Ssh.Users, &linkedca.ConfigTemplate{
				Type:     linkedca.ConfigTemplate_Type(typ),
				Name:     t.Name,
				Template: mustReadFileOrURI(t.TemplatePath, files),
				Path:     t.Path,
				Comment:  t.Comment,
				Requires: t.RequiredData,
				Content:  t.Content,
			})
		}
	}

	return c, nil
}

func mustDuration(d *provisioner.Duration) string {
	if d == nil || d.Duration == 0 {
		return ""
	}
	return d.String()
}

func mustMarshalToStruct(v interface{}) *structpb.Struct {
	b, err := json.Marshal(v)
	if err != nil {
		panic(errors.Wrapf(err, "error marshaling %T", v))
	}
	var r *structpb.Struct
	if err := json.Unmarshal(b, &r); err != nil {
		panic(errors.Wrapf(err, "error unmarshaling %T", v))
	}
	return r
}

func mustReadFileOrURI(fn string, m map[string][]byte) string {
	if fn == "" {
		return ""
	}

	stepPath := filepath.ToSlash(step.Path())
	if !strings.HasSuffix(stepPath, "/") {
		stepPath += "/"
	}

	fn = strings.TrimPrefix(filepath.ToSlash(fn), stepPath)

	ok, err := isFilename(fn)
	if err != nil {
		panic(err)
	}
	if ok {
		b, err := os.ReadFile(step.Abs(fn))
		if err != nil {
			panic(errors.Wrapf(err, "error reading %s", fn))
		}
		m[fn] = b
		return fn
	}
	return fn
}

func mustReadFilesOrURIs(fns []string, m map[string][]byte) []string {
	var result []string
	for _, fn := range fns {
		result = append(result, mustReadFileOrURI(fn, m))
	}
	return result
}

func isFilename(fn string) (bool, error) {
	u, err := url.Parse(fn)
	if err != nil {
		return false, errors.Wrapf(err, "error parsing %s", fn)
	}
	return u.Scheme == "" || u.Scheme == "file", nil
}
