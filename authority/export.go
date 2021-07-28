package authority

import (
	"encoding/json"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	step "go.step.sm/cli-utils/config"
	"go.step.sm/linkedca/config"
	"google.golang.org/protobuf/types/known/structpb"
)

// Export creates a linkedca configuration form the current ca.json and loaded
// authorities.
//
// Note that export will not export neither the pki password nor the certificate
// issuer password.
func (a *Authority) Export() (c *config.Configuration, err error) {
	// Recover from panics
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	files := make(map[string][]byte)

	// The exported configuration should not include the password in it.
	c = &config.Configuration{
		Version:         "1.0",
		Root:            mustReadFilesOrUris(a.config.Root, files),
		FederatedRoots:  mustReadFilesOrUris(a.config.FederatedRoots, files),
		Intermediate:    mustReadFileOrUri(a.config.IntermediateCert, files),
		IntermediateKey: mustReadFileOrUri(a.config.IntermediateKey, files),
		Address:         a.config.Address,
		InsecureAddress: a.config.InsecureAddress,
		DnsNames:        a.config.DNSNames,
		Db:              mustMarshalToStruct(a.config.DB),
		Logger:          mustMarshalToStruct(a.config.Logger),
		Monitoring:      mustMarshalToStruct(a.config.Monitoring),
		Authority: &config.Authority{
			Id:                   a.config.AuthorityConfig.AuthorityID,
			EnableAdmin:          a.config.AuthorityConfig.EnableAdmin,
			DisableIssuedAtCheck: a.config.AuthorityConfig.DisableIssuedAtCheck,
			Backdate:             a.config.AuthorityConfig.Backdate.String(),
		},
		Files: files,
	}

	// SSH
	if v := a.config.SSH; v != nil {
		c.Ssh = &config.SSH{
			HostKey:          mustReadFileOrUri(v.HostKey, files),
			UserKey:          mustReadFileOrUri(v.UserKey, files),
			AddUserPrincipal: v.AddUserPrincipal,
			AddUserCommand:   v.AddUserCommand,
		}
		for _, k := range v.Keys {
			typ, ok := config.SSHPublicKey_Type_value[strings.ToUpper(k.Type)]
			if !ok {
				return nil, errors.Errorf("unsupported ssh key type %s", k.Type)
			}
			c.Ssh.Keys = append(c.Ssh.Keys, &config.SSHPublicKey{
				Type:      config.SSHPublicKey_Type(typ),
				Federated: k.Federated,
				Key:       mustMarshalToStruct(k),
			})
		}
		if b := v.Bastion; b != nil {
			c.Ssh.Bastion = &config.Bastion{
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
			typ = int32(config.KMS_SOFTKMS)
		} else {
			typ, ok = config.KMS_Type_value[strings.ToUpper(v.Type)]
			if !ok {
				return nil, errors.Errorf("unsupported kms type %s", v.Type)
			}
		}
		c.Kms = &config.KMS{
			Type:            config.KMS_Type(typ),
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
			typ, ok := config.CertificateIssuer_Type_value[strings.ToUpper(iss.Type)]
			if !ok {
				return nil, errors.Errorf("unknown certificate issuer type %s", iss.Type)
			}
			// The exporte certificate issuer should not include the password.
			c.Authority.CertificateIssuer = &config.CertificateIssuer{
				Type:        config.CertificateIssuer_Type(typ),
				Provisioner: iss.Provisioner,
				Certificate: mustReadFileOrUri(iss.Certificate, files),
				Key:         mustReadFileOrUri(iss.Key, files),
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
	// Distiguised names template
	if v := a.config.AuthorityConfig.Template; v != nil {
		c.Authority.Template = &config.DistinguishedName{
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
		c.Tls = &config.TLS{
			MinVersion:    v.MinVersion.String(),
			MaxVersion:    v.MaxVersion.String(),
			Renegotiation: v.Renegotiation,
		}
		for _, cs := range v.CipherSuites.Value() {
			c.Tls.CipherSuites = append(c.Tls.CipherSuites, config.TLS_CiperSuite(cs))
		}
	}

	// Templates
	if v := a.config.Templates; v != nil {
		c.Templates = &config.Templates{
			Ssh:  &config.SSHTemplate{},
			Data: mustMarshalToStruct(v.Data),
		}
		// Remove automatically loaded vars
		if c.Templates.Data != nil && c.Templates.Data.Fields != nil {
			delete(c.Templates.Data.Fields, "Step")
		}
		for _, t := range v.SSH.Host {
			typ, ok := config.Template_Type_value[strings.ToUpper(string(t.Type))]
			if !ok {
				return nil, errors.Errorf("unsupported template type %s", t.Type)
			}
			c.Templates.Ssh.Hosts = append(c.Templates.Ssh.Hosts, &config.Template{
				Type:     config.Template_Type(typ),
				Name:     t.Name,
				Template: mustReadFileOrUri(t.TemplatePath, files),
				Path:     t.Path,
				Comment:  t.Comment,
				Requires: t.RequiredData,
				Content:  t.Content,
			})
		}
		for _, t := range v.SSH.User {
			typ, ok := config.Template_Type_value[strings.ToUpper(string(t.Type))]
			if !ok {
				return nil, errors.Errorf("unsupported template type %s", t.Type)
			}
			c.Templates.Ssh.Users = append(c.Templates.Ssh.Users, &config.Template{
				Type:     config.Template_Type(typ),
				Name:     t.Name,
				Template: mustReadFileOrUri(t.TemplatePath, files),
				Path:     t.Path,
				Comment:  t.Comment,
				Requires: t.RequiredData,
				Content:  t.Content,
			})
		}
	}

	return c, nil
}

func mustPassword(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
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

func mustReadFileOrUri(fn string, m map[string][]byte) string {
	if fn == "" {
		return ""
	}

	stepPath := filepath.ToSlash(step.StepPath())
	if !strings.HasSuffix(stepPath, "/") {
		stepPath += "/"
	}

	fn = strings.TrimPrefix(filepath.ToSlash(fn), stepPath)

	ok, err := isFilename(fn)
	if err != nil {
		panic(err)
	}
	if ok {
		b, err := ioutil.ReadFile(step.StepAbs(fn))
		if err != nil {
			panic(errors.Wrapf(err, "error reading %s", fn))
		}
		m[fn] = b
		return fn
	}
	return fn
}

func mustReadFilesOrUris(fns []string, m map[string][]byte) []string {
	var result []string
	for _, fn := range fns {
		result = append(result, mustReadFileOrUri(fn, m))
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
