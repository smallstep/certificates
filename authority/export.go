package authority

import (
	"encoding/json"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	step "go.step.sm/cli-utils/config"
	"go.step.sm/linkedca/config"
	"google.golang.org/protobuf/types/known/structpb"
)

func (a *Authority) Export() (c *config.Configuration, err error) {
	// Recover from panics
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	c = &config.Configuration{
		Root:            mustReadFilesOrUris(a.config.Root),
		FederatedRoots:  mustReadFilesOrUris(a.config.FederatedRoots),
		Intermediate:    mustReadFileOrUri(a.config.IntermediateCert),
		IntermediateKey: mustReadFileOrUri(a.config.IntermediateKey),
		Address:         a.config.Address,
		InsecureAddress: a.config.InsecureAddress,
		DnsNames:        a.config.DNSNames,
		Db:              mustMarshalToStruct(a.config.DB),
		Logger:          mustMarshalToStruct(a.config.Logger),
		Monitoring:      mustMarshalToStruct(a.config.Monitoring),
		Authority:       &config.Authority{},
		Password:        mustPassword(a.config.Password),
	}

	// SSH
	if v := a.config.SSH; v != nil {
		c.Ssh = &config.SSH{
			HostKey:          mustReadFileOrUri(v.HostKey),
			UserKey:          mustReadFileOrUri(v.UserKey),
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
	c.Authority.Id = a.config.AuthorityConfig.AuthorityID

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
			c.Authority.CertificateIssuer = &config.CertificateIssuer{
				Type:        config.CertificateIssuer_Type(typ),
				Provisioner: iss.Provisioner,
				Certificate: mustReadFileOrUri(iss.Certificate),
				Key:         mustReadFileOrUri(iss.Key),
				Password:    mustPassword(iss.Password),
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
	c.Authority.Claims = claimsToLinkedca(a.config.AuthorityConfig.Claims)

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
			content := t.Content
			if len(content) == 0 {
				content = mustReadFileOrUri(t.TemplatePath)
			}
			c.Templates.Ssh.Hosts = append(c.Templates.Ssh.Hosts, &config.Template{
				Type:     config.Template_Type(typ),
				Name:     t.Name,
				Template: t.TemplatePath,
				Path:     t.Path,
				Comment:  t.Comment,
				Requires: t.RequiredData,
				Content:  content,
			})
		}
		for _, t := range v.SSH.User {
			typ, ok := config.Template_Type_value[strings.ToUpper(string(t.Type))]
			if !ok {
				return nil, errors.Errorf("unsupported template type %s", t.Type)
			}
			content := t.Content
			if len(content) == 0 {
				content = mustReadFileOrUri(t.TemplatePath)
			}
			c.Templates.Ssh.Users = append(c.Templates.Ssh.Users, &config.Template{
				Type:     config.Template_Type(typ),
				Name:     t.Name,
				Template: t.TemplatePath,
				Path:     t.Path,
				Comment:  t.Comment,
				Requires: t.RequiredData,
				Content:  content,
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

func mustReadFileOrUri(fn string) []byte {
	if fn == "" {
		return nil
	}

	ok, err := isFilename(fn)
	if err != nil {
		panic(err)
	}
	if ok {
		b, err := ioutil.ReadFile(step.StepAbs(fn))
		if err != nil {
			panic(errors.Wrapf(err, "error reading %s", fn))
		}
		return b
	}
	return []byte(fn)
}

func mustReadFilesOrUris(fns []string) [][]byte {
	var result [][]byte
	for _, fn := range fns {
		result = append(result, mustReadFileOrUri(fn))
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
