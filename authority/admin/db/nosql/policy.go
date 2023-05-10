package nosql

import (
	"context"
	"encoding/json"
	"fmt"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/nosql"
)

type dbX509Policy struct {
	Allow              *dbX509Names `json:"allow,omitempty"`
	Deny               *dbX509Names `json:"deny,omitempty"`
	AllowWildcardNames bool         `json:"allow_wildcard_names,omitempty"`
}

type dbX509Names struct {
	CommonNames    []string `json:"cn,omitempty"`
	DNSDomains     []string `json:"dns,omitempty"`
	IPRanges       []string `json:"ip,omitempty"`
	EmailAddresses []string `json:"email,omitempty"`
	URIDomains     []string `json:"uri,omitempty"`
}

type dbSSHPolicy struct {
	// User contains SSH user certificate options.
	User *dbSSHUserPolicy `json:"user,omitempty"`
	// Host contains SSH host certificate options.
	Host *dbSSHHostPolicy `json:"host,omitempty"`
}

type dbSSHHostPolicy struct {
	Allow *dbSSHHostNames `json:"allow,omitempty"`
	Deny  *dbSSHHostNames `json:"deny,omitempty"`
}

type dbSSHHostNames struct {
	DNSDomains []string `json:"dns,omitempty"`
	IPRanges   []string `json:"ip,omitempty"`
	Principals []string `json:"principal,omitempty"`
}

type dbSSHUserPolicy struct {
	Allow *dbSSHUserNames `json:"allow,omitempty"`
	Deny  *dbSSHUserNames `json:"deny,omitempty"`
}

type dbSSHUserNames struct {
	EmailAddresses []string `json:"email,omitempty"`
	Principals     []string `json:"principal,omitempty"`
}

type dbPolicy struct {
	X509 *dbX509Policy `json:"x509,omitempty"`
	SSH  *dbSSHPolicy  `json:"ssh,omitempty"`
}

type dbAuthorityPolicy struct {
	ID          string    `json:"id"`
	AuthorityID string    `json:"authorityID"`
	Policy      *dbPolicy `json:"policy,omitempty"`
}

func (dbap *dbAuthorityPolicy) convert() *linkedca.Policy {
	if dbap == nil {
		return nil
	}
	return dbToLinked(dbap.Policy)
}

func (db *DB) getDBAuthorityPolicyBytes(_ context.Context, authorityID string) ([]byte, error) {
	data, err := db.db.Get(authorityPoliciesTable, []byte(authorityID))
	if nosql.IsErrNotFound(err) {
		return nil, admin.NewError(admin.ErrorNotFoundType, "authority policy not found")
	} else if err != nil {
		return nil, fmt.Errorf("error loading authority policy: %w", err)
	}
	return data, nil
}

func (db *DB) unmarshalDBAuthorityPolicy(data []byte) (*dbAuthorityPolicy, error) {
	if len(data) == 0 {
		//nolint:nilnil // legacy
		return nil, nil
	}
	var dba = new(dbAuthorityPolicy)
	if err := json.Unmarshal(data, dba); err != nil {
		return nil, fmt.Errorf("error unmarshaling policy bytes into dbAuthorityPolicy: %w", err)
	}
	return dba, nil
}

func (db *DB) getDBAuthorityPolicy(ctx context.Context, authorityID string) (*dbAuthorityPolicy, error) {
	data, err := db.getDBAuthorityPolicyBytes(ctx, authorityID)
	if err != nil {
		return nil, err
	}
	dbap, err := db.unmarshalDBAuthorityPolicy(data)
	if err != nil {
		return nil, err
	}
	if dbap == nil {
		//nolint:nilnil // legacy
		return nil, nil
	}
	if dbap.AuthorityID != authorityID {
		return nil, admin.NewError(admin.ErrorAuthorityMismatchType,
			"authority policy is not owned by authority %s", authorityID)
	}
	return dbap, nil
}

func (db *DB) CreateAuthorityPolicy(ctx context.Context, policy *linkedca.Policy) error {
	dbap := &dbAuthorityPolicy{
		ID:          db.authorityID,
		AuthorityID: db.authorityID,
		Policy:      linkedToDB(policy),
	}

	if err := db.save(ctx, dbap.ID, dbap, nil, "authority_policy", authorityPoliciesTable); err != nil {
		return admin.WrapErrorISE(err, "error creating authority policy")
	}

	return nil
}

func (db *DB) GetAuthorityPolicy(ctx context.Context) (*linkedca.Policy, error) {
	dbap, err := db.getDBAuthorityPolicy(ctx, db.authorityID)
	if err != nil {
		return nil, err
	}

	return dbap.convert(), nil
}

func (db *DB) UpdateAuthorityPolicy(ctx context.Context, policy *linkedca.Policy) error {
	old, err := db.getDBAuthorityPolicy(ctx, db.authorityID)
	if err != nil {
		return err
	}

	dbap := &dbAuthorityPolicy{
		ID:          db.authorityID,
		AuthorityID: db.authorityID,
		Policy:      linkedToDB(policy),
	}

	if err := db.save(ctx, dbap.ID, dbap, old, "authority_policy", authorityPoliciesTable); err != nil {
		return admin.WrapErrorISE(err, "error updating authority policy")
	}

	return nil
}

func (db *DB) DeleteAuthorityPolicy(ctx context.Context) error {
	old, err := db.getDBAuthorityPolicy(ctx, db.authorityID)
	if err != nil {
		return err
	}

	if err := db.save(ctx, old.ID, nil, old, "authority_policy", authorityPoliciesTable); err != nil {
		return admin.WrapErrorISE(err, "error deleting authority policy")
	}

	return nil
}

func dbToLinked(p *dbPolicy) *linkedca.Policy {
	if p == nil {
		return nil
	}
	r := &linkedca.Policy{}
	if x509 := p.X509; x509 != nil {
		r.X509 = &linkedca.X509Policy{}
		if allow := x509.Allow; allow != nil {
			r.X509.Allow = &linkedca.X509Names{}
			r.X509.Allow.Dns = allow.DNSDomains
			r.X509.Allow.Emails = allow.EmailAddresses
			r.X509.Allow.Ips = allow.IPRanges
			r.X509.Allow.Uris = allow.URIDomains
			r.X509.Allow.CommonNames = allow.CommonNames
		}
		if deny := x509.Deny; deny != nil {
			r.X509.Deny = &linkedca.X509Names{}
			r.X509.Deny.Dns = deny.DNSDomains
			r.X509.Deny.Emails = deny.EmailAddresses
			r.X509.Deny.Ips = deny.IPRanges
			r.X509.Deny.Uris = deny.URIDomains
			r.X509.Deny.CommonNames = deny.CommonNames
		}
		r.X509.AllowWildcardNames = x509.AllowWildcardNames
	}
	if ssh := p.SSH; ssh != nil {
		r.Ssh = &linkedca.SSHPolicy{}
		if host := ssh.Host; host != nil {
			r.Ssh.Host = &linkedca.SSHHostPolicy{}
			if allow := host.Allow; allow != nil {
				r.Ssh.Host.Allow = &linkedca.SSHHostNames{}
				r.Ssh.Host.Allow.Dns = allow.DNSDomains
				r.Ssh.Host.Allow.Ips = allow.IPRanges
				r.Ssh.Host.Allow.Principals = allow.Principals
			}
			if deny := host.Deny; deny != nil {
				r.Ssh.Host.Deny = &linkedca.SSHHostNames{}
				r.Ssh.Host.Deny.Dns = deny.DNSDomains
				r.Ssh.Host.Deny.Ips = deny.IPRanges
				r.Ssh.Host.Deny.Principals = deny.Principals
			}
		}
		if user := ssh.User; user != nil {
			r.Ssh.User = &linkedca.SSHUserPolicy{}
			if allow := user.Allow; allow != nil {
				r.Ssh.User.Allow = &linkedca.SSHUserNames{}
				r.Ssh.User.Allow.Emails = allow.EmailAddresses
				r.Ssh.User.Allow.Principals = allow.Principals
			}
			if deny := user.Deny; deny != nil {
				r.Ssh.User.Deny = &linkedca.SSHUserNames{}
				r.Ssh.User.Deny.Emails = deny.EmailAddresses
				r.Ssh.User.Deny.Principals = deny.Principals
			}
		}
	}

	return r
}

func linkedToDB(p *linkedca.Policy) *dbPolicy {
	if p == nil {
		return nil
	}

	// return early if x509 nor SSH is set
	if p.GetX509() == nil && p.GetSsh() == nil {
		return nil
	}

	r := &dbPolicy{}
	// fill x509 policy configuration
	if x509 := p.GetX509(); x509 != nil {
		r.X509 = &dbX509Policy{}
		if allow := x509.GetAllow(); allow != nil {
			r.X509.Allow = &dbX509Names{}
			if allow.Dns != nil {
				r.X509.Allow.DNSDomains = allow.Dns
			}
			if allow.Ips != nil {
				r.X509.Allow.IPRanges = allow.Ips
			}
			if allow.Emails != nil {
				r.X509.Allow.EmailAddresses = allow.Emails
			}
			if allow.Uris != nil {
				r.X509.Allow.URIDomains = allow.Uris
			}
			if allow.CommonNames != nil {
				r.X509.Allow.CommonNames = allow.CommonNames
			}
		}
		if deny := x509.GetDeny(); deny != nil {
			r.X509.Deny = &dbX509Names{}
			if deny.Dns != nil {
				r.X509.Deny.DNSDomains = deny.Dns
			}
			if deny.Ips != nil {
				r.X509.Deny.IPRanges = deny.Ips
			}
			if deny.Emails != nil {
				r.X509.Deny.EmailAddresses = deny.Emails
			}
			if deny.Uris != nil {
				r.X509.Deny.URIDomains = deny.Uris
			}
			if deny.CommonNames != nil {
				r.X509.Deny.CommonNames = deny.CommonNames
			}
		}

		r.X509.AllowWildcardNames = x509.GetAllowWildcardNames()
	}

	// fill ssh policy configuration
	if ssh := p.GetSsh(); ssh != nil {
		r.SSH = &dbSSHPolicy{}
		if host := ssh.GetHost(); host != nil {
			r.SSH.Host = &dbSSHHostPolicy{}
			if allow := host.GetAllow(); allow != nil {
				r.SSH.Host.Allow = &dbSSHHostNames{}
				if allow.Dns != nil {
					r.SSH.Host.Allow.DNSDomains = allow.Dns
				}
				if allow.Ips != nil {
					r.SSH.Host.Allow.IPRanges = allow.Ips
				}
				if allow.Principals != nil {
					r.SSH.Host.Allow.Principals = allow.Principals
				}
			}
			if deny := host.GetDeny(); deny != nil {
				r.SSH.Host.Deny = &dbSSHHostNames{}
				if deny.Dns != nil {
					r.SSH.Host.Deny.DNSDomains = deny.Dns
				}
				if deny.Ips != nil {
					r.SSH.Host.Deny.IPRanges = deny.Ips
				}
				if deny.Principals != nil {
					r.SSH.Host.Deny.Principals = deny.Principals
				}
			}
		}
		if user := ssh.GetUser(); user != nil {
			r.SSH.User = &dbSSHUserPolicy{}
			if allow := user.GetAllow(); allow != nil {
				r.SSH.User.Allow = &dbSSHUserNames{}
				if allow.Emails != nil {
					r.SSH.User.Allow.EmailAddresses = allow.Emails
				}
				if allow.Principals != nil {
					r.SSH.User.Allow.Principals = allow.Principals
				}
			}
			if deny := user.GetDeny(); deny != nil {
				r.SSH.User.Deny = &dbSSHUserNames{}
				if deny.Emails != nil {
					r.SSH.User.Deny.EmailAddresses = deny.Emails
				}
				if deny.Principals != nil {
					r.SSH.User.Deny.Principals = deny.Principals
				}
			}
		}
	}

	return r
}
