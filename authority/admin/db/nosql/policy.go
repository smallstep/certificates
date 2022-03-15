package nosql

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/nosql"
	"go.step.sm/linkedca"
)

type dbAuthorityPolicy struct {
	ID          string           `json:"id"`
	AuthorityID string           `json:"authorityID"`
	Policy      *linkedca.Policy `json:"policy"`
}

func (dbap *dbAuthorityPolicy) convert() *linkedca.Policy {
	return dbap.Policy
}

func (dbap *dbAuthorityPolicy) clone() *dbAuthorityPolicy {
	u := *dbap
	return &u
}

func (db *DB) getDBAuthorityPolicyBytes(ctx context.Context, authorityID string) ([]byte, error) {
	data, err := db.db.Get(authorityPoliciesTable, []byte(authorityID))
	if nosql.IsErrNotFound(err) {
		return nil, admin.NewError(admin.ErrorNotFoundType, "policy %s not found", authorityID)
	} else if err != nil {
		return nil, errors.Wrapf(err, "error loading admin %s", authorityID)
	}
	return data, nil
}

func (db *DB) unmarshalDBAuthorityPolicy(data []byte, authorityID string) (*dbAuthorityPolicy, error) {
	var dba = new(dbAuthorityPolicy)
	if err := json.Unmarshal(data, dba); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling admin %s into dbAdmin", authorityID)
	}
	// if !dba.DeletedAt.IsZero() {
	// 	return nil, admin.NewError(admin.ErrorDeletedType, "admin %s is deleted", authorityID)
	// }
	if dba.AuthorityID != db.authorityID {
		return nil, admin.NewError(admin.ErrorAuthorityMismatchType,
			"admin %s is not owned by authority %s", dba.ID, db.authorityID)
	}
	return dba, nil
}

func (db *DB) getDBAuthorityPolicy(ctx context.Context, authorityID string) (*dbAuthorityPolicy, error) {
	data, err := db.getDBAuthorityPolicyBytes(ctx, authorityID)
	if err != nil {
		return nil, err
	}
	dbap, err := db.unmarshalDBAuthorityPolicy(data, authorityID)
	if err != nil {
		return nil, err
	}
	return dbap, nil
}

func (db *DB) unmarshalAuthorityPolicy(data []byte, authorityID string) (*linkedca.Policy, error) {
	dbap, err := db.unmarshalDBAuthorityPolicy(data, authorityID)
	if err != nil {
		return nil, err
	}
	return dbap.convert(), nil
}

func (db *DB) CreateAuthorityPolicy(ctx context.Context, policy *linkedca.Policy) error {

	dbap := &dbAuthorityPolicy{
		ID:          db.authorityID,
		AuthorityID: db.authorityID,
		Policy:      policy,
	}

	old, err := db.getDBAuthorityPolicy(ctx, db.authorityID)
	if err != nil {
		return err
	}

	return db.save(ctx, dbap.ID, dbap, old, "authority_policy", authorityPoliciesTable)
}

func (db *DB) GetAuthorityPolicy(ctx context.Context) (*linkedca.Policy, error) {
	// policy := &linkedca.Policy{
	// 	X509: &linkedca.X509Policy{
	// 		Allow: &linkedca.X509Names{
	// 			Dns: []string{".localhost"},
	// 		},
	// 		Deny: &linkedca.X509Names{
	// 			Dns: []string{"denied.localhost"},
	// 		},
	// 	},
	// 	Ssh: &linkedca.SSHPolicy{
	// 		User: &linkedca.SSHUserPolicy{
	// 			Allow: &linkedca.SSHUserNames{},
	// 			Deny:  &linkedca.SSHUserNames{},
	// 		},
	// 		Host: &linkedca.SSHHostPolicy{
	// 			Allow: &linkedca.SSHHostNames{},
	// 			Deny:  &linkedca.SSHHostNames{},
	// 		},
	// 	},
	// }

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
		Policy:      policy,
	}

	return db.save(ctx, dbap.ID, dbap, old, "authority_policy", authorityPoliciesTable)
}

func (db *DB) DeleteAuthorityPolicy(ctx context.Context) error {
	dbap, err := db.getDBAuthorityPolicy(ctx, db.authorityID)
	if err != nil {
		return err
	}
	old := dbap.clone()

	dbap.Policy = nil
	return db.save(ctx, dbap.ID, dbap, old, "authority_policy", authorityPoliciesTable)
}
