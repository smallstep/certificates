package nosql

import (
	"context"
	"encoding/json"
	"fmt"

	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/nosql"
)

type dbAuthorityPolicy struct {
	ID          string           `json:"id"`
	AuthorityID string           `json:"authorityID"`
	Policy      *linkedca.Policy `json:"policy"`
}

func (dbap *dbAuthorityPolicy) convert() *linkedca.Policy {
	if dbap == nil {
		return nil
	}
	return dbap.Policy
}

func (db *DB) getDBAuthorityPolicyBytes(ctx context.Context, authorityID string) ([]byte, error) {
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
		Policy:      policy,
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
		Policy:      policy,
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
