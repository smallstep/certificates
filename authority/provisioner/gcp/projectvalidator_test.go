package gcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/cloudresourcemanager/v1"
)

func TestProjectValidator_ValidateProject(t *testing.T) {
	ctx := context.Background()
	type fields struct {
		ProjectIDs []string
	}
	type args struct {
		in0       context.Context
		projectID string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"allowed-1", fields{[]string{"allowed-1", "allowed-2"}}, args{ctx, "allowed-1"}, assert.NoError},
		{"allowed-2", fields{[]string{"allowed-1", "allowed-2"}}, args{ctx, "allowed-2"}, assert.NoError},
		{"empty", fields{nil}, args{ctx, "allowed-1"}, assert.NoError},
		{"not allowed", fields{[]string{"allowed-1", "allowed-2"}}, args{ctx, "not-allowed"}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ProjectValidator{
				ProjectIDs: tt.fields.ProjectIDs,
			}
			tt.assertion(t, p.ValidateProject(tt.args.in0, tt.args.projectID))
		})
	}
}

func TestNewOrganizationValidator(t *testing.T) {
	got := NewOrganizationValidator([]string{"project-1", "project-2"}, "organization")
	assert.Equal(t, &OrganizationValidator{
		ProjectValidator: &ProjectValidator{ProjectIDs: []string{"project-1", "project-2"}},
		OrganizationID:   "organization",
	}, got)
}

func TestOrganizationValidator_ValidateProject(t *testing.T) {
	ctx := context.Background()
	_, err := cloudresourcemanager.NewService(ctx)
	skip := (err != nil)

	type fields struct {
		ProjectValidator *ProjectValidator
		OrganizationID   string
	}
	type args struct {
		ctx       context.Context
		projectID string
	}
	tests := []struct {
		name      string
		skip      bool
		fields    fields
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"ok projects", false, fields{&ProjectValidator{ProjectIDs: []string{"allowed"}}, ""}, args{ctx, "allowed"}, assert.NoError},
		{"fail projects", false, fields{&ProjectValidator{ProjectIDs: []string{"allowed"}}, "organization"}, args{ctx, "not-allowed"}, assert.Error},
		{"fail organization", skip, fields{&ProjectValidator{ProjectIDs: []string{"allowed"}}, "fake-organization"}, args{ctx, "allowed"}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OrganizationValidator{
				ProjectValidator: tt.fields.ProjectValidator,
				OrganizationID:   tt.fields.OrganizationID,
			}
			if tt.skip {
				t.SkipNow()
				return
			}
			tt.assertion(t, p.ValidateProject(tt.args.ctx, tt.args.projectID))
		})
	}
}
