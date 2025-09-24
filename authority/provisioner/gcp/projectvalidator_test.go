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
	ctx := context.Background()
	_, err := cloudresourcemanager.NewService(ctx)
	skip := (err != nil)

	type args struct {
		projectIDs     []string
		organizationID string
	}
	tests := []struct {
		name      string
		skip      bool
		args      args
		want      *OrganizationValidator
		assertion assert.ErrorAssertionFunc
	}{
		{"ok projects", false, args{[]string{"project-1", "project-2"}, ""}, &OrganizationValidator{
			ProjectValidator: &ProjectValidator{[]string{"project-1", "project-2"}},
		}, assert.NoError},
		{"ok organization", skip, args{[]string{}, "organization"}, &OrganizationValidator{
			ProjectValidator: &ProjectValidator{[]string{}},
			OrganizationID:   "organization",
			projectsService:  &cloudresourcemanager.ProjectsService{},
		}, assert.NoError},
		{"ok projects organization", skip, args{[]string{"project-1"}, "organization"}, &OrganizationValidator{
			ProjectValidator: &ProjectValidator{[]string{"project-1"}},
			OrganizationID:   "organization",
			projectsService:  &cloudresourcemanager.ProjectsService{},
		}, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.SkipNow()
				return
			}
			got, err := NewOrganizationValidator(tt.args.projectIDs, tt.args.organizationID)
			tt.assertion(t, err)
			assert.EqualExportedValues(t, tt.want, got)
		})
	}
}

func TestOrganizationValidator_ValidateProject(t *testing.T) {
	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx)
	skip := (err != nil)

	var projectsService *cloudresourcemanager.ProjectsService
	if !skip {
		projectsService = svc.Projects
	}

	type fields struct {
		ProjectValidator *ProjectValidator
		OrganizationID   string
		projectsService  *cloudresourcemanager.ProjectsService
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
		{"ok projects", false, fields{&ProjectValidator{ProjectIDs: []string{"allowed"}}, "", projectsService}, args{ctx, "allowed"}, assert.NoError},
		{"fail projects", false, fields{&ProjectValidator{ProjectIDs: []string{"allowed"}}, "organization", projectsService}, args{ctx, "not-allowed"}, assert.Error},
		{"fail organization", skip, fields{&ProjectValidator{ProjectIDs: []string{"allowed"}}, "fake-organization", projectsService}, args{ctx, "allowed"}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OrganizationValidator{
				ProjectValidator: tt.fields.ProjectValidator,
				OrganizationID:   tt.fields.OrganizationID,
				projectsService:  tt.fields.projectsService,
			}
			if tt.skip {
				t.SkipNow()
				return
			}
			tt.assertion(t, p.ValidateProject(tt.args.ctx, tt.args.projectID))
		})
	}
}
