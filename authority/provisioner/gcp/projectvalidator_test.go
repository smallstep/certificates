package gcp

import (
	"context"
	"testing"
	"time"

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

func TestOrganizationValidator_ValidateProject_NetworkErrors(t *testing.T) {
	// Test network timeout scenarios
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	validator := &OrganizationValidator{
		ProjectValidator: &ProjectValidator{ProjectIDs: []string{"test-project"}},
		OrganizationID:   "test-org",
	}

	err := validator.ValidateProject(ctx, "test-project")
	assert.Error(t, err)
}

func TestOrganizationValidator_ValidateProject_EmptyOrganization(t *testing.T) {
	validator := &OrganizationValidator{
		ProjectValidator: &ProjectValidator{ProjectIDs: []string{"test-project"}},
		OrganizationID:   "", // Empty org ID
	}

	err := validator.ValidateProject(context.Background(), "test-project")
	assert.NoError(t, err) // Should pass when org ID is empty
}

func TestOrganizationValidator_ValidateProject_InvalidProject(t *testing.T) {
	validator := &OrganizationValidator{
		ProjectValidator: &ProjectValidator{ProjectIDs: []string{"allowed-project"}},
		OrganizationID:   "test-org",
	}

	err := validator.ValidateProject(context.Background(), "forbidden-project")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid project id")
}

func TestProjectValidator_ValidateProject_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		projectIDs []string
		testID     string
		wantError  bool
	}{
		{"empty project list allows all", []string{}, "any-project", false},
		{"nil project list allows all", nil, "any-project", false},
		{"exact match case sensitive", []string{"Project-1"}, "project-1", true},
		{"exact match case sensitive success", []string{"project-1"}, "project-1", false},
		{"empty string in list", []string{""}, "", false},
		{"empty string in list wrong project", []string{""}, "project", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &ProjectValidator{ProjectIDs: tt.projectIDs}
			err := validator.ValidateProject(context.Background(), tt.testID)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOrganizationValidator_ValidateProject_MalformedResponse(t *testing.T) {
	// This test requires mocking the cloudresourcemanager service
	// but will help cover the ancestry validation logic
	validator := &OrganizationValidator{
		ProjectValidator: &ProjectValidator{ProjectIDs: []string{"test-project"}},
		OrganizationID:   "test-org",
	}

	// Test with context that will cause the service to fail gracefully
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately to trigger error

	err := validator.ValidateProject(ctx, "test-project")
	assert.Error(t, err)
}

func TestOrganizationValidator_ValidateProject_WrongOrganization(t *testing.T) {
	// Skip if no GCP credentials available
	ctx := context.Background()
	_, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		t.Skip("Skipping GCP integration test - no credentials")
	}

	validator := &OrganizationValidator{
		ProjectValidator: &ProjectValidator{ProjectIDs: []string{"fake-project"}},
		OrganizationID:   "wrong-organization-id",
	}

	// This should fail because the project doesn't exist
	err = validator.ValidateProject(ctx, "fake-project")
	assert.Error(t, err)
}

// TestOrganizationValidator_AdditionalEdgeCases tests additional edge cases for better coverage
func TestOrganizationValidator_AdditionalEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("empty organization ID allows any organization", func(t *testing.T) {
		validator := &OrganizationValidator{
			ProjectValidator: &ProjectValidator{ProjectIDs: []string{"test-project"}},
			OrganizationID:   "", // Empty org ID should allow any organization
		}

		// Skip if no GCP credentials available
		_, err := cloudresourcemanager.NewService(ctx)
		if err != nil {
			t.Skip("Skipping GCP integration test - no credentials")
		}

		// Since organization ID is empty, this should not validate organization
		err = validator.ValidateProject(ctx, "test-project")
		// We expect this to fail because the project doesn't exist, not because of org validation
		assert.Error(t, err)
	})

	t.Run("project ID case sensitivity validation", func(t *testing.T) {
		validator := &OrganizationValidator{
			ProjectValidator: &ProjectValidator{ProjectIDs: []string{"Test-Project-123"}}, // Different case
			OrganizationID:   "test-org",
		}

		// Skip if no GCP credentials available
		_, err := cloudresourcemanager.NewService(ctx)
		if err != nil {
			t.Skip("Skipping GCP integration test - no credentials")
		}

		// This should fail because "test-project-123" is not in the allowed list (case sensitive)
		err = validator.ValidateProject(ctx, "test-project-123")
		assert.Error(t, err, "Case-sensitive project ID validation should fail")
	})

	t.Run("timeout context cancellation", func(t *testing.T) {
		validator := &OrganizationValidator{
			ProjectValidator: &ProjectValidator{ProjectIDs: []string{"test-project"}},
			OrganizationID:   "test-org",
		}

		// Create a context that times out immediately
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(1 * time.Millisecond) // Ensure context is canceled

		err := validator.ValidateProject(ctx, "test-project")
		assert.Error(t, err, "Canceled context should cause validation to fail")
	})
}