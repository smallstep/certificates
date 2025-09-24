package gcp

import (
	"context"
	"net/http"

	"google.golang.org/api/cloudresourcemanager/v1"

	"github.com/smallstep/certificates/errs"
)

type ProjectValidator struct {
	ProjectIDs []string
}

func (p *ProjectValidator) ValidateProject(_ context.Context, projectID string) error {
	if len(p.ProjectIDs) == 0 {
		return nil
	}

	for _, pi := range p.ProjectIDs {
		if pi == projectID {
			return nil
		}
	}

	return errs.Unauthorized("gcp.authorizeToken; invalid gcp token - invalid project id")
}

type OrganizationValidator struct {
	*ProjectValidator
	OrganizationID  string
	projectsService *cloudresourcemanager.ProjectsService
}

func NewOrganizationValidator(projectIDs []string, organizationID string) (*OrganizationValidator, error) {
	var svc *cloudresourcemanager.ProjectsService

	if organizationID != "" {
		crm, err := cloudresourcemanager.NewService(context.Background())
		if err != nil {
			return nil, err
		}

		svc = crm.Projects
	}

	return &OrganizationValidator{
		ProjectValidator: &ProjectValidator{projectIDs},
		OrganizationID:   organizationID,
		projectsService:  svc,
	}, nil
}

func (p *OrganizationValidator) ValidateProject(ctx context.Context, projectID string) error {
	if err := p.ProjectValidator.ValidateProject(ctx, projectID); err != nil {
		return err
	}

	if p.OrganizationID == "" {
		return nil
	}

	ancestry, err := p.projectsService.
		GetAncestry(projectID, &cloudresourcemanager.GetAncestryRequest{}).
		Context(ctx).
		Do()

	if err != nil {
		return errs.Wrap(http.StatusInternalServerError, err, "gcp.authorizeToken")
	}

	if len(ancestry.Ancestor) < 1 {
		return errs.InternalServer("gcp.authorizeToken; getAncestry response malformed")
	}

	progenitor := ancestry.Ancestor[len(ancestry.Ancestor)-1]

	if progenitor.ResourceId.Type != "organization" || progenitor.ResourceId.Id != p.OrganizationID {
		return errs.Unauthorized("gcp.authorizeToken; invalid gcp token - project does not belong to organization")
	}

	return nil
}
