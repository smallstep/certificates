package gcp

import (
	"context"
	"testing"
)

func TestProjectValidator(t *testing.T) {
	validator := &ProjectValidator{ProjectIDs: []string{"allowed-1", "allowed-2"}}

	if err := validator.ValidateProject(context.Background(), "not-allowed"); err == nil {
		t.Errorf("ProjectValidator.ValidateProject() = nil, want err")
	}

	if err := validator.ValidateProject(context.Background(), "allowed-2"); err != nil {
		t.Errorf("ProjectValidator.ValidateProject() = %v, want nil", err)
	}
}
