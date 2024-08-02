package acme

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
)

func TestIsErrNotFound(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"true ErrNotFound", args{ErrNotFound}, true},
		{"true sql.ErrNoRows", args{sql.ErrNoRows}, true},
		{"true wrapped ErrNotFound", args{fmt.Errorf("something failed: %w", ErrNotFound)}, true},
		{"true wrapped sql.ErrNoRows", args{fmt.Errorf("something failed: %w", sql.ErrNoRows)}, true},
		{"false other", args{errors.New("not found")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsErrNotFound(tt.args.err); got != tt.want {
				t.Errorf("IsErrNotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}
