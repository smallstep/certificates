package provisioner

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestClaimer_DefaultSSHCertDuration(t *testing.T) {
	duration := Duration{
		Duration: time.Hour,
	}
	type fields struct {
		global Claims
		claims *Claims
	}
	type args struct {
		certType uint32
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    time.Duration
		wantErr bool
	}{
		{"user", fields{globalProvisionerClaims, &Claims{DefaultUserSSHDur: &duration}}, args{1}, time.Hour, false},
		{"user global", fields{globalProvisionerClaims, nil}, args{ssh.UserCert}, 16 * time.Hour, false},
		{"host global", fields{globalProvisionerClaims, &Claims{DefaultHostSSHDur: &duration}}, args{2}, time.Hour, false},
		{"host global", fields{globalProvisionerClaims, nil}, args{ssh.HostCert}, 30 * 24 * time.Hour, false},
		{"invalid", fields{globalProvisionerClaims, nil}, args{0}, 0, true},
		{"invalid global", fields{globalProvisionerClaims, nil}, args{3}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Claimer{
				global: tt.fields.global,
				claims: tt.fields.claims,
			}
			got, err := c.DefaultSSHCertDuration(tt.args.certType)
			if (err != nil) != tt.wantErr {
				t.Errorf("Claimer.DefaultSSHCertDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Claimer.DefaultSSHCertDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}
