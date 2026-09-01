package metrix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func Test_sshCertValues(t *testing.T) {
	tests := []struct {
		name string
		cert *ssh.Certificate
		want []string
	}{
		{"user", &ssh.Certificate{CertType: ssh.UserCert}, []string{"user"}},
		{"host", &ssh.Certificate{CertType: ssh.HostCert}, []string{"host"}},
		{"host", &ssh.Certificate{CertType: 100}, []string{"unknown"}},
		{"nil", nil, []string{"unknown"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sshCertValues(tt.cert)
			assert.Equal(t, tt.want, got)
		})
	}
}
