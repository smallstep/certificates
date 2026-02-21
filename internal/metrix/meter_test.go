package metrix

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestMeter_Basic(t *testing.T) {
	// Test meter initialization
	meter := New()
	require.NotNil(t, meter)
	require.NotNil(t, meter.Handler)

	// Test that metrics endpoint works
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	meter.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Test basic operations
	mockProvisioner := &provisioner.JWK{Name: "test"}
	userCert := &ssh.Certificate{CertType: ssh.UserCert}
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "test"}}
	certs := []*x509.Certificate{cert}

	// Test all meter methods
	meter.SSHSigned(userCert, mockProvisioner, nil)
	meter.X509Signed(certs, mockProvisioner, nil)
	meter.KMSSigned(nil)
}