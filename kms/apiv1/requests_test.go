package apiv1

import "testing"

func TestProtectionLevel_String(t *testing.T) {
	tests := []struct {
		name string
		p    ProtectionLevel
		want string
	}{
		{"unspecified", UnspecifiedProtectionLevel, "unspecified"},
		{"software", Software, "software"},
		{"hsm", HSM, "hsm"},
		{"unknown", ProtectionLevel(100), "unknown(100)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("ProtectionLevel.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignatureAlgorithm_String(t *testing.T) {
	tests := []struct {
		name string
		s    SignatureAlgorithm
		want string
	}{
		{"UnspecifiedSignAlgorithm", UnspecifiedSignAlgorithm, "unspecified"},
		{"SHA256WithRSA", SHA256WithRSA, "SHA256-RSA"},
		{"SHA384WithRSA", SHA384WithRSA, "SHA384-RSA"},
		{"SHA512WithRSA", SHA512WithRSA, "SHA512-RSA"},
		{"SHA256WithRSAPSS", SHA256WithRSAPSS, "SHA256-RSAPSS"},
		{"SHA384WithRSAPSS", SHA384WithRSAPSS, "SHA384-RSAPSS"},
		{"SHA512WithRSAPSS", SHA512WithRSAPSS, "SHA512-RSAPSS"},
		{"ECDSAWithSHA256", ECDSAWithSHA256, "ECDSA-SHA256"},
		{"ECDSAWithSHA384", ECDSAWithSHA384, "ECDSA-SHA384"},
		{"ECDSAWithSHA512", ECDSAWithSHA512, "ECDSA-SHA512"},
		{"PureEd25519", PureEd25519, "Ed25519"},
		{"unknown", SignatureAlgorithm(100), "unknown(100)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.String(); got != tt.want {
				t.Errorf("SignatureAlgorithm.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
