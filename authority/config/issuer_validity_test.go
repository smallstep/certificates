package config

import (
	"encoding/json"
	"testing"

	_ "github.com/smallstep/certificates/cas"
)

func TestIssuerValidityLimit(t *testing.T) {
	for _, authority := range []string{`{}`, `{"issuerValidityLimit":""}`, `{"issuerValidityLimit":"truncate"}`, `{"issuerValidityLimit":"reject"}`, `{"issuerValidityLimit":"off"}`, `{"issuerValidityLimit":"Reject"}`} {
		t.Run(authority, func(t *testing.T) {
			var cfg Config
			data := `{"address":"127.0.0.1:9000","dnsNames":["localhost"],"root":"root.pem","crt":"issuer.pem","key":"issuer.key","authority":` + authority + `}`
			if err := json.Unmarshal([]byte(data), &cfg); err != nil {
				t.Fatal(err)
			}
			cfg.Init()
			err := cfg.Validate()
			invalid := authority == `{"issuerValidityLimit":"off"}` || authority == `{"issuerValidityLimit":"Reject"}`
			if (err != nil) != invalid {
				t.Fatalf("configuration validation: %v", err)
			}
		})
	}
}
