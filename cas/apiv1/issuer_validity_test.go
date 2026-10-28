package apiv1

import (
	"encoding/json"
	"testing"
)

func TestIssuerValidityLimit(t *testing.T) {
	mockRegister(t)
	for _, literal := range []string{"", "truncate", "reject", "off", "TRUNCATE", " trunc ate"} {
		t.Run(literal, func(t *testing.T) {
			var opts Options
			if err := json.Unmarshal([]byte(`{"issuerValidityLimit":`+`"`+literal+`"}`), &opts); err != nil {
				t.Fatal(err)
			}
			err := opts.Validate()
			accepted := literal == "" || literal == "truncate" || literal == "reject"
			if (err == nil) != accepted {
				t.Fatalf("policy %q validation: %v", literal, err)
			}
		})
	}
	var omitted *Options
	if err := omitted.Validate(); err != nil {
		t.Fatal(err)
	}
}
