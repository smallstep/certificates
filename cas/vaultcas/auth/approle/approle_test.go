package approle

import (
	"encoding/json"
	"testing"
)

func TestKubernetes_NewKubernetesAuthMethod(t *testing.T) {
	mountPath := "approle"
	raw := `{"roleID": "roleID", "secretID": "secretIDwrapped", "isWrappedToken": true}`

	_, err := NewApproleAuthMethod(mountPath, json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
}
