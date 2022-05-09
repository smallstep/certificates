package kubernetes

import (
	"encoding/json"
	"path"
	"path/filepath"
	"runtime"
	"testing"
)

func TestKubernetes_NewKubernetesAuthMethod(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	tokenPath := filepath.Join(path.Dir(filename), "token")
	mountPath := "kubernetes"
	raw := `{"role": "SomeRoleName", "tokenPath": "` + tokenPath + `"}`

	_, err := NewKubernetesAuthMethod(mountPath, json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
}
