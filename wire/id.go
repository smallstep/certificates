package wire

import "encoding/json"

type WireIDJSON struct {
	Name     string `json:"name,omitempty"`
	Domain   string `json:"domain,omitempty"`
	ClientID string `json:"client-id,omitempty"`
	Handle   string `json:"handle,omitempty"`
}

func ParseID(data []byte) (wireID WireIDJSON, err error) {
	err = json.Unmarshal(data, &wireID)
	return
}
