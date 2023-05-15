package wire

import (
	"encoding/json"
	"fmt"
	"strings"
)

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

type ClientID struct {
	Username string
	DeviceID string
	Domain   string
}

func ParseClientID(clientID string) (ClientID, error) {
	at := strings.SplitN(clientID, "@", 2)
	if len(at) != 2 {
		return ClientID{}, fmt.Errorf("could not match client ID format: %s", clientID)
	}
	comp := at[0]
	slash := strings.SplitN(comp, "/", 2)
	if len(slash) != 2 {
		return ClientID{}, fmt.Errorf("could not match client ID format: %s", clientID)
	}
	return ClientID{
		Username: slash[0],
		DeviceID: slash[1],
		Domain:   at[1],
	}, nil
}

type AccessTokenKey struct{}
