package wire

import (
	"encoding/json"
	"fmt"
	"go.step.sm/crypto/kms/uri"
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
	clientIdUri, err := uri.Parse(clientID)
	if err != nil {
		return ClientID{}, fmt.Errorf("invalid client id URI")
	}
	username := clientIdUri.User.Username()
	deviceId, _ := clientIdUri.User.Password()
	return ClientID{
		Username: username,
		DeviceID: deviceId,
		Domain:   clientIdUri.Host,
	}, nil
}
