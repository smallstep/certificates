package wire

import (
	"encoding/json"
	"fmt"
	"go.step.sm/crypto/kms/uri"
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

// ClientId format is : "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com" where '!' is used as a separator
// between the user id & device id
func ParseClientID(clientID string) (ClientID, error) {
	clientIdUri, err := uri.Parse(clientID)
	if err != nil {
		return ClientID{}, fmt.Errorf("invalid client id URI")
	}
	fullUsername := clientIdUri.User.Username()
	parts := strings.SplitN(fullUsername, "!", 2)
	if len(parts) != 2 {
		return ClientID{}, fmt.Errorf("invalid client id")
	}
	return ClientID{
		Username: parts[0],
		DeviceID: parts[1],
		Domain:   clientIdUri.Host,
	}, nil
}
