package wire

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.step.sm/crypto/kms/uri"
)

type ID struct {
	Name     string `json:"name,omitempty"`
	Domain   string `json:"domain,omitempty"`
	ClientID string `json:"client-id,omitempty"`
	Handle   string `json:"handle,omitempty"`
}

func ParseID(data []byte) (wireID ID, err error) {
	err = json.Unmarshal(data, &wireID)
	return
}

type ClientID struct {
	Username string
	DeviceID string
	Domain   string
}

// ParseClientID parses a Wire clientID. The ClientID format is as follows:
//
//	"wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com",
//
// where '!' is used as a separator between the user id & device id.
func ParseClientID(clientID string) (ClientID, error) {
	clientIDURI, err := uri.Parse(clientID)
	if err != nil {
		return ClientID{}, fmt.Errorf("invalid clientID URI %q: %w", clientID, err)
	}
	fullUsername := clientIDURI.User.Username()
	parts := strings.SplitN(fullUsername, "!", 2)
	if len(parts) != 2 {
		return ClientID{}, fmt.Errorf("invalid clientID %q", fullUsername)
	}
	return ClientID{
		Username: parts[0],
		DeviceID: parts[1],
		Domain:   clientIDURI.Host,
	}, nil
}
