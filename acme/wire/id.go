package wire

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type UserID struct {
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
	Handle string `json:"handle,omitempty"`
}

type DeviceID struct {
	Name     string `json:"name,omitempty"`
	Domain   string `json:"domain,omitempty"`
	ClientID string `json:"client-id,omitempty"`
	Handle   string `json:"handle,omitempty"`
}

func ParseUserID(value string) (id UserID, err error) {
	if err = json.Unmarshal([]byte(value), &id); err != nil {
		return
	}

	switch {
	case id.Handle == "":
		err = errors.New("handle must not be empty")
	case id.Name == "":
		err = errors.New("name must not be empty")
	case id.Domain == "":
		err = errors.New("domain must not be empty")
	}

	return
}

func ParseDeviceID(value string) (id DeviceID, err error) {
	if err = json.Unmarshal([]byte(value), &id); err != nil {
		return
	}

	switch {
	case id.Handle == "":
		err = errors.New("handle must not be empty")
	case id.Name == "":
		err = errors.New("name must not be empty")
	case id.Domain == "":
		err = errors.New("domain must not be empty")
	case id.ClientID == "":
		err = errors.New("client-id must not be empty")
	}

	return
}

type ClientID struct {
	Scheme   string
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
	clientIDURI, err := url.Parse(clientID)
	if err != nil {
		return ClientID{}, fmt.Errorf("invalid Wire client ID URI %q: %w", clientID, err)
	}
	if clientIDURI.Scheme != "wireapp" {
		return ClientID{}, fmt.Errorf("invalid Wire client ID scheme %q; expected \"wireapp\"", clientIDURI.Scheme)
	}
	fullUsername := clientIDURI.User.Username()
	parts := strings.SplitN(fullUsername, "!", 2)
	if len(parts) != 2 {
		return ClientID{}, fmt.Errorf("invalid Wire client ID username %q", fullUsername)
	}
	return ClientID{
		Scheme:   clientIDURI.Scheme,
		Username: parts[0],
		DeviceID: parts[1],
		Domain:   clientIDURI.Host,
	}, nil
}
