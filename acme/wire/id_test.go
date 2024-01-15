package wire

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseID(t *testing.T) {
	ok := `{"name": "Alice Smith", "domain": "wire.com", "client-id": "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com", "handle": "wireapp://%40alice_wire@wire.com"}`
	tests := []struct {
		name        string
		data        []byte
		wantWireID  ID
		expectedErr error
	}{
		{name: "ok", data: []byte(ok), wantWireID: ID{Name: "Alice Smith", Domain: "wire.com", ClientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com", Handle: "wireapp://%40alice_wire@wire.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotWireID, err := ParseID(tt.data)
			if tt.expectedErr != nil {
				assert.EqualError(t, err, tt.expectedErr.Error())
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantWireID, gotWireID)
		})
	}
}

func TestParseClientID(t *testing.T) {
	tests := []struct {
		name        string
		clientID    string
		want        ClientID
		expectedErr error
	}{
		{name: "ok", clientID: "wireapp://CzbfFjDOQrenCbDxVmgnFw!594930e9d50bb175@wire.com", want: ClientID{Scheme: "wireapp", Username: "CzbfFjDOQrenCbDxVmgnFw", DeviceID: "594930e9d50bb175", Domain: "wire.com"}},
		{name: "fail/uri", clientID: "bla", expectedErr: errors.New(`invalid Wire client ID URI "bla": error parsing bla: scheme is missing`)},
		{name: "fail/scheme", clientID: "not-wireapp://bla.com", expectedErr: errors.New(`invalid Wire client ID scheme "not-wireapp"; expected "wireapp"`)},
		{name: "fail/username", clientID: "wireapp://user@wire.com", expectedErr: errors.New(`invalid Wire client ID username "user"`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseClientID(tt.clientID)
			if tt.expectedErr != nil {
				assert.EqualError(t, err, tt.expectedErr.Error())
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
