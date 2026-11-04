package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_resolverAddress(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"1.1.1.1", "1.1.1.1:53"},
		{"1.1.1.1:53", "1.1.1.1:53"},
		{"1.1.1.1:5353", "1.1.1.1:5353"},
		{"dns.example.com", "dns.example.com:53"},
		{"dns.example.com:5353", "dns.example.com:5353"},
		{"2606:4700:4700::1111", "[2606:4700:4700::1111]:53"},
		{"[2606:4700:4700::1111]", "[2606:4700:4700::1111]:53"},
		{"[2606:4700:4700::1111]:5353", "[2606:4700:4700::1111]:5353"},
		{"::1", "[::1]:53"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			assert.Equal(t, tt.want, resolverAddress(tt.addr))
		})
	}
}
