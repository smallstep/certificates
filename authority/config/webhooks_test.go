package config

import (
	"net/netip"
	"testing"

	"github.com/smallstep/assert"
)

func TestWebhooksAddressPolicy_IsIPMatch(t *testing.T) {
	pubIPv4 := netip.MustParseAddr("104.196.30.220")
	pubIPv6 := netip.MustParseAddr("2600:1f18:2489:8202:3e66:ff9e:de27:befe")
	loopbackIPv4 := netip.MustParseAddr("127.0.0.1")
	loopbackIPv6 := netip.MustParseAddr("::1")
	privateIPv4 := netip.MustParseAddr("10.32.0.1")
	privateIPv6 := netip.MustParseAddr("fd12:3456:789a:1::1")
	linkLocalIPv4 := netip.MustParseAddr("169.254.0.1")
	linkLocalIPv6 := netip.MustParseAddr("fe80::1")

	type test struct {
		policy WebhookAddressPolicy
		ip     netip.Addr
		expect bool
	}
	tests := map[string]test{
		"true/public-ipv4": {
			policy: WebhookAddressPolicy{
				Public: true,
			},
			ip:     pubIPv4,
			expect: true,
		},
		"false/public-ipv4": {
			policy: WebhookAddressPolicy{
				Private:   true,
				Loopback:  true,
				LinkLocal: true,
			},
			ip:     pubIPv4,
			expect: false,
		},
		"true/public-ipv6": {
			policy: WebhookAddressPolicy{
				Public: true,
			},
			ip:     pubIPv6,
			expect: true,
		},
		"false/public-ipv6": {
			policy: WebhookAddressPolicy{
				Private:   true,
				Loopback:  true,
				LinkLocal: true,
			},
			ip:     pubIPv6,
			expect: false,
		},
		"false/public-ipv4-multicast": {
			policy: WebhookAddressPolicy{
				Public: true,
			},
			ip:     netip.MustParseAddr("224.0.1.0"),
			expect: false,
		},
		"false/public-ipv6-multicast": {
			policy: WebhookAddressPolicy{
				Public: true,
			},
			ip:     netip.MustParseAddr("ff00::1"),
			expect: false,
		},
		"true/loopback-ipv4": {
			policy: WebhookAddressPolicy{
				Loopback: true,
			},
			ip:     loopbackIPv4,
			expect: true,
		},
		"true/loopback-ipv6": {
			policy: WebhookAddressPolicy{
				Loopback: true,
			},
			ip:     loopbackIPv6,
			expect: true,
		},
		"false/loopback-ipv4": {
			policy: WebhookAddressPolicy{
				Private:   true,
				Public:    true,
				LinkLocal: true,
			},
			ip:     loopbackIPv4,
			expect: false,
		},
		"false/loopback-ipv6": {
			policy: WebhookAddressPolicy{
				Private:   true,
				Public:    true,
				LinkLocal: true,
			},
			ip:     loopbackIPv6,
			expect: false,
		},
		"true/private-ipv4": {
			policy: WebhookAddressPolicy{
				Private: true,
			},
			ip:     privateIPv4,
			expect: true,
		},
		"true/private-ipv6": {
			policy: WebhookAddressPolicy{
				Private: true,
			},
			ip:     privateIPv6,
			expect: true,
		},
		"false/private-ipv4": {
			policy: WebhookAddressPolicy{
				Loopback:  true,
				Public:    true,
				LinkLocal: true,
			},
			ip:     privateIPv4,
			expect: false,
		},
		"false/private-ipv6": {
			policy: WebhookAddressPolicy{
				Loopback:  true,
				Public:    true,
				LinkLocal: true,
			},
			ip:     privateIPv6,
			expect: false,
		},
		"true/link-local-ipv4": {
			policy: WebhookAddressPolicy{
				LinkLocal: true,
			},
			ip:     linkLocalIPv4,
			expect: true,
		},
		"true/link-local-ipv6": {
			policy: WebhookAddressPolicy{
				LinkLocal: true,
			},
			ip:     linkLocalIPv6,
			expect: true,
		},
		"false/link-local-ipv4": {
			policy: WebhookAddressPolicy{
				Loopback: true,
				Public:   true,
				Private:  true,
			},
			ip:     linkLocalIPv6,
			expect: false,
		},
		"false/link-local-ipv6": {
			policy: WebhookAddressPolicy{
				Loopback: true,
				Public:   true,
				Private:  true,
			},
			ip:     linkLocalIPv6,
			expect: false,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := tc.policy.IsIPMatch(tc.ip)

			assert.Equals(t, tc.expect, got)
		})
	}
}

func TestWebhookClient_ControlFunc(t *testing.T) {
	type test struct {
		serverAddr   string
		resolvedAddr string
		expectErr    error
		allow        WebhookAddressPolicy
		deny         WebhookAddressPolicy
	}
	tests := map[string]test{
		"ok/ipv4-public": {
			serverAddr:   "example.com:443",
			resolvedAddr: "93.184.216.34:443",
			allow: WebhookAddressPolicy{
				Public: true,
			},
			expectErr: nil,
		},
		"ok/ipv6-public": {
			serverAddr:   "example.com:443",
			resolvedAddr: "[2606:2800:220:1:248:1893:25c8:1946]:443",
			allow: WebhookAddressPolicy{
				Public: true,
			},
			expectErr: nil,
		},
		"err/ipv4-private": {
			serverAddr:   "example.com:443",
			resolvedAddr: "10.32.0.1:443",
			allow: WebhookAddressPolicy{
				Public: true,
			},
			expectErr: ErrWebhookAddress,
		},
		"ok/loopback-ipv6": {
			serverAddr:   "localhost:9443",
			resolvedAddr: "[::1]:9443",
			allow: WebhookAddressPolicy{
				Loopback: true,
			},
			expectErr: nil,
		},
		"ok/allowed-hostname": {
			serverAddr:   "example.com:443",
			resolvedAddr: "10.32.0.1:443",
			allow: WebhookAddressPolicy{
				Hostnames: []string{"example.com"},
			},
			expectErr: nil,
		},
		"err/denied-hostname": {
			serverAddr:   "example.com:443",
			resolvedAddr: "93.184.216.34:443",
			allow: WebhookAddressPolicy{
				Public: true,
			},
			deny: WebhookAddressPolicy{
				Hostnames: []string{"example.com"},
			},
			expectErr: ErrWebhookAddress,
		},
		"err/denied-ipv4": {
			serverAddr:   "example.com:443",
			resolvedAddr: "93.184.216.34:443",
			allow: WebhookAddressPolicy{
				Public:    true,
				Hostnames: []string{"example.com"},
			},
			deny: WebhookAddressPolicy{
				IPs: []string{"93.184.216.34"},
			},
			expectErr: ErrWebhookAddress,
		},
		"err/denied-ipv6": {
			serverAddr:   "example.com:443",
			resolvedAddr: "[2606:2800:220::1946]:443",
			allow: WebhookAddressPolicy{
				Public:    true,
				Hostnames: []string{"example.com"},
			},
			deny: WebhookAddressPolicy{
				IPs: []string{"2606:2800:220:0:0:0:0:1946"},
			},
			expectErr: ErrWebhookAddress,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			config := WebhookClient{
				Allow: tc.allow,
				Deny:  tc.deny,
			}
			err := config.init()
			assert.FatalError(t, err)
			controlFn := config.ControlFunc(tc.serverAddr)
			gotErr := controlFn("tcp", tc.resolvedAddr, nil)
			assert.Equals(t, tc.expectErr, gotErr)
		})
	}
}
