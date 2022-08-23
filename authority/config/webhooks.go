package config

import (
	"net"
	"net/netip"
	"syscall"

	"github.com/pkg/errors"
)

var WebhookAddressErr = errors.New("Webhook remote address not allowed")

type WebhookClient struct {
	Allow WebhookAddressPolicy `json:"allow,omitempty"`
	Deny  WebhookAddressPolicy `json:"deny,omitempty"`
}

func (wc *WebhookClient) init() error {
	if wc == nil {
		return nil
	}
	for _, ip := range wc.Allow.IPs {
		parsedIP, err := netip.ParseAddr(ip)
		if err != nil {
			return err
		}
		wc.Allow.parsedIPs = append(wc.Allow.parsedIPs, parsedIP)
	}
	for _, ip := range wc.Deny.IPs {
		parsedIP, err := netip.ParseAddr(ip)
		if err != nil {
			return err
		}
		wc.Deny.parsedIPs = append(wc.Deny.parsedIPs, parsedIP)
	}
	return nil
}

type WebhookAddressPolicy struct {
	// Private matches any IPv4 or IPv6 private unicast address
	Private bool `json:"private,omitempty"`

	// Loopback matches any IPv4 or IPv6 loopback address
	Loopback bool `json:"loopback,omitempty"`

	// LinkLocal matches any IPv4 link-local unicast address
	LinkLocal bool `json:"linkLocal,omitempty"`

	// Public matches any IPv4 or IPv6 unicast address that is not private,
	// loopback or link-local
	Public bool `json:"public,omitempty"`

	// IPs exact-matches a set of IPv4 or IPv6 addresses
	IPs []string `json:"ips,omitempty"`

	// Hostnames exact-matches a set of hostnames
	Hostnames []string `json:"hostnames,omitempty"`

	parsedIPs []netip.Addr
}

func (wap WebhookAddressPolicy) IsIPMatch(ip netip.Addr) bool {
	for _, policyIP := range wap.parsedIPs {
		if policyIP == ip {
			return true
		}
	}

	if ip.IsMulticast() {
		return false
	}

	if wap.Private && ip.IsPrivate() {
		return true
	}

	if wap.Loopback && ip.IsLoopback() {
		return true
	}

	if wap.LinkLocal && ip.IsLinkLocalUnicast() {
		return true
	}

	if wap.Public &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() {
		return true
	}

	return false
}

func (wap WebhookAddressPolicy) IsHostnameMatch(hostname string) bool {
	for _, h := range wap.Hostnames {
		if hostname == h {
			return true
		}
	}
	return false
}

// ControlFunc returns a function to be used in a net.Dialer's Control field
// The serverAddr may be a hostname or an IP
func (wc WebhookClient) ControlFunc(serverAddr string) func(string, string, syscall.RawConn) error {
	// The resolvedAddress is an IP:port. If the webhook was configured with a
	return func(network, resolvedAddress string, c syscall.RawConn) error {
		// First check if the server address is a denied hostname
		serverHost, _, err := net.SplitHostPort(serverAddr)
		if err != nil {
			return err
		}
		isServerHostname := false
		if _, err := netip.ParseAddr(serverHost); err != nil {
			isServerHostname = true
		}
		if isServerHostname && wc.Deny.IsHostnameMatch(serverHost) {
			return WebhookAddressErr
		}

		// Check if the resolved IP is a denied IP
		resolvedAddrHost, _, err := net.SplitHostPort(resolvedAddress)
		if err != nil {
			return err
		}
		resolvedIP, err := netip.ParseAddr(resolvedAddrHost)
		if err != nil {
			return err
		}
		if wc.Deny.IsIPMatch(resolvedIP) {
			return WebhookAddressErr
		}

		// Check if the server address is an allowed hostname
		if isServerHostname && wc.Allow.IsHostnameMatch(serverHost) {
			return nil
		}

		// Check if the resolved IP as an allowed IP
		if wc.Allow.IsIPMatch(resolvedIP) {
			return nil
		}

		return WebhookAddressErr
	}
}
