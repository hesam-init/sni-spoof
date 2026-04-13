// Package network provides utilities for detecting local network interface addresses.
package network

import (
	"net"
)

// GetDefaultInterfaceIPv4 discovers the local IPv4 address that would be used
// to reach the given remote address. It uses the UDP "connect" trick:
// connecting a UDP socket to a remote address reveals the local source IP
// without actually sending any data.
func GetDefaultInterfaceIPv4(remoteAddr string) string {
	if remoteAddr == "" {
		remoteAddr = "8.8.8.8"
	}
	conn, err := net.Dial("udp4", net.JoinHostPort(remoteAddr, "53"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// GetDefaultInterfaceIPv6 discovers the local IPv6 address that would be used
// to reach the given remote address, using the same UDP connect trick.
func GetDefaultInterfaceIPv6(remoteAddr string) string {
	if remoteAddr == "" {
		remoteAddr = "2001:4860:4860::8888"
	}
	conn, err := net.Dial("udp6", net.JoinHostPort(remoteAddr, "53"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
