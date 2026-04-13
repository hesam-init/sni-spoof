// Package injection provides packet interception and fake TCP injection.
// This file contains common types shared between Windows and Linux implementations.
package injection

import (
	"net"
	"sni-spoofing-go/connection"
)

// ConnID is re-exported from the connection package for convenience.
type ConnID = connection.ConnID

// FakeInjectiveConnection extends MonitorConnection with the state needed
// for fake TLS ClientHello injection. Shared between Windows and Linux.
type FakeInjectiveConnection struct {
	*connection.MonitorConnection

	FakeData     []byte     // The fake TLS ClientHello bytes to inject
	SchFakeSent  bool       // Whether the fake send has been scheduled
	FakeSent     bool       // Whether the fake packet has actually been sent
	T2aChan      chan string // Signalling channel for injection result
	BypassMethod string     // "wrong_seq" — the DPI bypass strategy
	PeerSock     net.Conn   // The incoming client connection (for cleanup on error)
}

// NewFakeInjectiveConnection creates a new FakeInjectiveConnection.
func NewFakeInjectiveConnection(
	sock net.Conn, srcIP, dstIP string, srcPort, dstPort uint16,
	fakeData []byte, bypassMethod string, peerSock net.Conn,
) *FakeInjectiveConnection {
	return &FakeInjectiveConnection{
		MonitorConnection: connection.NewMonitorConnection(sock, srcIP, dstIP, srcPort, dstPort),
		FakeData:          fakeData,
		SchFakeSent:       false,
		FakeSent:          false,
		T2aChan:           make(chan string, 1),
		BypassMethod:      bypassMethod,
		PeerSock:          peerSock,
	}
}
