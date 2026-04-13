// Package connection provides the MonitorConnection struct that tracks
// the TCP handshake state for a single connection being monitored by
// the packet injector.
package connection

import (
	"net"
	"sync"
)

// ConnID uniquely identifies a TCP connection as a 4-tuple:
// (source IP, source port, destination IP, destination port).
type ConnID struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// MonitorConnection holds the state for a single TCP connection being
// monitored by the WinDivert packet injector. It tracks the SYN and
// SYN-ACK sequence numbers observed during the TCP three-way handshake.
type MonitorConnection struct {
	Monitor   bool   // Whether this connection is still being monitored
	SynSeq    int64  // Sequence number from the SYN packet (-1 = not yet seen)
	SynAckSeq int64  // Sequence number from the SYN-ACK packet (-1 = not yet seen)
	SrcIP     string // Local source IP
	DstIP     string // Remote destination IP
	SrcPort   uint16 // Local source port
	DstPort   uint16 // Remote destination port
	ID        ConnID // Connection identifier tuple
	Mu        sync.Mutex
	Sock      net.Conn // The outgoing TCP connection
}

// NewMonitorConnection creates a new MonitorConnection with initial state.
func NewMonitorConnection(sock net.Conn, srcIP, dstIP string, srcPort, dstPort uint16) *MonitorConnection {
	return &MonitorConnection{
		Monitor:   true,
		SynSeq:    -1,
		SynAckSeq: -1,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		ID: ConnID{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
		},
		Sock: sock,
	}
}
