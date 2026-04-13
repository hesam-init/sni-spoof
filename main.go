// SNI-Spoofing-Go — Bypass DPI with fake TLS ClientHello injection.
//
// Cross-platform: Windows (WinDivert) and Linux/OpenWrt (nfqueue + raw socket).
// Requires admin/root privileges.
package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"sni-spoofing-go/config"
	"sni-spoofing-go/injection"
	"sni-spoofing-go/network"
	"sni-spoofing-go/packet"
)

const (
	dataMode     = "tls"
	bypassMethod = "wrong_seq"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config: ", err)
	}

	fakeSNI := []byte(cfg.FakeSNI)
	interfaceIPv4 := network.GetDefaultInterfaceIPv4(cfg.ConnectIP)
	if interfaceIPv4 == "" {
		log.Fatal("Failed to detect local interface IPv4 address")
	}
	fmt.Printf("Local interface: %s\n", interfaceIPv4)

	// Create the packet injector (platform-specific: WinDivert on Windows, nfqueue on Linux)
	fakeInjector, err := injection.NewFakeTcpInjector(interfaceIPv4, cfg.ConnectIP, uint16(cfg.ConnectPort))
	if err != nil {
		log.Fatal("Failed to create injector: ", err)
	}

	// Graceful shutdown: clean up iptables rules on Linux
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		fakeInjector.Close()
		os.Exit(0)
	}()

	go fakeInjector.Start()

	// Start the TCP listener
	listenAddr := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(cfg.ListenPort))
	listener, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		log.Fatal("Failed to listen: ", err)
	}
	defer listener.Close()
	fmt.Printf("Listening on %s\n", listenAddr)

	for {
		incomingSock, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		if tc, ok := incomingSock.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(11 * time.Second)
		}

		go handleConnection(incomingSock, cfg, interfaceIPv4, fakeSNI, fakeInjector)
	}
}

// handleConnection processes a single incoming proxy connection.
func handleConnection(
	incomingSock net.Conn,
	cfg *config.Config,
	interfaceIPv4 string,
	fakeSNI []byte,
	fakeInjector *injection.FakeTcpInjector,
) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in handle: %v", r)
		}
	}()

	// Build the fake TLS ClientHello
	rnd := make([]byte, 32)
	sessID := make([]byte, 32)
	keyShare := make([]byte, 32)
	rand.Read(rnd)
	rand.Read(sessID)
	rand.Read(keyShare)

	var fakeData []byte
	if dataMode == "tls" {
		fakeData = packet.GetClientHelloWith(rnd, sessID, fakeSNI, keyShare)
	} else {
		log.Fatal("impossible data mode!")
	}

	// dialOutgoing is platform-specific (dial_windows.go / dial_linux.go)
	outgoingSock, conn, srcPort, err := dialOutgoing(
		interfaceIPv4, cfg.ConnectIP, cfg.ConnectPort,
		fakeData, bypassMethod, incomingSock, fakeInjector,
	)
	if err != nil {
		log.Printf("Failed to connect to %s:%d: %v", cfg.ConnectIP, cfg.ConnectPort, err)
		incomingSock.Close()
		return
	}

	// Update the connection's socket reference
	conn.Mu.Lock()
	conn.Sock = outgoingSock
	conn.Mu.Unlock()

	if tc, ok := outgoingSock.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(11 * time.Second)
	}

	// Wait for the fake injection to complete
	key := injection.ConnID{
		SrcIP: interfaceIPv4, SrcPort: srcPort,
		DstIP: cfg.ConnectIP, DstPort: uint16(cfg.ConnectPort),
	}

	select {
	case msg := <-conn.T2aChan:
		if msg == "unexpected_close" {
			conn.Mu.Lock()
			conn.Monitor = false
			conn.Mu.Unlock()
			fakeInjector.Connections.Delete(key)
			outgoingSock.Close()
			incomingSock.Close()
			return
		}
		if msg != "fake_data_ack_recv" {
			log.Fatalf("impossible t2a msg: %s", msg)
		}
		// Success — fake ClientHello was injected, DPI saw the spoofed SNI
	case <-time.After(2 * time.Second):
		conn.Mu.Lock()
		conn.Monitor = false
		conn.Mu.Unlock()
		fakeInjector.Connections.Delete(key)
		outgoingSock.Close()
		incomingSock.Close()
		return
	}

	// Stop monitoring
	conn.Mu.Lock()
	conn.Monitor = false
	conn.Mu.Unlock()
	fakeInjector.Connections.Delete(key)

	// Bidirectional relay
	done := make(chan struct{}, 2)
	go func() { defer func() { done <- struct{}{} }(); relay(outgoingSock, incomingSock) }()
	go func() { defer func() { done <- struct{}{} }(); relay(incomingSock, outgoingSock) }()

	<-done
	outgoingSock.Close()
	incomingSock.Close()
	<-done
}

// relay copies data from src to dst until an error or EOF.
func relay(dst, src net.Conn) {
	buf := make([]byte, 65575)
	_, _ = io.CopyBuffer(dst, src, buf)
}
