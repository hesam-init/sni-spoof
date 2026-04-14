// SNI-Spoofing-Go — Bypass DPI with fake TLS ClientHello injection.
//
// Cross-platform: Windows (WinDivert) and Linux/OpenWrt (nfqueue + raw socket).
// Requires admin/root privileges.
//
// IPv4 only: CONNECT_IP, LISTEN_HOST, and all packet logic assume IPv4.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
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

func usage() {
	exe := os.Args[0]
	w := os.Stderr
	fmt.Fprintf(w, "SNI-Spoofing — fake TLS ClientHello (SNI) injection proxy. IPv4 only; run as Administrator / root.\n\n")
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  %s [options]\n\n", exe)
	fmt.Fprintf(w, "How to pass settings (pick one; do not combine with the others):\n\n")
	fmt.Fprintf(w, "  [no extra flags]\n")
	fmt.Fprintf(w, "      Load config.json from the directory of this program, or from the current\n")
	fmt.Fprintf(w, "      working directory if that file is not next to the binary.\n\n")
	fmt.Fprintf(w, "  -config <path>   or   -c <path>\n")
	fmt.Fprintf(w, "      Load JSON from <path> (LISTEN_HOST, LISTEN_PORT, CONNECT_IP, CONNECT_PORT, FAKE_SNI).\n\n")
	fmt.Fprintf(w, "  -listen, -connect, -fake-sni\n")
	fmt.Fprintf(w, "      Supply all three (IPv4 only). Host in -listen may be omitted for all interfaces\n")
	fmt.Fprintf(w, "      (e.g. -listen :8080 or -listen 0.0.0.0:8080).\n\n")
	fmt.Fprintf(w, "Examples:\n")
	fmt.Fprintf(w, "  %s\n", exe)
	fmt.Fprintf(w, "  %s -config /etc/sni/config.json\n", exe)
	fmt.Fprintf(w, "  %s -listen 127.0.0.1:8080 -connect 198.51.100.2:443 -fake-sni allowed.example.com\n\n", exe)
	fmt.Fprintf(w, "Options:\n")
	flag.PrintDefaults()
}

// configFromTriple builds config from three arguments: listen addr, upstream addr, fake SNI hostname.
func configFromTriple(listenAddr, connectAddr, fakeSNI string) (*config.Config, error) {
	listenHost, listenPortStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen address %q: %w", listenAddr, err)
	}
	listenPort, err := strconv.Atoi(listenPortStr)
	if err != nil || listenPort < 1 || listenPort > 65535 {
		return nil, fmt.Errorf("invalid listen port in %q", listenAddr)
	}
	connectIP, connectPortStr, err := net.SplitHostPort(connectAddr)
	if err != nil {
		return nil, fmt.Errorf("connect address %q: %w", connectAddr, err)
	}
	connectPort, err := strconv.Atoi(connectPortStr)
	if err != nil || connectPort < 1 || connectPort > 65535 {
		return nil, fmt.Errorf("invalid connect port in %q", connectAddr)
	}
	if strings.TrimSpace(fakeSNI) == "" {
		return nil, fmt.Errorf("FAKE_SNI must be non-empty")
	}
	if !network.IsIPv4(connectIP) {
		return nil, fmt.Errorf("connect host must be IPv4, got %q", connectIP)
	}
	if listenHost != "" && !network.IsIPv4(listenHost) {
		return nil, fmt.Errorf("listen host must be IPv4 or empty, got %q", listenHost)
	}
	return &config.Config{
		ListenHost:  listenHost,
		ListenPort:  listenPort,
		ConnectIP:   connectIP,
		ConnectPort: connectPort,
		FakeSNI:     fakeSNI,
	}, nil
}

func main() {
	flag.Usage = usage
	var configPath string
	var optListen, optConnect, optFakeSNI string
	flag.StringVar(&configPath, "config", "", "JSON configuration file (not with -listen/-connect/-fake-sni)")
	flag.StringVar(&configPath, "c", "", "same as -config")
	flag.StringVar(&optListen, "listen", "", "listen address host:port (use with -connect and -fake-sni)")
	flag.StringVar(&optConnect, "connect", "", "upstream address IPv4:port (use with -listen and -fake-sni)")
	flag.StringVar(&optFakeSNI, "fake-sni", "", "hostname for injected ClientHello SNI (use with -listen and -connect)")
	flag.Parse()

	configFromFlag := false
	cliListen, cliConnect, cliFakeSNI := false, false, false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "config", "c":
			configFromFlag = true
		case "listen":
			cliListen = true
		case "connect":
			cliConnect = true
		case "fake-sni":
			cliFakeSNI = true
		}
	})

	cliAny := cliListen || cliConnect || cliFakeSNI
	cliAll := cliListen && cliConnect && cliFakeSNI

	args := flag.Args()
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected arguments (use -listen/-connect/-fake-sni instead of positionals): %q\n\n", args)
		usage()
		os.Exit(2)
	}
	if configFromFlag && cliAny {
		log.Fatal("cannot combine -config/-c with -listen/-connect/-fake-sni")
	}
	if configFromFlag && strings.TrimSpace(configPath) == "" {
		log.Fatal("empty path for -config/-c")
	}
	if cliAny && !cliAll {
		log.Fatal("if using -listen, -connect, or -fake-sni, all three flags are required")
	}

	var cfg *config.Config
	var err error
	switch {
	case configFromFlag:
		cfg, err = config.LoadConfigFile(configPath)
	case cliAll:
		cfg, err = configFromTriple(optListen, optConnect, optFakeSNI)
	default:
		cfg, err = config.LoadConfig()
	}
	if err != nil {
		log.Fatal("Failed to load config: ", err)
	}

	fakeSNI := []byte(cfg.FakeSNI)
	if len(fakeSNI) > packet.MaxFakeSNILen {
		log.Fatalf("FAKE_SNI too long: max %d bytes, got %d", packet.MaxFakeSNILen, len(fakeSNI))
	}
	if !network.IsIPv4(cfg.ConnectIP) {
		log.Fatalf("CONNECT_IP must be an IPv4 address (IPv6 is not supported): %q", cfg.ConnectIP)
	}
	if cfg.ListenHost != "" && !network.IsIPv4(cfg.ListenHost) {
		log.Fatalf("LISTEN_HOST must be an IPv4 address or empty (IPv6 is not supported): %q", cfg.ListenHost)
	}
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
	if _, err := rand.Read(rnd); err != nil {
		log.Printf("crypto/rand: %v", err)
		incomingSock.Close()
		return
	}
	if _, err := rand.Read(sessID); err != nil {
		log.Printf("crypto/rand: %v", err)
		incomingSock.Close()
		return
	}
	if _, err := rand.Read(keyShare); err != nil {
		log.Printf("crypto/rand: %v", err)
		incomingSock.Close()
		return
	}

	var fakeData []byte
	if dataMode == "tls" {
		fakeData = packet.GetClientHelloWith(rnd, sessID, fakeSNI, keyShare)
	} else {
		log.Printf("unsupported data mode %q", dataMode)
		incomingSock.Close()
		return
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
			log.Printf("unexpected t2a msg: %q", msg)
			conn.Mu.Lock()
			conn.Monitor = false
			conn.Mu.Unlock()
			fakeInjector.Connections.Delete(key)
			outgoingSock.Close()
			incomingSock.Close()
			return
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
