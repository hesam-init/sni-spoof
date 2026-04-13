package packet

import (
	"encoding/hex"
	"testing"
)

func TestGetClientHelloWith_KnownValues(t *testing.T) {
	// Use deterministic values to verify output matches Python
	rnd := make([]byte, 32)
	sessID := make([]byte, 32)
	keyShare := make([]byte, 32)
	for i := 0; i < 32; i++ {
		rnd[i] = byte(i)
		sessID[i] = byte(i + 32)
		keyShare[i] = byte(i + 64)
	}

	targetSNI := []byte("auth.vercel.com")
	result := GetClientHelloWith(rnd, sessID, targetSNI, keyShare)

	// Verify length: should always be ~517 bytes for standard SNI lengths
	// The total is: static1(11) + rnd(32) + static2(1) + sessID(32) + static3(44)
	// + serverNameExt(2+2+1+2+15=22) + static4(135-len(mci.ir)+len(mci.ir)=135)
	// Actually the formula depends on template SNI length. Let's just check it's reasonable.
	if len(result) < 400 || len(result) > 600 {
		t.Fatalf("unexpected ClientHello length: %d", len(result))
	}

	// Verify the TLS record header
	if result[0] != 0x16 { // ContentType: Handshake
		t.Errorf("expected ContentType 0x16, got 0x%02x", result[0])
	}
	if result[1] != 0x03 || result[2] != 0x01 { // TLS 1.0
		t.Errorf("expected TLS version 0x0301, got 0x%02x%02x", result[1], result[2])
	}

	// Verify rnd is at offset 11
	for i := 0; i < 32; i++ {
		if result[11+i] != byte(i) {
			t.Errorf("rnd mismatch at offset %d: expected %d, got %d", i, i, result[11+i])
			break
		}
	}

	// Verify sessID is at offset 44
	for i := 0; i < 32; i++ {
		if result[44+i] != byte(i+32) {
			t.Errorf("sessID mismatch at offset %d: expected %d, got %d", i, i+32, result[44+i])
			break
		}
	}

	// Verify SNI is embedded at the right offset (127)
	sniStr := "auth.vercel.com"
	sniBytes := result[127 : 127+len(sniStr)]
	if string(sniBytes) != sniStr {
		t.Errorf("SNI mismatch: expected %q, got %q", sniStr, string(sniBytes))
	}

	// Test round-trip: parse what we built
	parsedRnd, parsedSessID, parsedSNI, parsedKeyShare, err := ParseClientHello(result)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}

	if hex.EncodeToString(parsedRnd) != hex.EncodeToString(rnd) {
		t.Error("round-trip rnd mismatch")
	}
	if hex.EncodeToString(parsedSessID) != hex.EncodeToString(sessID) {
		t.Error("round-trip sessID mismatch")
	}
	if parsedSNI != sniStr {
		t.Errorf("round-trip SNI mismatch: %q vs %q", parsedSNI, sniStr)
	}
	if hex.EncodeToString(parsedKeyShare) != hex.EncodeToString(keyShare) {
		t.Error("round-trip keyShare mismatch")
	}

	t.Logf("ClientHello length: %d bytes", len(result))
	t.Logf("ClientHello (first 32 bytes): %s", hex.EncodeToString(result[:32]))
}

func TestGetClientHelloWith_OriginalSNI(t *testing.T) {
	// Test with the original template SNI to ensure template fidelity
	rnd := chTemplate[11:43]    // same rnd as template
	sessID := chTemplate[44:76] // same sessID as template

	sniStr := "mci.ir" // original template SNI
	sniLen := len(sniStr)
	ksInd := 262 + sniLen
	keyShare := chTemplate[ksInd : ksInd+32]

	result := GetClientHelloWith(rnd, sessID, []byte(sniStr), keyShare)

	// Should be byte-for-byte identical to the template
	if len(result) != len(chTemplate) {
		t.Fatalf("length mismatch: got %d, want %d", len(result), len(chTemplate))
	}

	for i := range result {
		if result[i] != chTemplate[i] {
			t.Errorf("byte mismatch at offset %d: got 0x%02x, want 0x%02x", i, result[i], chTemplate[i])
			// Show some context
			start := i - 3
			if start < 0 {
				start = 0
			}
			end := i + 4
			if end > len(result) {
				end = len(result)
			}
			t.Errorf("context: got  %s", hex.EncodeToString(result[start:end]))
			t.Errorf("context: want %s", hex.EncodeToString(chTemplate[start:end]))
			break
		}
	}
}

func TestTCPHeaderParsing(t *testing.T) {
	// Construct a minimal IPv4+TCP packet (40 bytes)
	// IPv4 header (20 bytes) + TCP header (20 bytes)
	raw := make([]byte, 40)

	// IPv4 header
	raw[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	raw[2] = 0x00
	raw[3] = 40   // Total length
	raw[4] = 0x12 // Identification
	raw[5] = 0x34
	raw[9] = 6 // Protocol: TCP
	// Src IP: 192.168.1.1
	raw[12] = 192
	raw[13] = 168
	raw[14] = 1
	raw[15] = 1
	// Dst IP: 10.0.0.1
	raw[16] = 10
	raw[17] = 0
	raw[18] = 0
	raw[19] = 1

	// TCP header at offset 20
	raw[20] = 0x1F // Src port high byte (8000 = 0x1F40)
	raw[21] = 0x40 // Src port low byte
	raw[22] = 0x01 // Dst port high byte (443 = 0x01BB)
	raw[23] = 0xBB // Dst port low byte
	// Seq num: 0x12345678
	raw[24] = 0x12
	raw[25] = 0x34
	raw[26] = 0x56
	raw[27] = 0x78
	// Ack num: 0x9ABCDEF0
	raw[28] = 0x9A
	raw[29] = 0xBC
	raw[30] = 0xDE
	raw[31] = 0xF0
	// Data offset: 5 (20 bytes), flags: SYN+ACK (0x12)
	raw[32] = 0x50 // Data offset = 5
	raw[33] = 0x12 // SYN=1, ACK=1

	// Test IP version
	if v := IPVersion(raw); v != 4 {
		t.Errorf("IPVersion: got %d, want 4", v)
	}

	// Test IP header length
	if l := IPHeaderLen(raw); l != 20 {
		t.Errorf("IPHeaderLen: got %d, want 20", l)
	}

	// Test IP addresses
	srcIP := IPv4SrcAddr(raw)
	if srcIP.String() != "192.168.1.1" {
		t.Errorf("SrcIP: got %s, want 192.168.1.1", srcIP)
	}

	dstIP := IPv4DstAddr(raw)
	if dstIP.String() != "10.0.0.1" {
		t.Errorf("DstIP: got %s, want 10.0.0.1", dstIP)
	}

	// Test IP total length
	if l := IPv4TotalLen(raw); l != 40 {
		t.Errorf("IPv4TotalLen: got %d, want 40", l)
	}

	// Test IP identification
	if id := IPv4Ident(raw); id != 0x1234 {
		t.Errorf("IPv4Ident: got 0x%04x, want 0x1234", id)
	}

	// Test TCP ports
	if p := TCPSrcPort(raw); p != 8000 {
		t.Errorf("TCPSrcPort: got %d, want 8000", p)
	}
	if p := TCPDstPort(raw); p != 443 {
		t.Errorf("TCPDstPort: got %d, want 443", p)
	}

	// Test TCP seq/ack
	if s := TCPSeqNum(raw); s != 0x12345678 {
		t.Errorf("TCPSeqNum: got 0x%08x, want 0x12345678", s)
	}
	if a := TCPAckNum(raw); a != 0x9ABCDEF0 {
		t.Errorf("TCPAckNum: got 0x%08x, want 0x9ABCDEF0", a)
	}

	// Test TCP flags
	flags := GetTCPFlags(raw)
	if !flags.SYN {
		t.Error("expected SYN flag set")
	}
	if !flags.ACK {
		t.Error("expected ACK flag set")
	}
	if flags.RST {
		t.Error("expected RST flag clear")
	}
	if flags.FIN {
		t.Error("expected FIN flag clear")
	}
	if flags.PSH {
		t.Error("expected PSH flag clear")
	}

	// Test TCP payload (no payload in this case)
	if l := TCPPayloadLen(raw); l != 0 {
		t.Errorf("TCPPayloadLen: got %d, want 0", l)
	}

	// Test modifying seq number
	SetTCPSeqNum(raw, 0xDEADBEEF)
	if s := TCPSeqNum(raw); s != 0xDEADBEEF {
		t.Errorf("after SetTCPSeqNum: got 0x%08x, want 0xDEADBEEF", s)
	}

	// Test setting PSH flag
	SetTCPFlag(raw, "psh", true)
	flags = GetTCPFlags(raw)
	if !flags.PSH {
		t.Error("expected PSH flag set after SetTCPFlag")
	}
	if !flags.SYN {
		t.Error("SYN flag should still be set")
	}

	// Test clearing SYN flag
	SetTCPFlag(raw, "syn", false)
	flags = GetTCPFlags(raw)
	if flags.SYN {
		t.Error("SYN flag should be cleared")
	}
	if !flags.ACK {
		t.Error("ACK flag should still be set")
	}

	// Test SetTCPPayload
	payload := []byte("Hello, World!")
	newRaw := SetTCPPayload(raw, payload)
	if l := IPv4TotalLen(newRaw); l != uint16(40+len(payload)) {
		t.Errorf("after SetTCPPayload, total len: got %d, want %d", l, 40+len(payload))
	}
	if l := TCPPayloadLen(newRaw); l != len(payload) {
		t.Errorf("after SetTCPPayload, payload len: got %d, want %d", l, len(payload))
	}
	if string(TCPPayload(newRaw)) != "Hello, World!" {
		t.Errorf("payload content mismatch: got %q", string(TCPPayload(newRaw)))
	}

	t.Logf("TCP header parsing tests passed")
}
