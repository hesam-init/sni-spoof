// Package packet provides TLS ClientHello and ServerHello template builders.
// These construct byte-for-byte identical packets to the Python implementation
// for fooling DPI systems with spoofed SNI values.
package packet

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// ------------------------------------------------------------------
// ClientHelloMaker
// ------------------------------------------------------------------

var (
	chTemplateHex = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	chTemplate    []byte

	// Template SNI used in the original hex template
	templateSNI = []byte("mci.ir")

	// Pre-computed static byte slices from the template
	chStatic1 []byte // template[:11]                             — TLS record header + handshake header + client version
	chStatic2 = []byte{0x20}                                      // session ID length prefix
	chStatic3 []byte // template[76:120]                          — cipher suites + compression + extensions preamble
	chStatic4 []byte // template[127+len(templateSNI):262+len(templateSNI)] — extensions after SNI until key_share data
	chStatic5 = []byte{0x00, 0x15}                                // padding extension type

	// TLS Change Cipher Spec + Application Data header
	TLSChangeCipher  = []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	TLSAppDataHeader = []byte{0x17, 0x03, 0x03}
)

func init() {
	var err error
	chTemplate, err = hex.DecodeString(chTemplateHex)
	if err != nil {
		panic("packet: failed to decode ClientHello template hex: " + err.Error())
	}

	sniLen := len(templateSNI)
	chStatic1 = chTemplate[:11]
	chStatic3 = chTemplate[76:120]
	chStatic4 = chTemplate[127+sniLen : 262+sniLen]
}

// GetClientHelloWith builds a TLS ClientHello packet with the given random,
// session ID, target SNI, and key share bytes.
// rnd, sessID, and keyShare must each be exactly 32 bytes.
func GetClientHelloWith(rnd, sessID, targetSNI, keyShare []byte) []byte {
	sniLen := len(targetSNI)

	// Server Name extension: type(2) + ext_len(2) + list_len(2) + type(1) + name_len(2) + name
	serverNameExt := make([]byte, 0, 2+2+1+2+sniLen)
	serverNameExt = appendUint16BE(serverNameExt, uint16(sniLen+5)) // extension data length
	serverNameExt = appendUint16BE(serverNameExt, uint16(sniLen+3)) // server name list length
	serverNameExt = append(serverNameExt, 0x00)                     // host name type
	serverNameExt = appendUint16BE(serverNameExt, uint16(sniLen))   // host name length
	serverNameExt = append(serverNameExt, targetSNI...)             // host name

	// Padding extension: type already in static5, length(2) + zeros
	paddingLen := 219 - sniLen
	paddingExt := make([]byte, 0, 2+paddingLen)
	paddingExt = appendUint16BE(paddingExt, uint16(paddingLen))
	paddingExt = append(paddingExt, make([]byte, paddingLen)...)

	// Assemble: static1 + rnd + static2 + sessID + static3 + serverNameExt + static4 + keyShare + static5 + paddingExt
	result := make([]byte, 0, 517) // total length is always 517 for standard SNI lengths
	result = append(result, chStatic1...)
	result = append(result, rnd...)
	result = append(result, chStatic2...)
	result = append(result, sessID...)
	result = append(result, chStatic3...)
	result = append(result, serverNameExt...)
	result = append(result, chStatic4...)
	result = append(result, keyShare...)
	result = append(result, chStatic5...)
	result = append(result, paddingExt...)

	return result
}

// ParseClientHello parses a 517-byte ClientHello back into its components.
func ParseClientHello(data []byte) (rnd, sessID []byte, sni string, keyShare []byte, err error) {
	if len(data) != 517 {
		return nil, nil, "", nil, fmt.Errorf("expected 517 bytes, got %d", len(data))
	}

	rnd = data[11:43]
	sessID = data[44:76]

	sniLenField := binary.BigEndian.Uint16(data[125:127])
	sni = string(data[127 : 127+sniLenField])

	ksInd := 262 + len(sni)
	keyShare = data[ksInd : ksInd+32]

	return rnd, sessID, sni, keyShare, nil
}

// GetClientResponseWith builds a TLS client response (ChangeCipherSpec + ApplicationData).
func GetClientResponseWith(appData1 []byte) []byte {
	result := make([]byte, 0, len(TLSChangeCipher)+len(TLSAppDataHeader)+2+len(appData1))
	result = append(result, TLSChangeCipher...)
	result = append(result, TLSAppDataHeader...)
	result = appendUint16BE(result, uint16(len(appData1)))
	result = append(result, appData1...)
	return result
}

// ------------------------------------------------------------------
// ServerHelloMaker
// ------------------------------------------------------------------

var (
	shTemplateHex = "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1dae291c5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbde406130200002e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5b0e4eb188ebd30193271e8171152eb4e"
	shTemplate    []byte

	shStatic1 []byte // template[:11]
	shStatic2 = []byte{0x20}
	shStatic3 []byte // template[76:95]
)

func init() {
	var err error
	shTemplate, err = hex.DecodeString(shTemplateHex)
	if err != nil {
		panic("packet: failed to decode ServerHello template hex: " + err.Error())
	}

	shStatic1 = shTemplate[:11]
	shStatic3 = shTemplate[76:95]
}

// GetServerHelloWith builds a TLS ServerHello packet.
func GetServerHelloWith(rnd, sessID, keyShare, appData1 []byte) []byte {
	result := make([]byte, 0, 256)
	result = append(result, shStatic1...)
	result = append(result, rnd...)
	result = append(result, shStatic2...)
	result = append(result, sessID...)
	result = append(result, shStatic3...)
	result = append(result, keyShare...)
	result = append(result, TLSChangeCipher...)
	result = append(result, TLSAppDataHeader...)
	result = appendUint16BE(result, uint16(len(appData1)))
	result = append(result, appData1...)
	return result
}

// ParseServerHello parses a ServerHello packet (must be >= 159 bytes).
func ParseServerHello(data []byte) (rnd, sessID, keyShare, appData1 []byte, err error) {
	if len(data) < 159 {
		return nil, nil, nil, nil, fmt.Errorf("expected >= 159 bytes, got %d", len(data))
	}

	rnd = data[11:43]
	sessID = data[44:76]
	keyShare = data[95:127]
	appData1 = data[138:]

	return rnd, sessID, keyShare, appData1, nil
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

func appendUint16BE(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}
