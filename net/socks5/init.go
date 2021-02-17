package socks5

import "fmt"

const maxInitRequestSize = 257

// MethodsFromInitPacket parses a request initiation packet
// and returns a slice that contains the acceptable auth methods
// for the client.
func MethodsFromInitPacket(pkt []byte) ([]AuthMethod, error) {
	sz := len(pkt)
	if sz < 3 {
		return nil, fmt.Errorf("invalid read packet")
	}
	if pkt[0] != SOCKS5Version {
		return nil, fmt.Errorf("incompatible SOCKS version")
	}
	count := int(pkt[1])
	if sz < count+2 {
		return nil, fmt.Errorf("incorrect nmethods specified: %v vs %v", count, sz-2)
	}

	methods := make([]AuthMethod, count)
	for i := range methods {
		methods[i] = AuthMethod(pkt[i+2])
	}
	return methods, nil
}

// InitResponse creates a packet that tells the client which
// auth method has been selected.
func InitResponse(method AuthMethod) []byte {
	res := make([]byte, 2)
	res[0] = SOCKS5Version
	res[1] = byte(method)
	return res
}
