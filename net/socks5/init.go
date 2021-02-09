package socks5

import "fmt"

const MaxInitRequestSize = 257

func MethodsFromInitPacket(pkt []byte) ([]AuthMethod, error) {
	sz := len(pkt)

	if sz < 3 {
		return nil, fmt.Errorf("Invalid read packet")
	}
	if pkt[0] != SOCKS5Version {
		return nil, fmt.Errorf("Incompatible SOCKS version")
	}
	count := int(pkt[1])
	if sz < count+2 {
		return nil, fmt.Errorf("Incorrect nmethods specified: %v vs %v", count, sz-2)
	}

	methods := make([]AuthMethod, count)
	for i := range methods {
		methods[i] = AuthMethod(pkt[i+2])
	}

	return methods, nil
}

func InitResponse(method AuthMethod) []byte {
	res := make([]byte, 2)
	res[0] = SOCKS5Version
	res[1] = byte(method)
	return res
}
