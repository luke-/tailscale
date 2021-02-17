package socks5

import (
	"encoding/binary"
	"fmt"
	"net"
)

const maxRequestPacketSize int = 261

// Request reperesents data contained within a SOCKS5
// connection request packet.
type Request struct {
	command     Command
	destination string
	port        uint16
	addrType    Addr
}

// RequestFromPacket converts raw packet bytes into a
// SOCKS5Request struct.
func RequestFromPacket(pkt []byte) (*Request, error) {
	cmd := pkt[1]
	addrType := Addr(pkt[3])

	var destination string
	var port uint16

	// version + command + reserved + address type + port
	const minPacketSize = 6

	if addrType == IPv4 {
		if len(pkt) < minPacketSize+4 {
			return nil, fmt.Errorf("packet too small to contain IPv4 address")
		}
		destination = net.IP(pkt[4:8]).String()
		port = binary.BigEndian.Uint16(pkt[8:10])
	} else if addrType == DomainName {
		dstSize := int(pkt[4])
		if len(pkt) < minPacketSize+dstSize+1 {
			return nil, fmt.Errorf("packet too small to contain FQDN of length %v", dstSize)
		}
		destination = string(pkt[5 : 5+dstSize])
		port = binary.BigEndian.Uint16(pkt[4+dstSize : 4+dstSize+2])
	} else if addrType == IPv6 {
		if len(pkt) < minPacketSize+16 {
			return nil, fmt.Errorf("packet too small to contain IPv6 address")
		}
		destination = net.IP(pkt[4:20]).String()
		port = binary.BigEndian.Uint16(pkt[20:22])
	} else {
		return nil, fmt.Errorf("unsupported address type")
	}

	return &Request{
		command:     Command(cmd),
		destination: destination,
		port:        port,
		addrType:    addrType,
	}, nil
}
