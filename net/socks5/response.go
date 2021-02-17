package socks5

import (
	"encoding/binary"
	"fmt"
	"net"
)

const maxResponsePacketSize int = 261

// Reply are the bytes sent in SOCKS5 packets
// that represent replies from the server to a client
// request.
type Reply byte

// The set of valid SOCKS5 reply types as per the RFC 1928.
const (
	Success                 Reply = 0
	GeneralFailure          Reply = 1
	ConnectionNotAllowed    Reply = 2
	NetworkUnreachable      Reply = 3
	HostUnreachable         Reply = 4
	ConnectionRefused       Reply = 5
	TTLExpired              Reply = 6
	CommandNotSupported     Reply = 7
	AddressTypeNotSupported Reply = 8
)

// Response contains the contents of
// a response packet sent from the proxy
// to the client.
type Response struct {
	reply    Reply
	addrType Addr
	bindAddr string
	bindPort uint16
}

// PacketFromResponse converts a SOCKS5Response struct into
// a packet. If res.reply == Success, it may throw an error on
// receiving an invalid bind address. Otherwise, it will not throw.
func PacketFromResponse(res *Response) ([]byte, error) {
	pkt := make([]byte, 0, maxResponsePacketSize)
	pkt = append(pkt, SOCKS5Version)
	pkt = append(pkt, byte(res.reply))
	pkt = append(pkt, 0) // null reserved byte
	pkt = append(pkt, byte(res.addrType))

	if res.reply != Success {
		return pkt, nil
	}

	var addr []byte
	switch res.addrType {
	case IPv4:
		addr = net.ParseIP(res.bindAddr).To4()
		if addr == nil {
			return nil, fmt.Errorf("invalid IPv4 address for binding")
		}
	case DomainName:
		if len(res.bindAddr) > 255 {
			return nil, fmt.Errorf("invalid domain name for binding")
		}
		addr = make([]byte, 0, len(res.bindAddr)+1)
		addr = append(addr, byte(len(res.bindAddr)))
		addr = append(addr, []byte(res.bindAddr)...)
	case IPv6:
		addr = net.ParseIP(res.bindAddr).To16()
		if addr == nil {
			return nil, fmt.Errorf("invalid IPv6 address for binding")
		}
	default:
		return nil, fmt.Errorf("unsupported address type")
	}

	pkt = append(pkt, addr...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(res.bindPort))
	pkt = append(pkt, port...)

	return pkt, nil
}
