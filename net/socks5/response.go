package socks5

import (
	"encoding/binary"
	"fmt"
	"net"
)

const MaxResponsePacketSize int = 261

// SOCKS5Reply are the bytes sent in SOCKS5 packets
// that represent replies from the server to a client
// request.
type SOCKS5Reply byte

const (
	Success                 SOCKS5Reply = 0
	GeneralFailure          SOCKS5Reply = 1
	ConnectionNotAllowed    SOCKS5Reply = 2
	NetworkUnreachable      SOCKS5Reply = 3
	HostUnreachable         SOCKS5Reply = 4
	ConnectionRefused       SOCKS5Reply = 5
	TTLExpired              SOCKS5Reply = 6
	CommandNotSupported     SOCKS5Reply = 7
	AddressTypeNotSupported SOCKS5Reply = 8
)

// Response contains the contents of
// a response packet sent from the proxy
// to the client.
type Response struct {
	reply    SOCKS5Reply
	addrType Addr
	bindAddr string
	bindPort uint16
}

// PacketFromResponse converts a SOCKS5Response struct into
// a packet. If res.reply == Success, it may throw an error on
// receiving an invalid bind address. Otherwise, it will not throw.
func PacketFromResponse(res *Response) ([]byte, error) {
	pkt := make([]byte, 0, MaxResponsePacketSize)

	pkt = append(pkt, SOCKS5Version)
	pkt = append(pkt, byte(res.reply))
	pkt = append(pkt, 0) // null reserved byte
	pkt = append(pkt, byte(res.addrType))

	if res.reply == Success {
		var addr []byte
		if res.addrType == IPv4 {
			addr = net.ParseIP(res.bindAddr).To4()
			if addr == nil {
				return nil, fmt.Errorf("Invalid IPv4 address for binding")
			}
		} else if res.addrType == DomainName {
			if len(res.bindAddr) > 255 {
				return nil, fmt.Errorf("Invalid domain name for binding")
			}
			addr = make([]byte, 0, len(res.bindAddr)+1)
			addr = append(addr, byte(len(res.bindAddr)))
			addr = append(addr, []byte(res.bindAddr)...)
		} else if res.addrType == IPv6 {
			addr = net.ParseIP(res.bindAddr).To16()
			if addr == nil {
				return nil, fmt.Errorf("Invalid IPv6 address for binding")
			}
		} else {
			return nil, fmt.Errorf("Unsupported address type")
		}
		pkt = append(pkt, addr...)

		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(res.bindPort))
		pkt = append(pkt, port...)
	}

	return pkt, nil
}
