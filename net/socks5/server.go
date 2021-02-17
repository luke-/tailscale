package socks5

import "net"

// SOCKS5Version is the byte that represents the SOCKS version
// in requests.
const SOCKS5Version byte = 5

// AuthMethod represent the bytes sent in SOCKS5 packets
// that represent the authentication methods available.
type AuthMethod byte

// A set of valid SOCKS5 auth methods as described in RFC 1928.
const (
	NoAuthRequired       AuthMethod = 0
	GSSAPIAuth           AuthMethod = 1
	UsernamePasswordAuth AuthMethod = 2
	NoAcceptableAuth     AuthMethod = 255
)

// Command are the bytes sent in SOCKS5 packets
// that represent the kind of connection the client needs.
type Command byte

// The set of valid SOCKS5 commans as described in RFC 1928.
const (
	Connect      Command = 1
	Bind         Command = 2
	UDPAssociate Command = 3
)

// Addr are the bytes sent in SOCKS5 packets
// that represent particular address types.
type Addr byte

// The set of valid SOCKS5 address types as defined in RFC 1928.
const (
	IPv4       Addr = 1
	DomainName Addr = 3
	IPv6       Addr = 4
)

// ListenAndServe creates a SOCKS5 server at the given address:port.
func ListenAndServe(address string) error {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func() {
			conn := Conn{client: c}
			err := conn.init()
			if err != nil {
				conn.client.Close()
			}
		}()
	}
}
