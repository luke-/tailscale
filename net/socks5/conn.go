package socks5

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

// Conn represents a SOCKS5 connection for client to reach
// server. The struct is filled by each of the internal methods
// in turn as the transaction progresses.
type Conn struct {
	dialContext DialContext
	client      net.Conn
	server      net.Conn
	methods     []AuthMethod
	request     *Request
}

// NewConn creates a new SOCKS5 connection that uses the default
// dialing context to talk to the SOCKS5 server
func NewConn(clientConn net.Conn) *Conn {
	dialer := &net.Dialer{}
	return NewConnWithDialContext(clientConn, dialer.DialContext)
}

// NewConnWithDialContext creates a new SOCKS5 connection that uses
// a custom dialing context to talk to the SOCKS5 server
func NewConnWithDialContext(clientConn net.Conn, dialContext DialContext) *Conn {
	return &Conn{
		client:      clientConn,
		dialContext: dialContext,
	}
}

func (conn *Conn) init() error {
	buf := make([]byte, MaxInitRequestSize)
	n, err := conn.client.Read(buf)
	if err != nil {
		return err
	}

	log.Printf("Received connection request from %s\n", conn.client.RemoteAddr())

	conn.methods, err = MethodsFromInitPacket(buf[:n])

	if err != nil {
		conn.client.Write(InitResponse(NoAcceptableAuth))
		return err
	}

	for _, m := range conn.methods {
		if m == NoAuthRequired {
			log.Printf("No auth required, moving ahead...\n")
			_, err := conn.client.Write(InitResponse(NoAuthRequired))
			if err != nil {
				return err
			}
			return conn.handleRequest()
		}
	}

	_, err = conn.client.Write(InitResponse(NoAcceptableAuth))

	if err != nil {
		return err
	}

	return fmt.Errorf("No acceptable auth methods")
}

func (conn *Conn) handleRequest() error {
	buf := make([]byte, MaxRequestPacketSize)

	n, err := conn.client.Read(buf)

	if err != nil {
		return err
	}

	req, err := RequestFromPacket(buf[:n])

	if err != nil {
		buf, _ := PacketFromResponse(&Response{reply: GeneralFailure})
		conn.client.Write(buf)
		return err
	}

	conn.request = req

	log.Printf("Attempting to connect to %s:%v\n", conn.request.destination, conn.request.port)

	return conn.createReply()
}

func (conn *Conn) createReply() error {
	var err error
	conn.server, err = conn.dialContext(
		context.Background(),
		"tcp",
		fmt.Sprintf("%s:%v", conn.request.destination, conn.request.port),
	)

	if err != nil {
		return err
	}

	go io.Copy(conn.client, conn.server)
	go io.Copy(conn.server, conn.client)

	serverAddr, serverPortStr, err := net.SplitHostPort(conn.server.LocalAddr().String())
	serverPort, _ := strconv.Atoi(serverPortStr)

	if err != nil {
		return err
	}

	var addrType Addr
	if ip := net.ParseIP(serverAddr); ip != nil {
		if ip.To4() != nil {
			addrType = IPv4
		} else {
			addrType = IPv6
		}
	} else {
		addrType = DomainName
	}

	var buf []byte
	buf, err = PacketFromResponse(&Response{
		reply:    Success,
		addrType: addrType,
		bindAddr: serverAddr,
		bindPort: uint16(serverPort),
	})

	if err != nil {
		buf, _ = PacketFromResponse(&Response{reply: GeneralFailure})
	}

	conn.client.Write(buf)

	log.Printf("Wrote out details to %s\n", conn.client.RemoteAddr())

	return err
}
