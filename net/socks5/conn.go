package socks5

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

// DialContext is the type of net.Dialer.DialContext. Conn owns a DialContext so that
// custom DialContexts (such as in gVisor netstack) can also be adapted to use here.
type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

// Conn represents a SOCKS5 connection for client to reach
// server.
type Conn struct {
	// The struct is filled by each of the internal
	// methods in turn as the transaction progresses.
	dialContext DialContext
	client      net.Conn
	server      net.Conn
	methods     []AuthMethod
	request     *Request
}

// NewConn creates a new SOCKS5 connection that uses the default
// dialing context to talk to the SOCKS5 server.
func NewConn(clientConn net.Conn) *Conn {
	dialer := &net.Dialer{}
	return NewConnWithDialContext(clientConn, dialer.DialContext)
}

// NewConnWithDialContext creates a new SOCKS5 connection that uses
// a custom dialing context to talk to the SOCKS5 server.
func NewConnWithDialContext(clientConn net.Conn, dialContext DialContext) *Conn {
	return &Conn{
		client:      clientConn,
		dialContext: dialContext,
	}
}

func (conn *Conn) init() error {
	buf := make([]byte, maxInitRequestSize)
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
	return fmt.Errorf("no acceptable auth methods")
}

func (conn *Conn) handleRequest() error {
	buf := make([]byte, maxRequestPacketSize)
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
	log.Printf("Attempting to connect to %s:%v", conn.request.destination, conn.request.port)
	return conn.createReply()
}

func (conn *Conn) createReply() error {
	var err error
	srv, err := conn.dialContext(
		context.Background(),
		"tcp",
		fmt.Sprintf("%s:%v", conn.request.destination, conn.request.port),
	)
	if err != nil {
		return err
	}
	conn.server = srv
	serverAddr, serverPortStr, err := net.SplitHostPort(conn.server.LocalAddr().String())
	if err != nil {
		return err
	}
	serverPort, _ := strconv.Atoi(serverPortStr)
	go io.Copy(conn.client, conn.server)
	go io.Copy(conn.server, conn.client)

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

	buf, err := PacketFromResponse(&Response{
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
