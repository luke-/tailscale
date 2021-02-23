// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// netstack doesn't build on 32-bit machines (https://github.com/google/gvisor/issues/5241)
// +build amd64 arm64 ppc64le riscv64 s390x

// Package netstack wires up gVisor's netstack into Tailscale.
package netstack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"inet.af/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/tstun"
)

// Impl contains the state for the netstack implementation,
// and implements wgengine.FakeImpl to act as a userspace network
// stack when Tailscale is running in fake mode.
type Impl struct {
	ipstack *stack.Stack
	linkEP  *channel.Endpoint
	tundev  *tstun.TUN
	e       wgengine.Engine
	mc      *magicsock.Conn
	logf    logger.Logf
}

const nicID = 1

// Create creates and populates a new Impl.
func Create(logf logger.Logf, tundev *tstun.TUN, e wgengine.Engine, mc *magicsock.Conn) (wgengine.FakeImpl, error) {
	if mc == nil {
		return nil, errors.New("nil magicsock.Conn")
	}
	if tundev == nil {
		return nil, errors.New("nil tundev")
	}
	if logf == nil {
		return nil, errors.New("nil logger")
	}
	if e == nil {
		return nil, errors.New("nil Engine")
	}
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	const mtu = 1500
	linkEP := channel.New(512, mtu, "")
	if err := ipstack.CreateNIC(nicID, linkEP); err != nil {
		return nil, fmt.Errorf("could not create netstack NIC: %w", err)
	}
	// Add 0.0.0.0/0 default route.
	ipv4Subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 4)), tcpip.AddressMask(strings.Repeat("\x00", 4)))
	ipv6Subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 16)), tcpip.AddressMask(strings.Repeat("\x00", 16)))
	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         nicID,
		},
		{
			Destination: ipv6Subnet,
			NIC:         nicID,
		},
	})
	ns := &Impl{
		logf:    logf,
		ipstack: ipstack,
		linkEP:  linkEP,
		tundev:  tundev,
		e:       e,
		mc:      mc,
	}
	return ns, nil
}

// Start sets up all the handlers so netstack can start working. Implements
// wgengine.FakeImpl.
func (ns *Impl) Start() error {
	ns.e.AddNetworkMapCallback(ns.updateIPs)
	tcpFwd := tcp.NewForwarder(ns.ipstack, 0, 16, ns.acceptTCP)
	udpFwd := udp.NewForwarder(ns.ipstack, ns.acceptUDP)
	ns.ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	ns.ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	go ns.injectOutbound()
	ns.tundev.PostFilterIn = ns.injectInbound

	return nil
}

func (ns *Impl) updateIPs(nm *netmap.NetworkMap) {
	oldIPs := make(map[tcpip.Address]bool)
	for _, ip := range ns.ipstack.AllAddresses()[nicID] {
		oldIPs[ip.AddressWithPrefix.Address] = true
	}
	newIPs := make(map[tcpip.Address]bool)
	for _, ip := range nm.Addresses {
		newIPs[tcpip.Address(ip.IP.IPAddr().IP)] = true
	}

	ipsToBeAdded := make(map[tcpip.Address]bool)
	for ip := range newIPs {
		if !oldIPs[ip] {
			ipsToBeAdded[ip] = true
		}
	}
	ipsToBeRemoved := make(map[tcpip.Address]bool)
	for ip := range oldIPs {
		if !newIPs[ip] {
			ipsToBeRemoved[ip] = true
		}
	}

	for ip := range ipsToBeRemoved {
		err := ns.ipstack.RemoveAddress(nicID, ip)
		if err != nil {
			ns.logf("netstack: could not deregister IP %s: %v", ip, err)
		} else {
			ns.logf("[v2] netstack: deregistered IP %s", ip)
		}
	}
	for ip := range ipsToBeAdded {
		var err *tcpip.Error
		if ip.To4() == "" {
			err = ns.ipstack.AddAddress(nicID, ipv6.ProtocolNumber, ip)
		} else {
			err = ns.ipstack.AddAddress(nicID, ipv4.ProtocolNumber, ip)
		}
		if err != nil {
			ns.logf("netstack: could not register IP %s: %v", ip, err)
		} else {
			ns.logf("[v2] netstack: registered IP %s", ip)
		}
	}
}

func (ns *Impl) dialTCP(address string) (*gonet.TCPConn, error) {
	remoteIPPort, err := netaddr.ParseIPPort(address)
	if err != nil {
		return nil, fmt.Errorf("could not parse IP:port: %w", err)
	}
	remoteAddress := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.Address(remoteIPPort.TCPAddr().IP),
		Port: remoteIPPort.Port,
	}
	var ipType tcpip.NetworkProtocolNumber
	if remoteIPPort.IP.Is4() {
		ipType = ipv4.ProtocolNumber
	} else {
		ipType = ipv6.ProtocolNumber
	}

	return gonet.DialTCP(ns.ipstack, remoteAddress, ipType)
}

func (ns *Impl) injectOutbound() {
	for {
		packetInfo, ok := ns.linkEP.ReadContext(context.Background())
		if !ok {
			ns.logf("[v2] ReadContext-for-write = ok=false")
			continue
		}
		pkt := packetInfo.Pkt
		hdrNetwork := pkt.NetworkHeader()
		hdrTransport := pkt.TransportHeader()

		full := make([]byte, 0, pkt.Size())
		full = append(full, hdrNetwork.View()...)
		full = append(full, hdrTransport.View()...)
		full = append(full, pkt.Data.ToView()...)

		ns.logf("[v2] packet Write out: % x", full)
		if err := ns.tundev.InjectOutbound(full); err != nil {
			log.Printf("netstack inject outbound: %v", err)
			return
		}

	}
}

func (ns *Impl) injectInbound(p *packet.Parsed, t *tstun.TUN) filter.Response {
	var pn tcpip.NetworkProtocolNumber
	switch p.IPVersion {
	case 4:
		pn = header.IPv4ProtocolNumber
	case 6:
		pn = header.IPv6ProtocolNumber
	}
	ns.logf("[v2] packet in (from %v): % x", p.Src, p.Buffer())
	vv := buffer.View(append([]byte(nil), p.Buffer()...)).ToVectorisedView()
	packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: vv,
	})
	ns.linkEP.InjectInbound(pn, packetBuf)
	return filter.Accept
}

func (ns *Impl) acceptTCP(r *tcp.ForwarderRequest) {
	ns.logf("[v2] ForwarderRequest: %v", r)
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	localAddr, err := ep.GetLocalAddress()
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	c := gonet.NewTCPConn(&wq, ep)
	go ns.forwardTCP(c, net.JoinHostPort("100.101.102.103", strconv.Itoa(int(localAddr.Port))))
}

func (ns *Impl) forwardTCP(client *gonet.TCPConn, address string) {
	ns.logf("[v2] netstack: forwarding to address %s", address)
	server, err := ns.dialTCP(address)
	if err != nil {
		ns.logf("netstack: could not connect to server %s: %s", address, err)
		client.Close()
		return
	}
	go io.Copy(server, client)
	go io.Copy(client, server)
}

func (ns *Impl) acceptUDP(r *udp.ForwarderRequest) {
	ns.logf("[v2] UDP ForwarderRequest: %v", r)
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		ns.logf("Could not create endpoint, exiting")
		return
	}
	c := gonet.NewUDPConn(ns.ipstack, &wq, ep)
	go echoUDP(c)
}

func echoUDP(c *gonet.UDPConn) {
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			break
		}
		c.Write(buf[:n])
	}
	c.Close()
}
