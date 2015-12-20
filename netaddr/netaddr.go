// Package netaddr defines type Address which is composed of ip address
// and port number used by transport layer TCP and UDP.
package netaddr

import (
	"fmt"
	"net"
	"strconv"
)

// Address represents internet address over ip protocols. It contains
// a port number used by transport layer TCP and UDP.
type Address struct {
	net  string
	host string
	port uint16
}

// NewAddress creates Address from net, host and port. Empty net is
// treated as "ip". If net is unrecogonized, nil is returned.
func NewAddress(net, host string, port uint16) *Address {
	switch net {
	case "":
		net = "ip"
	case "ip", "ip4", "ip6":
	case "tcp", "tcp4", "tcp6":
	case "udp", "udp4", "udp6":
	default:
		return nil
	}
	return &Address{net, host, port}
}

// FromNetAddr creates Address from net.Addr. Only *Address, *net.IPAddr,
// *net.TCPAddr and *net.UDPAddr are recogonized. For *net.IPAddr, Address
// with port number zero is returned.
func FromNetAddr(addr net.Addr) *Address {
	switch addr := addr.(type) {
	case *Address:
		return addr
	case *net.IPAddr:
		return &Address{addr.Network(), addr.IP.String(), 0}
	case *net.TCPAddr:
		return &Address{addr.Network(), addr.IP.String(), uint16(addr.Port)}
	case *net.UDPAddr:
		return &Address{addr.Network(), addr.IP.String(), uint16(addr.Port)}
	}
	return nil
}

// Network implements the net.Addr Network method.
func (addr *Address) Network() string {
	return addr.net
}

// String implements the net.Addr String method.
func (addr *Address) String() string {
	if addr == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s://%s", addr.net, addr.HostPort())
}

// Type classifies net of address to "ip", "tcp", "udp" categories.
// If net is unrecogonized, empty string is returned.
func (addr *Address) Type() string {
	switch addr.net {
	case "ip", "ip4", "ip6":
		return "ip"
	case "tcp", "tcp4", "tcp6":
		return "tcp"
	case "udp", "udp4", "udp6":
		return "udp"
	}
	return ""
}

// Net returns addr's net.
func (addr *Address) Net() string {
	return addr.net
}

// Host returns addr's host.
func (addr *Address) Host() string {
	return addr.host
}

// Port returns addr's port.
func (addr *Address) Port() uint16 {
	return addr.port
}

// HostPort returns addr's host and port in form "host:port" or
// "[host]:port" if host contains a colon or percent sign.
func (addr *Address) HostPort() string {
	return net.JoinHostPort(addr.host, strconv.Itoa(int(addr.port)))
}

// Parts returns addr's net, host, port as separate components.
func (addr *Address) Parts() (net, host string, port uint16) {
	return addr.net, addr.host, addr.port
}

// ToTCP converts addr to internet address in TCP network. If addr
// isn't in "ip" or "tcp" network, nil is returned.
func (addr *Address) ToTCP() *Address {
	switch addr.net {
	case "ip":
		return &Address{"tcp", addr.host, addr.port}
	case "ip4":
		return &Address{"tcp4", addr.host, addr.port}
	case "ip6":
		return &Address{"tcp6", addr.host, addr.port}
	case "tcp", "tcp4", "tcp6":
		return addr
	}
	return nil
}

// ToUDP converts addr to internet address in UDP network. If addr
// isn't in "ip" or "udp" network, nil is returned.
func (addr *Address) ToUDP() *Address {
	switch addr.net {
	case "ip":
		return &Address{"udp", addr.host, addr.port}
	case "ip4":
		return &Address{"udp4", addr.host, addr.port}
	case "ip6":
		return &Address{"udp6", addr.host, addr.port}
	case "udp", "udp4", "udp6":
		return addr
	}
	return nil
}
