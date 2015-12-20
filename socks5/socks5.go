// Package socks5 contains constants defined in https://tools.ietf.org/rfc/rfc1928.txt and functions
// to read and write socks5 messages.
package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
)

// Authentication methods.
const (
	AuthenticationNone             = 0x00
	AuthenticationGSSAPI           = 0x01
	AuthenticationUsernamePassword = 0x02
	AuthenticationNoAcceptable     = 0xFF
)

// Socks5 address type.
const (
	AddressTypeIPv4       = 0x01
	AddressTypeDomainName = 0x03
	AddressTypeIPv6       = 0x04
)

// Addr is socks5 address including address type, host and port.
type Addr []byte

// Socks5 request commands.
const (
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03
)

const (
	kVersion = 0x05
)

const (
	// The longest possible socks5 message should composes of domain
	// name and other short fields.
	kMaxMessageSize = 255 + 20
)

// Error is the interface that implemented by all socks errors.
type Error interface {
	error

	// Socks5Error is a no-op function that serves to distinguish
	// socks errors from other errors.
	Socks5Error()
}

// RFCError represents errors specifed in RFC 1928.
type RFCError int

const (
	ErrSucceeded RFCError = iota
	ErrGeneralFailure
	ErrNotAllowedByRuleset
	ErrNetworkUnreachable
	ErrHostUnreachable
	ErrConnectionRefused
	ErrTTLExpired
	ErrCommandNotSupported
	ErrAddressTypeNotSupported
)

var rfcErrors = map[RFCError]string{
	ErrSucceeded:               "succeeded",
	ErrGeneralFailure:          "general SOCKS server failure",
	ErrNotAllowedByRuleset:     "connection not allowed by ruleset",
	ErrNetworkUnreachable:      "Network unreachable",
	ErrHostUnreachable:         "Host unreachable",
	ErrConnectionRefused:       "Connection refused",
	ErrTTLExpired:              "TTL expired",
	ErrCommandNotSupported:     "Command not supported",
	ErrAddressTypeNotSupported: "Address type not supported",
}

func (err RFCError) Error() string {
	if errstr, ok := rfcErrors[err]; ok {
		return errstr
	}
	return "not a socks error"
}

func (err RFCError) Errno() int {
	return int(err)
}

func (err RFCError) Socks5Error() {}

type UnsupportedVersionError int

func (err UnsupportedVersionError) Error() string {
	return fmt.Sprintf("only version 5 supported, got %d", int(err))
}

func (err UnsupportedVersionError) Socks5Error() {}

type ReservedValueError int

func (err ReservedValueError) Error() string {
	return fmt.Sprintf("reserved field must be 0, got %d", int(err))
}

func (err ReservedValueError) Socks5Error() {}

type stringError string

func (err stringError) Error() string {
	return string(err)
}

func (err stringError) Socks5Error() {}

// 1 byte type + min(variable domain name, IPv4, IPv6) + 2 port
const leastAddressSize = 1 + 1 + 2

const ipv4AddressSize = 1 + net.IPv4len + 2
const ipv6AddressSize = 1 + net.IPv6len + 2

var errInvalidSocks5Address = stringError("invalid socks5 address")

// ParseAddress parses socks5 address and returns its network type, host
// and port. The network type is one of "ip"(for domain name), "ip4",
// "ip6". On return, n is the number of bytes occupied by this addr, 0 on
// failure.
//
// Addresses returned from ReadAddress and ReadRequest should be parsed
// without error.
func ParseAddress(addr Addr) (n int, network, host string, port uint16, err error) {
	if len(addr) < leastAddressSize {
		return 0, "", "", 0, errInvalidSocks5Address
	}
	pos := 1
	switch addressType := addr[0]; addressType {
	case AddressTypeIPv4:
		if len(addr) < ipv4AddressSize {
			return 0, "", "", 0, errInvalidSocks5Address
		}
		network = "ip4"
		host = net.IP(addr[pos : pos+net.IPv4len]).String()
		pos += net.IPv4len
	case AddressTypeIPv6:
		if len(addr) < ipv6AddressSize {
			return 0, "", "", 0, errInvalidSocks5Address
		}
		network = "ip6"
		host = net.IP(addr[pos : pos+net.IPv6len]).String()
		pos += net.IPv6len
	case AddressTypeDomainName:
		l := int(addr[pos])
		if len(addr) < l+leastAddressSize {
			return 0, "", "", 0, errInvalidSocks5Address
		}
		network = "ip"
		pos += 1
		host = string(addr[pos : pos+l])
		pos += l
	default:
		return 0, "", "", 0, ErrAddressTypeNotSupported
	}
	port = binary.BigEndian.Uint16(addr[pos:])
	return pos + 2, network, host, port, nil
}

// ReadAuthMethods reads socks5 authentication methods from r.
func ReadAuthMethods(r io.Reader) (nbytes int, methods []byte, err error) {
	var buf [kMaxMessageSize]byte

	nbytes, err = io.ReadFull(r, buf[:2])
	if err != nil {
		return nbytes, nil, err
	}
	if version := buf[0]; version != kVersion {
		return 2, nil, ErrGeneralFailure
	}
	nmethods := int(buf[1])
	if nmethods == 0 {
		return 2, nil, nil
	}

	rd, err := io.ReadFull(r, buf[:nmethods])
	nbytes += rd
	if err != nil {
		return nbytes, nil, err
	}
	return nbytes, buf[:nmethods], nil
}

// WriteAuthMethod writes socks5 authentication method selection reply to w.
func WriteAuthMethod(w io.Writer, method byte) (int, error) {
	return w.Write([]byte{kVersion, method})
}

// ReadAddress reads socks5 address from r.
func ReadAddress(r io.Reader) (n int, addr Addr, err error) {
	var buf [kMaxMessageSize]byte
	n, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return
	}

	var l int
	switch addressType := buf[0]; addressType {
	case AddressTypeIPv4:
		l = 4
	case AddressTypeIPv6:
		l = 16
	case AddressTypeDomainName:
		if _, err = io.ReadFull(r, buf[n:n+1]); err != nil {
			return n, nil, ErrAddressTypeNotSupported
		}
		l = int(buf[n])
		n += 1
	default:
		return n, nil, ErrAddressTypeNotSupported
	}

	l += 2 //port number
	rd, err := io.ReadFull(r, buf[n:n+l])
	n += rd
	if err != nil {
		return
	}
	return n, buf[:n], nil
}

// ReadCmdRequest reads socks5 command request from r.
func ReadCmdRequest(r io.Reader) (n int, cmd int, addr Addr, err error) {
	var buf [3]byte
	n, err = io.ReadFull(r, buf[:3])
	if err != nil {
		return
	}
	if version := buf[0]; version != kVersion {
		err = UnsupportedVersionError(version)
		return
	}
	switch cmd = int(buf[1]); cmd {
	case CmdConnect, CmdBind, CmdUDPAssociate:
	default:
		err = ErrCommandNotSupported
		return
	}
	if reserved := buf[2]; reserved != 0 {
		err = ReservedValueError(reserved)
		return
	}
	rd, addr, err := ReadAddress(r)
	return n + rd, cmd, addr, err
}

var fallbackAddress = [7]byte{AddressTypeIPv4}

func saveHost(buf []byte, host string) (int, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip := ip.To4(); ip != nil {
			buf[0] = AddressTypeIPv4
			copy(buf[1:], []byte(ip))
			return 4 + 1, nil
		} else {
			buf[0] = AddressTypeIPv6
			ip = ip.To16()
			copy(buf[1:], []byte(ip))
			return 16 + 1, nil
		}
	} else {
		buf[0] = AddressTypeDomainName
		l := len(host)
		if l > math.MaxUint8 {
			return 0, stringError(fmt.Sprintf("domain name too long, length %d: %s", l, host))
		}
		buf[1] = byte(l)
		copy(buf[2:], host)
		return l + 2, nil
	}
}

// WriteCmdReply writes command reply to w. If rep is not 0 or address
// is empty, zero IPv4 address is written. If address is invalid, error
// of type *net.AddrError returned.
func WriteCmdReply(w io.Writer, rep byte, address string) (int, error) {
	var buf [kMaxMessageSize]byte
	buf[0] = kVersion
	buf[1] = rep
	buf[2] = 0

	if rep != 0 || address == "" {
		copy(buf[3:], fallbackAddress[:])
		return w.Write(buf[:10])
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return 0, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, &net.AddrError{fmt.Sprintf("invalid port number: %s", portStr), address}
	}

	n, err := saveHost(buf[3:], host)
	if err != nil {
		return 0, err
	}
	n += 3
	binary.BigEndian.PutUint16(buf[n:], uint16(port))
	return w.Write(buf[:n+2])
}
