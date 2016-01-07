// Package config parses configurations used by other components.
package config

import (
	"fmt"
	"time"

	"github.com/kezhuw/shadowsocks/netaddr"
	"github.com/kezhuw/toml"
)

// Remote specifies a remote endpoint and its encryption scheme.
type Remote struct {
	Address    *netaddr.Address
	Password   string
	Encryption string
}

// Local specifies a endpoint running at local to proxy incoming traffic
// through remote.
type Local struct {
	Listen  *netaddr.Address
	Remote  Remote
	Timeout time.Duration
}

// Server specifies a end point run at remote to proxy incoming traffic
// to destination.
type Server struct {
	Listen     *netaddr.Address
	Password   string
	Encryption string
	Timeout    time.Duration
}

// Config contains configurations for local and remote server.
type Config struct {
	Locals  []Local
	Servers []Server
}

// Parse parses TOML formatted configrations from content.
func Parse(content []byte) (*Config, error) {
	var rawConfig rawConfig
	if err := toml.Unmarshal(content, &rawConfig); err != nil {
		return nil, err
	}
	return convert(rawConfig)
}

type rawAddress struct {
	Net  string
	Host string
	Port uint16
}

type rawRemote struct {
	Net  string
	Host string
	Port uint16
	Role string
}

type rawRole struct {
	Name       string
	Password   string
	Encryption string
}

type rawLocal struct {
	Listen  rawAddress
	Remote  rawRemote
	Timeout string
}

type rawServer struct {
	Role    string
	Listen  rawAddress
	Timeout string
}

type rawConfig struct {
	Roles   []rawRole
	Locals  []rawLocal
	Servers []rawServer
}

type configError struct{ err error }

func newAddr(net, host string, port uint16, isLocal bool) (addr *netaddr.Address) {
	switch net {
	case "", "ip", "ip4", "ip6", "tcp", "tcp4", "tcp6":
		addr = netaddr.NewAddress(net, host, port)
	case "udp", "udp4", "udp6":
		if isLocal {
			goto address_error
		}
		addr = netaddr.NewAddress(net, host, port)
	default:
		goto address_error
	}
	if addr != nil {
		return addr
	}
address_error:
	panic(configError{fmt.Errorf("invalid configured address: net %q, host %q, port %d", net, host, port)})
}

func parseTimeout(t string) time.Duration {
	if t == "" {
		return 0
	}
	d, err := time.ParseDuration(t)
	if err != nil {
		panic(configError{err})
	}
	return d
}

func newAddrFromRawAddress(raw *rawAddress) *netaddr.Address {
	return newAddr(raw.Net, raw.Host, raw.Port, true)
}

func newAddrFromRawRemote(raw *rawRemote) *netaddr.Address {
	return newAddr(raw.Net, raw.Host, raw.Port, false)
}

func convert(raw rawConfig) (config *Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(configError); ok {
				config = nil
				err = e.err
				return
			}
			panic(r)
		}
	}()

	roles := make(map[string]rawRole, len(raw.Roles))
	for _, role := range raw.Roles {
		roles[role.Name] = role
	}

	config = new(Config)
	for _, rawOptions := range raw.Locals {
		role, ok := roles[rawOptions.Remote.Role]
		if !ok {
			return nil, fmt.Errorf("role %q not found", rawOptions.Remote.Role)
		}
		remoteAddr := newAddrFromRawRemote(&rawOptions.Remote)
		options := Local{
			Listen:  newAddrFromRawAddress(&rawOptions.Listen),
			Remote:  Remote{remoteAddr, role.Password, role.Encryption},
			Timeout: parseTimeout(rawOptions.Timeout),
		}
		config.Locals = append(config.Locals, options)
	}
	for _, rawOptions := range raw.Servers {
		role, ok := roles[rawOptions.Role]
		if !ok {
			return nil, fmt.Errorf("role %q not found", rawOptions.Role)
		}
		options := Server{
			Listen:     newAddrFromRawAddress(&rawOptions.Listen),
			Password:   role.Password,
			Encryption: role.Encryption,
			Timeout:    parseTimeout(rawOptions.Timeout),
		}
		config.Servers = append(config.Servers, options)
	}
	return config, nil
}
