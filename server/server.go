// Package server implements a proxy to accept incoming ciphertext
// connection and relay network traffics between client and destination.
package server

import (
	"io"
	"net"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/kezhuw/shadowsocks/config"
	"github.com/kezhuw/shadowsocks/crypto"
	"github.com/kezhuw/shadowsocks/key"
	"github.com/kezhuw/shadowsocks/netaddr"
	"github.com/kezhuw/shadowsocks/socks5"
	"github.com/kezhuw/shadowsocks/tunnel"
)

// Serve listens on servers, accepting and serving incoming connection.
func Serve(servers []config.Server) {
	var wg sync.WaitGroup
	wg.Add(len(servers))
	for _, options := range servers {
		go handleServer(options, &wg)
	}
	wg.Wait()
}

func handleServer(options config.Server, wg *sync.WaitGroup) {
	defer wg.Done()

	serverAddr := options.Listen.ToTCP()

	listener, err := net.Listen(serverAddr.Network(), serverAddr.HostPort())
	if err != nil {
		log.Errorf("server[%s] can't listen on server address: %s", serverAddr, err)
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok && (err.Temporary() || err.Timeout()) {
				continue
			}
			log.Errorf("server[%s] accept error: %s", serverAddr, err)
			return
		}
		go handleConnection(conn, &options)
	}
}

func handleConnection(conn net.Conn, options *config.Server) {
	localAddr := netaddr.FromNetAddr(conn.RemoteAddr())
	serverAddr := options.Listen.ToTCP()

	log.Infof("server[%s] new connection from %s", serverAddr, localAddr)

	defer conn.Close()

	localStream, err := crypto.NewStream(options.Encryption, key.NewGenerator(options.Password), conn)

	dstAddr, err := readAddress(localStream)
	if err != nil {
		log.Warnf("server[%s] local[%s] fail to read destination address: %s", serverAddr, localAddr, err)
		return
	}

	dstConn, err := net.Dial(dstAddr.Network(), dstAddr.HostPort())
	if err != nil {
		log.Warnf("server[%s] local[%s] can't connect to destination address: %s", serverAddr, localAddr, err)
		return
	}
	defer dstConn.Close()

	log.Infof("server[%s] local[%s] connected to %s", serverAddr, localAddr, dstAddr)

	err = tunnel.Copy(dstConn, localStream)
	if err != nil {
		log.Warnf("server[%s] local[%s] dst[%s] connection aborted: %s", serverAddr, localAddr, dstAddr, err)
	} else {
		log.Infof("server[%s] local[%s] dst[%s] connection closed", serverAddr, localAddr, dstAddr)
	}
}

func readAddress(r io.Reader) (*netaddr.Address, error) {
	_, addr, err := socks5.ReadAddress(r)
	if err != nil {
		return nil, err
	}
	_, net, host, port, _ := socks5.ParseAddress(addr)
	return netaddr.NewAddress(net, host, port).ToTCP(), nil
}
