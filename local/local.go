// Package local implements a proxy to accept incoming plaintext
// connection and relay network traffics between client and remote server
// using configured cipher method.
package local

import (
	log "github.com/Sirupsen/logrus"
	"github.com/kezhuw/shadowsocks/config"
	"github.com/kezhuw/shadowsocks/crypto"
	"github.com/kezhuw/shadowsocks/key"
	"github.com/kezhuw/shadowsocks/netaddr"
	"github.com/kezhuw/shadowsocks/socks5"
	"github.com/kezhuw/shadowsocks/tunnel"
	"io"
	"net"
	"sync"
	"syscall"
)

// Serve listens on locals, accepting and serving incoming connection.
func Serve(locals []config.Local) {
	var wg sync.WaitGroup
	wg.Add(len(locals))
	for _, options := range locals {
		go handleLocal(options, &wg)
	}
	wg.Wait()
}

func handleLocal(options config.Local, wg *sync.WaitGroup) {
	defer wg.Done()

	localAddr := options.Listen.ToTCP()

	listener, err := net.Listen(localAddr.Network(), localAddr.HostPort())
	if err != nil {
		log.Errorf("local[%s] can't listen on local address: %s", localAddr, err)
		return
	}
	defer listener.Close()

	log.Infof("local[%s] listening ...", localAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok && (err.Temporary() || err.Timeout()) {
				continue
			}
			log.Errorf("local[%s] accept error: %s", localAddr, err)
			return
		}
		go handleConnection(conn, &options)
	}
}

func handleConnection(clientConn net.Conn, options *config.Local) {
	defer clientConn.Close()

	localAddr := options.Listen.ToTCP()
	clientAddr := netaddr.FromNetAddr(clientConn.RemoteAddr())

	log.Infof("local[%s] new connection from %s", localAddr, clientAddr)

	if err := handleHandshake(clientConn); err != nil {
		log.Errorf("local[%s] client[%s] handshake failed: %s", localAddr, clientAddr, err)
		return
	}

	dstAddr, err := readConnectAddress(clientConn)
	if err != nil {
		log.Errorf("local[%s] client[%s] fail to read destination address: %s", localAddr, clientAddr, err)
		replyCmdFailure(clientConn, err)
		return
	}

	remoteAddr := options.Remote.Address.ToTCP()
	remoteConn, err := net.Dial(remoteAddr.Net(), remoteAddr.HostPort())
	if err != nil {
		log.Errorf("local[%s] client[%s] remote[%s] can't connect to remote server: %s", localAddr, clientAddr, remoteAddr, err)
		replyCmdFailure(clientConn, err)
		return
	}
	defer remoteConn.Close()

	if err := replyCmdAddress(clientConn, remoteConn.LocalAddr()); err != nil {
		log.Warnf("local[%s] client[%s] fail to reply address for command request: %s", localAddr, clientAddr, err)
		return
	}

	remoteStream, err := crypto.NewStream(options.Remote.Encryption, key.NewGenerator(options.Remote.Password), remoteConn)
	if err != nil {
		log.Errorf("local[%s] remote[%s] fail to create cipher stream: %s", localAddr, remoteAddr, err)
		return
	}

	_, err = remoteStream.Write(dstAddr)
	if err != nil {
		log.Errorf("local[%s] remote[%s] fail to write destination addr to remote: %s", localAddr, remoteAddr, err)
		return
	}

	err = tunnel.Copy(remoteStream, clientConn)
	if err != nil {
		log.Warnf("local[%s] client[%s] remote[%s] connection aborted: %s", localAddr, clientAddr, remoteAddr, err)
	} else {
		log.Infof("local[%s] client[%s] remote[%s] connection closed", localAddr, clientAddr, remoteAddr)
	}
}

func handleHandshake(rw io.ReadWriter) error {
	_, _, err := socks5.ReadAuthMethods(rw)
	if err != nil {
		return err
	}
	_, err = socks5.WriteAuthMethod(rw, socks5.AuthenticationNone)
	return err
}

func readConnectAddress(rw io.ReadWriter) (addr []byte, err error) {
	_, cmd, addr, err := socks5.ReadCmdRequest(rw)
	if cmd != socks5.CmdConnect {
		return nil, socks5.ErrCommandNotSupported
	}
	return addr, err
}

func replyCmdFailure(w io.Writer, err error) {
	var replyErr socks5.RFCError
	switch err := err.(type) {
	case *net.DNSError:
		replyErr = socks5.ErrHostUnreachable
	case *net.OpError:
		switch {
		case err.Err == syscall.ECONNREFUSED:
			replyErr = socks5.ErrConnectionRefused
		case err.Err == syscall.EHOSTUNREACH:
			replyErr = socks5.ErrHostUnreachable
		default:
			replyErr = socks5.ErrGeneralFailure
		}
	case net.Error:
		replyErr = socks5.ErrNetworkUnreachable
	case socks5.RFCError:
	default:
		replyErr = socks5.ErrGeneralFailure
	}
	socks5.WriteCmdReply(w, byte(replyErr.Errno()), "")
}

func replyCmdAddress(w io.Writer, addr net.Addr) error {
	_, err := socks5.WriteCmdReply(w, 0, addr.String())
	return err
}
