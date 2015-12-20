// Package crypto provides interface for cipher method providers.
// Clients can using those cipher methods via io.ReadWriter interface.
package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Cipher is the interface that implemented by cipher provider.
type Cipher interface {
	KeyLen() int
	IVLen() int
	NewEncrypter(key, iv []byte) (cipher.Stream, error)
	NewDecrypter(key, iv []byte) (cipher.Stream, error)
}

// KeyGenerator is cipher key generator. For given generator, it must
// generate the same key for the same input.
type KeyGenerator func(keyLen int) []byte

var ciphers = map[string]Cipher{}

func generateIV(ivLen int) []byte {
	iv := make([]byte, ivLen)
	_, err := rand.Read(iv)
	if err != nil {
		panic(err)
	}
	return iv
}

type stream struct {
	c         Cipher
	rw        io.ReadWriter
	key       []byte
	readErr   error
	writeErr  error
	writeBuf  []byte
	encrypter cipher.Stream
	decrypter cipher.Stream
}

type UnsupportedCipherMethodError string

func (name UnsupportedCipherMethodError) Error() string {
	return fmt.Sprintf("unsupported cipher method: %s", string(name))
}

type DuplicatedCipherMethodError string

func (name DuplicatedCipherMethodError) Error() string {
	return fmt.Sprintf("%s already registered", string(name))
}

// Register makes a cipher implementation available by the provided
// name. If Register is called twice with the same name or if cipher
// is nil, it panics.
func Register(name string, cipher Cipher) {
	if cipher == nil {
		panic("shadowsocks/crypto: trying register nil cipher")
	}
	if _, existed := ciphers[name]; existed {
		panic(DuplicatedCipherMethodError(name))
	}
	ciphers[name] = cipher
}

// NewStream wraps rw through stream cipher provided by cipherName.
// On Read, first few bytes will be interpreted as iv used for
// decryption. On Write, plaintext iv will be prepended in first call
// for read end decryption.
func NewStream(cipherName string, keyGen KeyGenerator, rw io.ReadWriter) (io.ReadWriter, error) {
	c, ok := ciphers[cipherName]
	if !ok {
		return nil, UnsupportedCipherMethodError(cipherName)
	}

	key := keyGen(c.KeyLen())
	iv := generateIV(c.IVLen())

	encrypter, err := c.NewEncrypter(key, iv)
	if err != nil {
		return nil, err
	}

	s := &stream{
		c:         c,
		rw:        rw,
		key:       key,
		writeBuf:  iv,
		encrypter: encrypter,
		decrypter: nil}
	return s, nil
}

// Read implements the io.Reader interface.
func (s *stream) Read(b []byte) (int, error) {
	if s.readErr != nil {
		return 0, s.readErr
	}

	if s.decrypter == nil {
		iv := make([]byte, s.c.IVLen())
		_, s.readErr = io.ReadFull(s.rw, iv)
		if s.readErr != nil {
			return 0, s.readErr
		}
		s.decrypter, s.readErr = s.c.NewDecrypter(s.key, iv)
		if s.readErr != nil {
			return 0, s.readErr
		}
	}

	var n int
	n, s.readErr = s.rw.Read(b)
	if n != 0 {
		data := b[:n]
		s.decrypter.XORKeyStream(data, data)
	}
	return n, s.readErr
}

// Write implements the io.Writer interface.
func (s *stream) Write(b []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}

	// io.Writer says: "Write must not modify the slice data, even temporarily."
	s.writeBuf = append(s.writeBuf, b...)
	data := s.writeBuf[len(s.writeBuf)-len(b):]
	s.encrypter.XORKeyStream(data, data)

	var n int
	n, s.writeErr = s.rw.Write(s.writeBuf)
	if n != 0 {
		s.writeBuf = s.writeBuf[n:]
	}
	return len(b), s.writeErr
}
