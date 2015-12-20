// Package rc4 implements cipher methods based on RC4 encryption.
package rc4

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"github.com/kezhuw/shadowsocks/crypto"
)

type rc4Cipher struct {
	keyLen int
	ivLen  int
}

var ciphers = map[string]*rc4Cipher{
	"rc4-md5": {16, 16},
}

func (c *rc4Cipher) KeyLen() int {
	return c.keyLen
}

func (c *rc4Cipher) IVLen() int {
	return c.ivLen
}

func (c *rc4Cipher) NewEncrypter(key, iv []byte) (cipher.Stream, error) {
	return newStream(key, iv)
}

func (c *rc4Cipher) NewDecrypter(key, iv []byte) (cipher.Stream, error) {
	return newStream(key, iv)
}

func init() {
	for name, c := range ciphers {
		crypto.Register(name, c)
	}
}

func newStream(key, iv []byte) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	return rc4.NewCipher(h.Sum(nil))
}
