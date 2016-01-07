// Package aes implements cipher methods based on AES encryption.
package aes

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/kezhuw/shadowsocks/crypto"
)

type aesCipher struct {
	keyLen int
	ivLen  int
}

var ciphers = map[string]*aesCipher{
	"aes-128-cfb": {16, 16},
	"aes-192-cfb": {24, 16},
	"aes-256-cfb": {32, 16},
}

func (c *aesCipher) KeyLen() int {
	return c.keyLen
}

func (c *aesCipher) IVLen() int {
	return c.ivLen
}

func (c *aesCipher) NewEncrypter(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBEncrypter(block, iv), nil
}

func (c *aesCipher) NewDecrypter(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

func init() {
	for name, c := range ciphers {
		crypto.Register(name, c)
	}
}
