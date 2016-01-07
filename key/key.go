// Package key defines function to create key generator conformed to
// official shadowsocks implementation.
package key

import (
	"crypto/md5"

	"github.com/kezhuw/shadowsocks/crypto"
)

// NewGenerator creates a key generator that comform to official
// shadowsocks implementation.
func NewGenerator(password string) crypto.KeyGenerator {
	return func(keyLen int) []byte {
		h := md5.New()
		key := make([]byte, 0, keyLen+md5.Size)
		var lastDigest []byte
		for len(key) < keyLen {
			h.Reset()
			h.Write(lastDigest)
			h.Write([]byte(password))
			key = h.Sum(key)
			lastDigest = key[len(key)-md5.Size:]
		}
		return key[:keyLen]
	}
}
