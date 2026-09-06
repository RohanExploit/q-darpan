// Fixture: Go standard-library crypto, exercising selector_expression calls.
package tokens

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func NewRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func NewECKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func NewBlock(key []byte) (interface{}, error) {
	return aes.NewCipher(key)
}

func Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func LegacySum(data []byte) []byte {
	h := md5.New()
	return h.Sum(data)
}
