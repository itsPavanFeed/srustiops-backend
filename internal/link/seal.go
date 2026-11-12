package link

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// SealTo encrypts plaintext to a tenant's X25519 public key, so only that
// tenant can read it (central queues webhooks this way while a tenant is
// offline). The envelope is the ephemeral public key, the nonce and the
// AES-256-GCM ciphertext; aad binds it to its tenant and purpose.
func SealTo(pub *ecdh.PublicKey, aad, plaintext []byte) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	gcm, err := sealCipher(shared, eph.PublicKey().Bytes(), pub.Bytes())
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	out := append(eph.PublicKey().Bytes(), nonce...)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

// OpenWith decrypts an envelope from SealTo with the tenant's private key.
func OpenWith(priv *ecdh.PrivateKey, aad, envelope []byte) ([]byte, error) {
	if len(envelope) < 32+12+16 {
		return nil, errors.New("sealed envelope is too short")
	}
	ephPub, err := ecdh.X25519().NewPublicKey(envelope[:32])
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	gcm, err := sealCipher(shared, envelope[:32], priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	n := gcm.NonceSize()
	return gcm.Open(nil, envelope[32:32+n], envelope[32+n:], aad)
}

func sealCipher(shared, ephPub, recipient []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, ephPub...), recipient...), "srustiops sealed v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
