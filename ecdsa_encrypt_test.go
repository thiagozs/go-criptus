package criptus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECDSA_EncryptAndDecrypt(t *testing.T) {
	curve, err := NewECDSA()
	assert.NoError(t, err)

	priv, pub, err := curve.GenerateKeys()
	assert.NoError(t, err)

	assert.NotNil(t, priv, "Private key is nil")
	assert.NotNil(t, pub, "Public key is nil")

	message := "Hello, ECDSA!"

	signature, err := curve.Sign(message, priv)
	assert.NoError(t, err)

	ok := curve.Verify(message, signature, pub)
	assert.Equal(t, true, ok, "Signature verification failed")
}

func TestECDSA_EncodeDecodePrivateKey(t *testing.T) {
	curve, err := NewECDSA()
	assert.NoError(t, err)

	priv, _, err := curve.GenerateKeys()
	assert.NoError(t, err)

	encoded, err := curve.EncodePrivate(priv)
	assert.NoError(t, err)

	decoded, err := curve.DecodePrivate(encoded)
	assert.NoError(t, err)

	assert.Equal(t, priv, decoded, "Decoded private key is different from original")
}

func TestECDSA_EncodeDecodePublicKey(t *testing.T) {
	curve, err := NewECDSA()
	assert.NoError(t, err)

	_, pub, err := curve.GenerateKeys()
	assert.NoError(t, err)

	encoded, err := curve.EncodePublic(pub)
	assert.NoError(t, err)

	decoded, err := curve.DecodePublic(encoded)
	assert.NoError(t, err)

	assert.Equal(t, pub, decoded, "Decoded public key is different from original")
}
