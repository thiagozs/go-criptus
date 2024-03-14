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
