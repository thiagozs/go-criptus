package criptus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test3DesEncrypt(t *testing.T) {
	specialSign := "][;,[2psldp0981zx;./"
	key := "11223344556677881122334455667788" // Adjusted key length to 32 bytes
	secret := "this is a secret"

	opts := []T3DESOptions{
		T3DESWithKey(key),
		T3DESWithSpecialSign(specialSign),
		T3DESWithKind(TripleEncrypt128), // Assuming this is for 128-bit 3DES encryption
	}

	tDesEncrypt, err := New3DESEncrypt(opts...)
	assert.NoError(t, err)

	ans, err := tDesEncrypt.SecretEncrypt(secret)
	assert.NoError(t, err)

	a, err := tDesEncrypt.SecretDecrypt(ans)
	assert.NoError(t, err)

	assert.Equal(t, secret, a)
}
