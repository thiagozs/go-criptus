package criptus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDesSecret(t *testing.T) {
	specialSign := "12345678901"
	key := "458796"
	secret := "this is a secret"

	opts := []DESOptions{
		DESWithKey(key),
		DESWithSpecialSign(specialSign),
		DESWithKeyType(DesEncrypt56),
	}

	des, err := NewDesEncrypt(opts...)
	assert.NoError(t, err)

	str, err := des.SecretEncrypt(secret)
	assert.NoError(t, err)

	ans, err := des.SecretDecrypt(str)
	assert.NoError(t, err)

	assert.Equal(t, secret, ans)
}
