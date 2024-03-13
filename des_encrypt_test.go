package criptus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDesSecret(t *testing.T) {
	specialSign := "12345678901"
	key := "458796"
	secret := "this is a secret"

	des, err := NewDesEncrypt(specialSign, key)
	assert.NoError(t, err)

	str, err := des.SecretEncrypt(secret)
	assert.NoError(t, err)

	ans, err := des.SecretDecrypt(str)
	assert.NoError(t, err)

	assert.Equal(t, secret, ans)
}
