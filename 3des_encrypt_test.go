package criptus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test3DesEncrypt(t *testing.T) {
	specialSign := "][;,[2psldp0981zx;./"
	key := "112233"
	secret := "this is a secret"

	tDesEncrypt, err := NewTripleDesEncrypt(specialSign, key)
	assert.NoError(t, err)

	ans, err := tDesEncrypt.SecretEncrypt(secret, 12)
	assert.NoError(t, err)

	a, err := tDesEncrypt.SecretDecrypt(ans, 12)
	assert.NoError(t, err)

	assert.Equal(t, secret, a)

}
