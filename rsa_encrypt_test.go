package criptus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRsaEncrypt(t *testing.T) {
	secret := "this is a secret"
	rsa, err := NewRsaEncrypt()
	assert.NoError(t, err)

	err = rsa.SaveRsaKey()
	assert.NoError(t, err)

	sec, err := rsa.RsaEncrypt(secret, rsa.PublishKeyPath)
	assert.NoError(t, err)

	toStr := rsa.ToString(sec)
	toByte := rsa.ToByte(toStr)

	ans, err := rsa.RsaDecrypt(toByte, rsa.PrivateKeyPath)
	assert.NoError(t, err)

	assert.Equal(t, secret, ans)
}
