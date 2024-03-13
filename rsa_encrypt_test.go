package criptus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRsaEncrypt(t *testing.T) {
	secret := "this is a secret"
	rsa := NewRsaEncrypt(RsaBits1024, "", "", "", "")

	err := rsa.SaveRsaKey()
	assert.NoError(t, err)

	sec, err := rsa.RsaEncrypt(secret, rsa.PublishKeyPath)
	assert.NoError(t, err)

	encriptedStr := rsa.EncryptString(sec)
	srcByte := rsa.DecryptByte(encriptedStr)

	ans, err := rsa.RsaDecrypt(srcByte, rsa.PrivateKeyPath)
	assert.NoError(t, err)

	assert.Equal(t, secret, ans)
}
