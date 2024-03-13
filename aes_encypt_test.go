package criptus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAesSecret(t *testing.T) {

	cases := []struct {
		name        string
		specialSign string
		key         string
		str         string
		kind        AesKeyType
		mode        AesModeType
	}{
		{
			"AES-192_CFB",
			"123456789012345678901234",
			"123456",
			"this is a secret",
			AesEncrypt192,
			AesModeTypeCFB,
		},
		{
			"AES-256_CBC",
			"123456789012345678901234567890123",
			"123456",
			"this is a secret",
			AesEncrypt256,
			AesModeTypeCBC,
		},
		{
			"AES-128_ECB",
			"1234567890",
			"123456",
			"this is a secret",
			AesEncrypt128,
			AesModeTypeECB,
		},
		{
			"AES-256_CTR",
			"12345678901234567890123456789012",
			"123456",
			"this is a secret",
			AesEncrypt256,
			AesModeTypeCTR,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := NewAesEncrypt(c.specialSign, c.key, "", c.kind, c.mode)
			if err != nil {
				t.Errorf("Error: %s\n", err)
			}

			a, err := e.SecretEncrypt(c.str)
			assert.NoError(t, err, "Encryption should not error")

			b, err := e.SecretDecrypt(a)
			assert.NoError(t, err, "Decryption should not error")
			assert.Equal(t, c.str, b, "Decrypted text should match the original")

		})
	}
}
