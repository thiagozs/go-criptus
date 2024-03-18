package criptus

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/spf13/cast"
)

type TripleDesEncrypt struct {
	SpecialSign string
	Key         string
	KeyType     TripleKeyType
}

func New3DESEncrypt(opts ...T3DESOptions) (*TripleDesEncrypt, error) {

	params, err := newT3DESParams(opts...)
	if err != nil {
		return nil, err
	}

	if params.GetKind() == 0 {
		params.SetKind(TripleEncrypt128)
	}

	if len(params.GetKey()) == 0 {
		return nil, errors.New("need the key to encrypt, please add it. ")
	}

	if len(params.GetSpecialSign()) == 0 {
		params.SetSpecialSign(BaseSpecialSign)
	}

	specialSign := formatSpecialSign(params.GetSpecialSign(),
		params.GetKey(), params.GetKind())

	return &TripleDesEncrypt{
		SpecialSign: specialSign,
		Key:         params.GetKey(),
		KeyType:     params.GetKind(),
	}, nil
}

func (t *TripleDesEncrypt) getPrefix(length int) string {
	if len(t.SpecialSign)%2 == 0 {
		return t.SpecialSign[len(t.SpecialSign)-length:]
	}

	return t.SpecialSign[:length]
}

func (t *TripleDesEncrypt) generateDesKey() ([]byte, error) {
	var key []byte

	switch t.KeyType {
	case TripleEncrypt128:
		// For 128-bit keys, use K1 and K2, and repeat K1
		if len(t.Key) < 16 { // Ensure the base key is at least 16 bytes
			return nil, errors.New("base key too short for 128-bit encryption")
		}

		// Use the first 8 bytes for K1 and the next 8 bytes for K2
		K1 := t.Key[:8]
		K2 := t.Key[8:16]

		// K1, K2
		key = append([]byte(K1), []byte(K2)...)
		// Repeat K1 to form K1, K2, K1
		key = append(key, []byte(K1)...)

	case TripleEncrypt192:
		if len(t.Key) < 24 { // Ensure the base key is at least 24 bytes
			return nil, errors.New("base key too short for 192-bit encryption")
		}

		// Use the first 24 bytes directly for K1, K2, K3
		key = []byte(t.Key[:24])

	default:
		return nil, errors.New("invalid key type")
	}

	return key, nil
}

func (t *TripleDesEncrypt) SecretEncrypt(secret interface{}) (string, error) {
	if secret == nil {
		return "", errors.New("need the secret to encrypt")
	}

	desKey, err := t.generateDesKey()
	if err != nil {
		return "", err
	}

	ans, err := t.tripleDesEncrypt(cast.ToString(secret), desKey)
	if err != nil {
		return "", err
	}

	return ans, nil
}

func (t *TripleDesEncrypt) SecretDecrypt(secret interface{}) (string, error) {
	if secret == "" {
		return "", errors.New("need the secret to decrypt")
	}

	aesKey, err := t.generateDesKey()
	if err != nil {
		return "", err
	}

	b, err := t.tripleDesDecrypt(cast.ToString(secret), aesKey)
	if err != nil {
		return "", nil
	}

	return string(b), nil
}

func (t *TripleDesEncrypt) tripleDesEncrypt(origData string, key []byte) (string, error) {
	encodeByte := []byte(origData)

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}

	encodeByte = pkcs5Padding(encodeByte, block.BlockSize())

	blockMode := cipher.NewCBCEncrypter(block, key[:t.KeyType.Block()])

	crypted := make([]byte, len(encodeByte))

	blockMode.CryptBlocks(crypted, encodeByte)

	hexStr := fmt.Sprintf("%x", crypted)

	return hexStr, nil
}

func (t *TripleDesEncrypt) tripleDesDecrypt(decodeStr string, key []byte) ([]byte, error) {
	decodeBytes, err := hex.DecodeString(decodeStr)
	if err != nil {
		return nil, err
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, key[:t.KeyType.Block()])

	origData := make([]byte, len(decodeBytes))

	blockMode.CryptBlocks(origData, decodeBytes)

	origData = pkcs5UnPadding(origData)

	return origData, nil
}
