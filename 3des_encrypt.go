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

func NewTripleDesEncrypt(specialSign, key string) (*TripleDesEncrypt, error) {
	if len(key) == 0 {
		return nil, errors.New("need the key to encrypt, please add it. ")
	}

	if len(specialSign) == 0 {
		specialSign = BaseSpecialSign
	}

	specialSign = formatSpecialSign(specialSign, key, TripleEncrypt)

	return &TripleDesEncrypt{
		SpecialSign: specialSign,
		Key:         key,
		KeyType:     TripleEncrypt,
	}, nil
}

func (t *TripleDesEncrypt) getPrefix(length int) string {
	if len(t.SpecialSign)%2 == 0 {
		return t.SpecialSign[len(t.SpecialSign)-length:]
	}

	return t.SpecialSign[:length]
}

func (t *TripleDesEncrypt) generateTripleDesKey(id interface{}) []byte {
	idStr := cast.ToString(id)
	length := t.KeyType.Length() - len(idStr) - len(t.Key)

	buf := make([]byte, 0, t.KeyType.Length())

	prefix := t.getPrefix(length)

	buf = append(buf, []byte(prefix)...)
	buf = append(buf, []byte(idStr)...)
	buf = append(buf, []byte(t.Key)...)

	if len(buf) > 24 {
		buf = buf[:t.KeyType.Length()+1]
	}

	return buf
}

func (t *TripleDesEncrypt) SecretEncrypt(secret interface{}, fields ...interface{}) (string, error) {
	number := 0
	for i := range fields {
		number += fields[i].(int)
	}

	if secret == nil {
		return "", errors.New("need the secret to encrypt")
	}

	desKey := t.generateTripleDesKey(number)

	ans, err := t.tripleDesEncrypt(cast.ToString(secret), desKey)
	if err != nil {
		return "", err
	}

	return ans, nil
}

func (t *TripleDesEncrypt) SecretDecrypt(secret interface{}, fields ...interface{}) (string, error) {
	number := 0
	for i := range fields {
		number += fields[i].(int)
	}

	if secret == "" {
		return "", errors.New("need the secret to decrypt")
	}

	aesKey := t.generateTripleDesKey(number)

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
