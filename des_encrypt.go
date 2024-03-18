package criptus

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cast"
)

type DesEncrypt struct {
	SpecialSign string // Encryption and decryption will be based on this string of characters, if not, it will be based on DesBaseSpecialSign.
	Key         string // Key, it is recommended to use a 5-8 digit key
	Kind        DesKeyType
}

func NewDesEncrypt(opts ...DESOptions) (*DesEncrypt, error) {

	params, err := newDESParams(opts...)
	if err != nil {
		return nil, err
	}

	if len(params.GetKey()) == 0 {
		return nil, errors.New("need the key to encrypt, please add it. ")
	}

	if len(params.GetSpecialSign()) == 0 {
		params.SetSpecialSign(BaseSpecialSign)
	}

	if params.GetKeyType() == 0 {
		params.SetKeyType(DesEncrypt64)
	}

	specialSign := formatSpecialSign(params.GetSpecialSign(),
		params.GetKey(), params.GetKeyType())

	return &DesEncrypt{
		SpecialSign: specialSign,
		Key:         params.GetKey(),
		Kind:        params.GetKeyType(),
	}, nil
}

func (d *DesEncrypt) getPrefix(length int) string {
	if len(d.SpecialSign)%2 == 0 {
		return d.SpecialSign[len(d.SpecialSign)-length:]
	}
	return d.SpecialSign[:length]
}

func (d *DesEncrypt) generateDesKey(id interface{}) []byte {
	idStr := cast.ToString(id)
	length := d.Kind.Length() - len(idStr) - len(d.Key)
	buf := make([]byte, 0, d.Kind.Length())
	prefix := d.getPrefix(length)
	buf = append(buf, []byte(prefix)...)
	buf = append(buf, []byte(idStr)...)
	buf = append(buf, []byte(d.Key)...)
	if len(buf) > 8 {
		buf = buf[:d.Kind.Length()+1]
	}
	return buf
}

func (d *DesEncrypt) SecretEncrypt(secret interface{}, fields ...interface{}) (string, error) {
	number := 0
	for i := range fields {
		number += fields[i].(int)
	}
	if secret != "" {
		desKey := d.generateDesKey(number)
		ans, err := d.desEncrypt(cast.ToString(secret), desKey)
		if err != nil {
			return "", err
		}
		return ans, nil
	}
	return "", errors.New("need the secret to encrypt")
}

func (d *DesEncrypt) SecretDecrypt(secret interface{}, fields ...interface{}) (string, error) {
	number := 0
	for i := range fields {
		number += fields[i].(int)
	}

	if secret == "" {
		return "", errors.New("need the secret to decrypt")
	}

	aesKey := d.generateDesKey(number)
	b, err := d.desDecrypt(cast.ToString(secret), aesKey)
	if err != nil {
		return "", nil
	}

	return string(b), nil
}

func (d *DesEncrypt) desEncrypt(origData string, key []byte) (string, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Generate a random IV
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	encodeByte := pkcs5Padding([]byte(origData), block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, iv)

	crypted := make([]byte, len(encodeByte))
	blockMode.CryptBlocks(crypted, encodeByte)

	// Prepend IV to the ciphertext
	cryptedWithIV := append(iv, crypted...)

	hexStr := fmt.Sprintf("%x", cryptedWithIV)
	return hexStr, nil
}

func (d *DesEncrypt) desDecrypt(decodeStr string, key []byte) ([]byte, error) {
	decodeBytes, err := hex.DecodeString(decodeStr)
	if err != nil {
		return nil, err
	}

	// Extract IV from the beginning of the ciphertext
	iv := decodeBytes[:des.BlockSize]
	decodeBytes = decodeBytes[des.BlockSize:]

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)

	origData := make([]byte, len(decodeBytes))
	blockMode.CryptBlocks(origData, decodeBytes)

	origData = pkcs5UnPadding(origData)
	return origData, nil
}
