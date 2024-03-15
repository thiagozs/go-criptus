package criptus

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"github.com/spf13/cast"
)

type AesEncrypt struct {
	// Encryption and decryption will be based on this string
	// of characters, if not, it will be based on AesBaseSpecialSign.
	SpecialSign     string
	Key             string // Key, it is recommended to use a 5-8 digit key
	IV              string // Initial Vector 16 bytes
	AesModeType     AesModeType
	AesKeyType      AesKeyType
	AesKey          []byte
	PlainTextLength int
}

func NewAESEncrypt(opts ...AESOptions) (*AesEncrypt, error) {

	params, err := newAESParams(opts...)
	if err != nil {
		return nil, err
	}

	if len(params.GetKey()) == 0 {
		return nil, errors.New("need the key to encrypt, please add it. ")
	}

	if len(params.GetSpecialSign()) == 0 {
		params.SetSpecialSign(BaseSpecialSign)
	}

	specialSign := formatSpecialSign(params.GetSpecialSign(),
		params.GetKey(), params.GetAesKeyType())

	if len(params.GetIV()) == 0 {
		params.SetIV(specialSign + params.GetKey())
	}

	if len(params.GetIV()) > IVLength {
		params.SetIV(params.GetIV()[:IVLength])
	}

	return &AesEncrypt{
		SpecialSign: specialSign,
		Key:         params.GetKey(),
		IV:          params.GetIV(),
		AesModeType: params.GetAesModeType(),
		AesKeyType:  params.GetAesKeyType(),
	}, nil
}

func (a *AesEncrypt) getPrefix(length int) string {
	if len(a.SpecialSign)%2 == 0 {
		return a.SpecialSign[len(a.SpecialSign)-length:]
	}
	return a.SpecialSign[:length]
}

func (a *AesEncrypt) generateAesKey() []byte {
	length := int(a.AesKeyType.Length() - len(a.Key))
	buf := make([]byte, 0, a.AesKeyType.Length())
	prefix := a.getPrefix(length)
	buf = append(buf, []byte(prefix)...)
	buf = append(buf, []byte(a.Key)...)
	return buf
}

func (a *AesEncrypt) SecretEncrypt(secret interface{}) (string, error) {
	if secret != "" {
		a.AesKey = a.generateAesKey()
		str := cast.ToString(secret)
		a.PlainTextLength = len(str)
		ans, err := a.aesEncrypt(str)
		if err != nil {
			return "", err
		}

		return ans, nil
	}

	return "", errors.New("secret is empty")
}

func (a *AesEncrypt) SecretDecrypt(secret interface{}) (string, error) {
	if secret != "" {
		a.AesKey = a.generateAesKey()
		b, err := a.aesDecrypt(cast.ToString(secret))
		if err != nil {
			return "", err
		}

		return b, nil
	}

	return "", nil
}

func (a *AesEncrypt) aesEncrypt(encodeStr string) (string, error) {
	block, err := aes.NewCipher(a.AesKey)
	if err != nil {
		return "", err
	}

	switch a.AesModeType {
	case AesModeTypeCBC:
		return a.aesEncrypterCBC(encodeStr, block)
	case AesModeTypeCFB:
		return a.aesEncrypterCFB(encodeStr, block)
	case AesModeTypeECB:
		return a.aesEncrypterECB(encodeStr, block)
	case AesModeTypeCTR:
		return a.aesEncrypterCTR(encodeStr, block)
	case AesModeTypeOFB:
		return a.aesEncrypterOFB(encodeStr, block)
	}
	return "", nil
}

func (a *AesEncrypt) aesDecrypt(decodeStr string) (string, error) {
	//decodeBytes, err := hex.DecodeString(decodeStr)
	decodeBytes, err := base64.StdEncoding.DecodeString(decodeStr)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(a.AesKey)
	if err != nil {
		return "", err
	}

	switch a.AesModeType {
	case AesModeTypeCBC:
		return a.aesDecrypterCBC(decodeBytes, block)
	case AesModeTypeCFB:
		return a.aesDecrypterCFB(decodeStr, block)
	case AesModeTypeCTR:
		return a.aesDecrypterCTR(decodeStr, block)
	case AesModeTypeOFB:
		return a.aesDecrypterOFB(decodeStr, block)
	case AesModeTypeECB:
		return a.aesDecrypterECB(decodeStr, block)
	}
	return "", nil
}

func (a *AesEncrypt) aesEncrypterCBC(encodeStr string, block cipher.Block) (string, error) {
	encodeByte := []byte(encodeStr)
	encodeByte = pkcs5Padding(encodeByte, block.BlockSize())

	blockMode := cipher.NewCBCEncrypter(block, []byte(a.IV))

	crypted := make([]byte, len(encodeByte))

	blockMode.CryptBlocks(crypted, encodeByte)

	return base64.StdEncoding.EncodeToString(crypted), nil
}

func (a *AesEncrypt) aesDecrypterCBC(decodeBytes []byte, block cipher.Block) (string, error) {
	blockMode := cipher.NewCBCDecrypter(block, []byte(a.IV))

	blockMode.CryptBlocks(decodeBytes, decodeBytes)

	return string(pkcs5UnPadding(decodeBytes)), nil
}

func (a *AesEncrypt) aesEncrypterCFB(encodeStr string, block cipher.Block) (string, error) {
	originData := []byte(encodeStr)
	encrypted := make([]byte, aes.BlockSize+len(originData))

	if _, err := io.ReadFull(rand.Reader, []byte(a.IV)); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, []byte(a.IV))

	stream.XORKeyStream(encrypted[aes.BlockSize:], originData)

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (a *AesEncrypt) aesDecrypterCFB(decodeStr string, block cipher.Block) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(decodeStr)
	if err != nil {
		return "", err
	}

	if len(encrypted) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	encrypted = encrypted[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, []byte(a.IV))

	stream.XORKeyStream(encrypted, encrypted)

	return string(encrypted), nil
}

func (a *AesEncrypt) aesEncrypterECB(encodeStr string, block cipher.Block) (string, error) {
	size := block.BlockSize()

	data := pkcs7Padding([]byte(encodeStr), size)

	encrypted := make([]byte, len(data))

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Encrypt(encrypted[bs:be], data[bs:be])
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (a *AesEncrypt) aesDecrypterECB(encodeStr string, block cipher.Block) (string, error) {
	size := block.BlockSize()

	data, err := base64.StdEncoding.DecodeString(encodeStr)
	if err != nil {
		return "", err
	}

	decrypted := make([]byte, len(data))

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return string(pkcs7UnPadding(decrypted)), nil
}

func (a *AesEncrypt) aesEncrypterCTR(plainText string, block cipher.Block) (string, error) {
	stream := cipher.NewCTR(block, []byte(a.IV))

	dst := make([]byte, len(plainText))

	stream.XORKeyStream(dst, []byte(plainText))

	return base64.StdEncoding.EncodeToString(dst), nil
}

func (a *AesEncrypt) aesDecrypterCTR(decode string, block cipher.Block) (string, error) {
	plainText, err := base64.StdEncoding.DecodeString(decode)
	if err != nil {
		return "", err
	}
	stream := cipher.NewCTR(block, []byte(a.IV))

	dst := make([]byte, len(plainText))

	stream.XORKeyStream(dst, plainText)

	return string(dst), nil
}

func (a *AesEncrypt) aesEncrypterOFB(plainText string, block cipher.Block) (string, error) {
	stream := cipher.NewOFB(block, []byte(a.IV))

	dst := make([]byte, len(plainText))

	stream.XORKeyStream(dst, []byte(plainText))

	return base64.StdEncoding.EncodeToString(dst), nil
}

func (a *AesEncrypt) aesDecrypterOFB(decode string, block cipher.Block) (string, error) {
	plainText, err := base64.StdEncoding.DecodeString(decode)
	if err != nil {
		return "", err
	}
	stream := cipher.NewOFB(block, []byte(a.IV))

	dst := make([]byte, len(plainText))

	stream.XORKeyStream(dst, plainText)

	return string(dst), nil
}
