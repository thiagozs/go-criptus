package criptus

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

type RsaBitsType int

const (
	RsaBits512     RsaBitsType = 512
	RsaBits1024    RsaBitsType = 1024
	RsaBits2048    RsaBitsType = 2048
	RsaBits4096    RsaBitsType = 4096
	RsaDefaultBits             = RsaBits1024
)

const (
	RsaDefaultPublishKeyName = "publishKey"
	RsaDefaultPrivateKeyName = "privateKey"

	PublishKey = "PUBLIC KEY"
	PrivateKey = "RSA PRIVATE KEY"
)

type RsaEncrypt struct {
	Bits           RsaBitsType
	PublishKeyName string
	PrivateKeyName string
	PublishKeyPath string
	PrivateKeyPath string
}

var RsaBitsMap = map[RsaBitsType]int{
	RsaBits512:  512,
	RsaBits1024: 1024,
	RsaBits2048: 2048,
	RsaBits4096: 4096,
}

func formatPubAndPriKeyName(name string) string {
	return fmt.Sprintf("\\%s.pem", name)
}

func NewDefaultRsaEncrypt() *RsaEncrypt {
	defaultPath, _ := os.Getwd()
	return &RsaEncrypt{
		Bits:           RsaDefaultBits,
		PublishKeyName: formatPubAndPriKeyName(RsaDefaultPublishKeyName),
		PrivateKeyName: formatPubAndPriKeyName(RsaDefaultPrivateKeyName),
		PublishKeyPath: defaultPath + formatPubAndPriKeyName(RsaDefaultPublishKeyName),
		PrivateKeyPath: defaultPath + formatPubAndPriKeyName(RsaDefaultPrivateKeyName),
	}
}

func NewRsaEncrypt(bits RsaBitsType, publishKeyName, publishKeyPath,
	privateKeyName, privateKeyPath string) *RsaEncrypt {
	obj := NewDefaultRsaEncrypt()
	if bits != 0 {
		obj.Bits = bits
	}

	if publishKeyName != "" {
		obj.PublishKeyName = formatPubAndPriKeyName(publishKeyName)
	}
	if publishKeyPath != "" {
		obj.PublishKeyPath = publishKeyPath + formatPubAndPriKeyName(publishKeyName)
	}
	if privateKeyName != "" {
		obj.PrivateKeyName = formatPubAndPriKeyName(privateKeyName)
	}
	if privateKeyPath != "" {
		obj.PrivateKeyPath = privateKeyPath + formatPubAndPriKeyName(privateKeyName)
	}
	return obj
}

func (r *RsaEncrypt) SaveRsaKey() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, RsaBitsMap[r.Bits])
	if err != nil {
		fmt.Println(err)
		return err
	}
	publicKey := privateKey.PublicKey

	x509PrivateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	x509PublicBytes := x509.MarshalPKCS1PublicKey(&publicKey)

	blockPrivate := pem.Block{Type: PrivateKey, Bytes: x509PrivateBytes}
	blockPublic := pem.Block{Type: PublishKey, Bytes: x509PublicBytes}

	privateFile, errPri := os.Create(r.PrivateKeyPath)
	if errPri != nil {
		return errPri
	}

	defer func(privateFile *os.File) {
		errClose := privateFile.Close()
		if errClose != nil {
			panic(errClose)
		}
	}(privateFile)

	err = pem.Encode(privateFile, &blockPrivate)
	if err != nil {
		return err
	}

	publicFile, errPub := os.Create(r.PublishKeyPath)
	if errPub != nil {
		return errPub
	}

	defer publicFile.Close()

	err = pem.Encode(publicFile, &blockPublic)
	if err != nil {
		return err
	}

	return nil
}

func (r *RsaEncrypt) RsaEncrypt(src, filePath string) ([]byte, error) {
	srcByte := []byte(src)
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	fileInfo, errInfo := file.Stat()
	if errInfo != nil {
		return nil, errInfo
	}

	keyBytes := make([]byte, fileInfo.Size())

	file.Read(keyBytes)

	block, _ := pem.Decode(keyBytes)

	publicKey, errPb := x509.ParsePKCS1PublicKey(block.Bytes)
	if errPb != nil {
		return nil, errPb
	}

	retByte, errRet := rsa.EncryptPKCS1v15(rand.Reader, publicKey, srcByte)
	if errRet != nil {
		return nil, errRet
	}
	return retByte, nil
}

func (r *RsaEncrypt) RsaDecrypt(srcByte []byte, filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}

	fileInfo, errInfo := file.Stat()
	if errInfo != nil {
		return "", errInfo
	}

	keyBytes := make([]byte, fileInfo.Size())

	_, _ = file.Read(keyBytes)

	block, _ := pem.Decode(keyBytes)

	privateKey, errPb := x509.ParsePKCS1PrivateKey(block.Bytes)
	if errPb != nil {
		return "", errPb
	}

	retByte, errRet := rsa.DecryptPKCS1v15(rand.Reader, privateKey, srcByte)
	if errRet != nil {
		return "", errRet
	}
	return string(retByte), nil
}

func (r *RsaEncrypt) EncryptString(retByte []byte) string {
	return base64.StdEncoding.EncodeToString(retByte)
}

func (r *RsaEncrypt) DecryptByte(src string) []byte {
	b, _ := base64.StdEncoding.DecodeString(src)
	return b
}
