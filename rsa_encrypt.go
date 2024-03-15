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

const (
	RsaDefaultPublishKeyName = "publishKey"
	RsaDefaultPrivateKeyName = "privateKey"

	PublishKey = "PUBLIC KEY"
	PrivateKey = "RSA PRIVATE KEY"
)

type RsaEncrypt struct {
	PublishKeyName string
	PrivateKeyName string
	PublishKeyPath string
	PrivateKeyPath string
	Kind           RsaBitsType
}

func formatPubAndPriKeyName(name string) string {
	return fmt.Sprintf("\\%s.pem", name)
}

func NewDefaultRsaEncrypt() *RsaEncrypt {
	defaultPath, _ := os.Getwd()
	return &RsaEncrypt{
		Kind:           RsaBits1024,
		PublishKeyName: formatPubAndPriKeyName(RsaDefaultPublishKeyName),
		PrivateKeyName: formatPubAndPriKeyName(RsaDefaultPrivateKeyName),
		PublishKeyPath: defaultPath + formatPubAndPriKeyName(RsaDefaultPublishKeyName),
		PrivateKeyPath: defaultPath + formatPubAndPriKeyName(RsaDefaultPrivateKeyName),
	}
}

func NewRsaEncrypt(opts ...RSAOptions) (*RsaEncrypt, error) {

	params, err := newRSAParams(opts...)
	if err != nil {
		return nil, err
	}

	obj := NewDefaultRsaEncrypt()
	if bits := params.GetBits(); bits == 0 {
		obj.Kind = bits
	}

	if params.GetPublishKeyName() != "" {
		obj.PublishKeyName = formatPubAndPriKeyName(params.GetPublishKeyName())
	}

	if params.GetPublishKeyPath() != "" {
		obj.PublishKeyPath = params.GetPublishKeyPath() +
			formatPubAndPriKeyName(params.GetPublishKeyName())
	}

	if params.GetPrivateKeyName() != "" {
		obj.PrivateKeyName = formatPubAndPriKeyName(params.GetPrivateKeyName())
	}

	if params.GetPrivateKeyPath() != "" {
		obj.PrivateKeyPath = params.GetPrivateKeyPath() +
			formatPubAndPriKeyName(params.GetPrivateKeyName())
	}

	return obj, nil
}

func (r *RsaEncrypt) SaveRsaKey() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, r.Kind.Bits())
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
