package criptus

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"runtime"
)

const (
	RsaDefaultPublishKeyName = "publishKey"
	RsaDefaultPrivateKeyName = "privateKey"

	PublishKey = "PUBLIC KEY"
	PrivateKey = "RSA PRIVATE KEY"
)

type RsaEncrypt struct {
	PublishKeyPath  string
	PrivateKeyPath  string
	OneTimeGenerate bool
	Kind            RsaBitsType
}

func formatName(name string) string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("\\%s.pem", name)
	}

	return fmt.Sprintf("/%s.pem", name)
}

func NewRsaEncrypt(opts ...RSAOptions) (*RsaEncrypt, error) {

	params, err := newRSAParams(opts...)
	if err != nil {
		return nil, err
	}

	defaultPath, _ := os.Getwd()

	if len(params.GetPublishKeyPath()) == 0 {
		params.SetPublishKeyPath(defaultPath +
			formatName(RsaDefaultPublishKeyName))
	}

	if len(params.GetPrivateKeyPath()) == 0 {
		params.SetPrivateKeyPath(defaultPath +
			formatName(RsaDefaultPrivateKeyName))
	}

	if params.GetBits() == 0 {
		params.SetBits(RsaBits1024)
	}

	return &RsaEncrypt{
		PublishKeyPath: params.GetPublishKeyPath(),
		PrivateKeyPath: params.GetPrivateKeyPath(),
		Kind:           params.GetBits(),
	}, nil
}

func (r *RsaEncrypt) SaveRsaKey() error {
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey

	if _, err := os.Stat(r.PublishKeyPath); err == nil {
		// Load the existing public key
		publicKeyBytes, err := os.ReadFile(r.PublishKeyPath)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(publicKeyBytes)
		if block == nil || block.Type != PublishKey {
			return fmt.Errorf("failed to decode PEM block containing public key")
		}
		pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return err
		}
		publicKey = pubKey
	}

	if _, err := os.Stat(r.PrivateKeyPath); err == nil {
		// Load the existing private key
		privateKeyBytes, err := os.ReadFile(r.PrivateKeyPath)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(privateKeyBytes)
		if block == nil || block.Type != PrivateKey {
			return fmt.Errorf("failed to decode PEM block containing private key")
		}
		priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		privateKey = priKey
	}

	// If keys are not loaded, generate new ones
	if privateKey == nil || publicKey == nil {
		privateKey, err := rsa.GenerateKey(rand.Reader, r.Kind.Bits())
		if err != nil {
			return err
		}

		publicKey = &privateKey.PublicKey

		x509PrivateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		x509PublicBytes := x509.MarshalPKCS1PublicKey(publicKey)

		blockPrivate := pem.Block{Type: PrivateKey, Bytes: x509PrivateBytes}
		blockPublic := pem.Block{Type: PublishKey, Bytes: x509PublicBytes}

		privateFile, err := os.Create(r.PrivateKeyPath)
		if err != nil {
			return err
		}

		defer privateFile.Close()

		err = pem.Encode(privateFile, &blockPrivate)
		if err != nil {
			return err
		}

		publicFile, err := os.Create(r.PublishKeyPath)
		if err != nil {
			return err
		}

		defer publicFile.Close()

		if err := pem.Encode(publicFile, &blockPublic); err != nil {
			return err
		}
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

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	retByte, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, srcByte)
	if err != nil {
		return nil, err
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

func (r *RsaEncrypt) ToString(retByte []byte) string {
	return base64.StdEncoding.EncodeToString(retByte)
}

func (r *RsaEncrypt) ToByte(src string) []byte {
	b, _ := base64.StdEncoding.DecodeString(src)
	return b
}
