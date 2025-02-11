package criptus

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Constantes para os nomes dos arquivos padrão e para os blocos PEM.
const (
	defaultPublicKeyName  = "publicKey.pem"
	defaultPrivateKeyName = "privateKey.pem"

	publicKeyPEMBlockType  = "PUBLIC KEY"
	privateKeyPEMBlockType = "RSA PRIVATE KEY"
)

// RsaBitsType define uma interface para obter o tamanho (em bits) da chave RSA.
type RsaBitsType interface {
	Bits() int
}

// Para simplificar, definimos um tipo básico para os bits.
type rsaBits int

func (b rsaBits) Bits() int {
	return int(b)
}

const (
	RsaBits512  rsaBits = 512
	RsaBits1024 rsaBits = 1024
	RsaBits2048 rsaBits = 2048
	RsaBits4096 rsaBits = 4096
)

// RsaEncrypt guarda os caminhos para as chaves e o tamanho desejado da chave.
type RsaEncrypt struct {
	PublicKeyPath  string
	PrivateKeyPath string
	Bits           RsaBitsType
}

// NewRsaEncrypt cria uma nova instância de RsaEncrypt, aplicando as opções ou utilizando
// os valores padrão para os caminhos e tamanho da chave.
func NewRsaEncrypt(opts ...RSAOptions) (*RsaEncrypt, error) {
	params, err := newRSAParams(opts...)
	if err != nil {
		return nil, err
	}

	defaultPath, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// Se não tiver caminho definido, utiliza o caminho atual com o nome padrão.
	if params.GetPublishKeyPath() == "" {
		params.SetPublishKeyPath(filepath.Join(defaultPath, defaultPublicKeyName))
	}
	if params.GetPrivateKeyPath() == "" {
		params.SetPrivateKeyPath(filepath.Join(defaultPath, defaultPrivateKeyName))
	}
	if params.GetBits() == nil {
		params.SetBits(RsaBits1024)
	}

	return &RsaEncrypt{
		PublicKeyPath:  params.GetPublishKeyPath(),
		PrivateKeyPath: params.GetPrivateKeyPath(),
		Bits:           params.GetBits(),
	}, nil
}

// --- Funções auxiliares para carregamento e salvamento das chaves ---

// loadRSAPrivateKey carrega uma chave privada RSA de um arquivo PEM.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != privateKeyPEMBlockType {
		return nil, fmt.Errorf("falha ao decodificar o bloco PEM da chave privada")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// loadRSAPublicKey carrega uma chave pública RSA de um arquivo PEM.
func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != publicKeyPEMBlockType {
		return nil, fmt.Errorf("falha ao decodificar o bloco PEM da chave pública")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

// saveRSAPrivateKey salva uma chave privada RSA em um arquivo PEM.
func saveRSAPrivateKey(path string, key *rsa.PrivateKey) error {
	data := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  privateKeyPEMBlockType,
		Bytes: data,
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// saveRSAPublicKey salva uma chave pública RSA em um arquivo PEM.
func saveRSAPublicKey(path string, key *rsa.PublicKey) error {
	data := x509.MarshalPKCS1PublicKey(key)
	block := &pem.Block{
		Type:  publicKeyPEMBlockType,
		Bytes: data,
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

// --- Métodos do RsaEncrypt ---

// GenerateKeys gera as chaves RSA e as salva nos arquivos configurados.
// Caso ambas já existam, nada é feito.
func (r *RsaEncrypt) GenerateKeys() error {
	// Tenta carregar as chaves existentes.
	_, privErr := loadRSAPrivateKey(r.PrivateKeyPath)
	_, pubErr := loadRSAPublicKey(r.PublicKeyPath)

	// Se as duas chaves foram carregadas com sucesso, encerra.
	if privErr == nil && pubErr == nil {
		return nil
	}

	// Gera nova chave RSA.
	newPriv, err := rsa.GenerateKey(rand.Reader, r.Bits.Bits())
	if err != nil {
		return err
	}
	newPub := &newPriv.PublicKey

	// Salva as chaves nos respectivos arquivos.
	if err := saveRSAPrivateKey(r.PrivateKeyPath, newPriv); err != nil {
		return err
	}
	if err := saveRSAPublicKey(r.PublicKeyPath, newPub); err != nil {
		return err
	}
	return nil
}

// Encrypt criptografa o texto plano utilizando a chave pública encontrada em pubKeyPath.
func (r *RsaEncrypt) Encrypt(plaintext string, pubKeyPath string) ([]byte, error) {
	pub, err := loadRSAPublicKey(pubKeyPath)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(plaintext))
}

// Decrypt descriptografa o texto cifrado utilizando a chave privada encontrada em privKeyPath.
func (r *RsaEncrypt) Decrypt(ciphertext []byte, privKeyPath string) (string, error) {
	priv, err := loadRSAPrivateKey(privKeyPath)
	if err != nil {
		return "", err
	}
	plainBytes, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}

// EncodeBase64 codifica os dados em Base64.
func (r *RsaEncrypt) EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodifica uma string Base64 para bytes.
func (r *RsaEncrypt) DecodeBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
