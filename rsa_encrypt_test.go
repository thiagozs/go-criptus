package criptus_test

import (
	"os"
	"testing"

	"github.com/thiagozs/go-criptus"
)

func TestRsaEncrypt(t *testing.T) {
	// Cria a instância do RsaEncrypt.
	rsaEnc, err := criptus.NewRsaEncrypt()
	if err != nil {
		t.Fatalf("Erro ao criar instância de RsaEncrypt: %v", err)
	}

	// Remove os arquivos de chave (caso existam) para garantir um teste limpo.
	os.Remove(rsaEnc.PublicKeyPath)
	os.Remove(rsaEnc.PrivateKeyPath)

	// Gera as chaves RSA.
	if err := rsaEnc.GenerateKeys(); err != nil {
		t.Fatalf("Erro ao gerar chaves RSA: %v", err)
	}

	// Verifica se os arquivos de chave foram criados.
	if _, err := os.Stat(rsaEnc.PublicKeyPath); os.IsNotExist(err) {
		t.Fatalf("Arquivo da chave pública não foi criado: %s", rsaEnc.PublicKeyPath)
	}
	if _, err := os.Stat(rsaEnc.PrivateKeyPath); os.IsNotExist(err) {
		t.Fatalf("Arquivo da chave privada não foi criado: %s", rsaEnc.PrivateKeyPath)
	}

	// Mensagem de teste.
	mensagemOriginal := "Esta é uma mensagem de teste"

	// Criptografa a mensagem utilizando a chave pública.
	ciphertext, err := rsaEnc.Encrypt(mensagemOriginal, rsaEnc.PublicKeyPath)
	if err != nil {
		t.Fatalf("Erro ao criptografar a mensagem: %v", err)
	}

	// Descriptografa a mensagem utilizando a chave privada.
	mensagemDescriptografada, err := rsaEnc.Decrypt(ciphertext, rsaEnc.PrivateKeyPath)
	if err != nil {
		t.Fatalf("Erro ao descriptografar a mensagem: %v", err)
	}

	// Compara se a mensagem descriptografada é igual à original.
	if mensagemDescriptografada != mensagemOriginal {
		t.Errorf("A mensagem descriptografada difere da original.\nEsperado: %s\nObtido: %s", mensagemOriginal, mensagemDescriptografada)
	}

	// Testa os métodos de codificação e decodificação Base64.
	encoded := rsaEnc.EncodeBase64(ciphertext)
	decoded, err := rsaEnc.DecodeBase64(encoded)
	if err != nil {
		t.Fatalf("Erro ao decodificar a string Base64: %v", err)
	}
	if string(decoded) != string(ciphertext) {
		t.Errorf("Decodificação Base64 incorreta.\nEsperado: %v\nObtido: %v", ciphertext, decoded)
	}
}
