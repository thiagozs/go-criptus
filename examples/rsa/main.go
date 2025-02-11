package main

import (
	"fmt"

	"github.com/thiagozs/go-criptus"
)

func main() {
	// Cria a instância do RsaEncrypt.
	rsaEnc, err := criptus.NewRsaEncrypt()
	if err != nil {
		panic(err)
	}

	// Gera as chaves RSA (se já não existirem, elas serão criadas)
	if err := rsaEnc.GenerateKeys(); err != nil {
		panic(err)
	}

	mensagem := "Olá, mundo!"

	// Criptografa utilizando a chave pública
	cipherText, err := rsaEnc.Encrypt(mensagem, rsaEnc.PublicKeyPath)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Mensagem criptografada: %s\n", rsaEnc.EncodeBase64(cipherText))

	// Descriptografa utilizando a chave privada
	plainText, err := rsaEnc.Decrypt(cipherText, rsaEnc.PrivateKeyPath)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Mensagem descriptografada: %s\n", plainText)
}
