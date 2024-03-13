package main

import (
	"fmt"

	"github.com/thiagozs/go-criptus"
)

func main() {

	secret := "this is a secret"

	e, err := criptus.NewAesEncrypt(criptus.BaseSpecialSign,
		"123456", "", criptus.AesEncrypt128, criptus.AesModeTypeECB)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	a, err := e.SecretEncrypt(secret)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	b, err := e.SecretDecrypt(a)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	fmt.Printf("Encrypted: %s\n", a)
	fmt.Printf("Decrypted: %s\n", b)
}
