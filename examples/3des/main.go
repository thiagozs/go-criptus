package main

import (
	"fmt"

	"github.com/thiagozs/go-criptus"
)

func main() {

	secret := "this is a secret"

	opts := []criptus.T3DESOptions{
		criptus.T3DESWithKey("123456789012345678901234"),
		criptus.T3DESWithKind(criptus.TripleEncrypt128),
	}

	des, err := criptus.New3DESEncrypt(opts...)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	a, err := des.SecretEncrypt(secret)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	b, err := des.SecretDecrypt(a)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	fmt.Printf("Encrypted: %s\n", a)
	fmt.Printf("Decrypted: %s\n", b)

}
