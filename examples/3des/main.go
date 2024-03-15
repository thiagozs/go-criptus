package main

import (
	"fmt"

	"github.com/thiagozs/go-criptus"
)

func main() {

	secret := "this is a secret"

	des, err := criptus.New3DESEncrypt(criptus.T3DESWithKey("123456"))
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	a, err := des.SecretEncrypt(secret, 12, 1, 2, 3, 4)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	b, err := des.SecretDecrypt(a, 12, 1, 2, 3, 4)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	fmt.Printf("Encrypted: %s\n", a)
	fmt.Printf("Decrypted: %s\n", b)

}
