package main

import (
	"fmt"

	"github.com/thiagozs/go-criptus"
)

func main() {
	specialSign := "12345678901"
	key := "458796"
	secret := "this is a secret"

	des, err := criptus.NewDesEncrypt(specialSign, key)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	str, err := des.SecretEncrypt(secret)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	ans, err := des.SecretDecrypt(str)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("Encrypted: %s\n", str)
	fmt.Printf("Decrypted: %s\n", ans)
}
