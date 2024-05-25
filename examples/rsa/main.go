package main

import (
	"fmt"

	"github.com/thiagozs/go-criptus"
)

func main() {
	content := "this is a secret"

	rsa, err := criptus.NewRsaEncrypt()
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	if err := rsa.SaveRsaKey(); err != nil {
		fmt.Println("Error: ", err)
		return
	}

	sec, err := rsa.RsaEncrypt(content, rsa.PublishKeyPath)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	toStr := rsa.ToString(sec)
	toByte := rsa.ToByte(toStr)

	ans, err := rsa.RsaDecrypt(toByte, rsa.PrivateKeyPath)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	fmt.Printf("Encrypted: %s\n", toStr)
	fmt.Printf("Decrypted: %s\n", ans)
}
