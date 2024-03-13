package main

import (
	"fmt"

	"github.com/thiagozs/go-criptus"
)

func main() {
	secret := "this is a secret"

	rsa := criptus.NewRsaEncrypt(criptus.RsaBits1024, "", "", "", "")
	if err := rsa.SaveRsaKey(); err != nil {
		fmt.Println("Error: ", err)
		return
	}

	sec, err := rsa.RsaEncrypt(secret, rsa.PublishKeyPath)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	encriptedStr := rsa.EncryptString(sec)
	srcByte := rsa.DecryptByte(encriptedStr)

	ans, err := rsa.RsaDecrypt(srcByte, rsa.PrivateKeyPath)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	fmt.Printf("Encrypted: %s\n", encriptedStr)
	fmt.Printf("Decrypted: %s\n", ans)
}
