package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func Decrypt(encryptedText, key string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return encryptedText, nil
	}

	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return encryptedText, nil
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return encryptedText, nil
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return encryptedText, nil
	}

	if len(ciphertext) < gcm.NonceSize() {
		return encryptedText, nil
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return encryptedText, nil
	}

	return string(plaintext), nil
}

func main() {
	encryptionKey := "/Cph21akSvMOopp4V+dj74ZxYCLDSzIyi54vr0U/LOM="
	extractCode := "7f2yzlcGQawRMlTXRAk7CZxFhCD0KfpMsmyaJVnrQw=="

	decrypted, err := Decrypt(extractCode, encryptionKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Decrypted:", decrypted)
}
