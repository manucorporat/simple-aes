package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
)

const SIGNATURE_SIZE = 32
const META_SIZE = 32 + 32 + 16 // aesEntropy + hmacEntropy + IV
const HEADER_SIZE = SIGNATURE_SIZE + META_SIZE

func Decrypt(data []byte, password string) []byte {
	// Check file size is correct
	if len(data) <= HEADER_SIZE {
		panic("encrypted file header is wrong")
	}
	signature := data[0:SIGNATURE_SIZE]
	message := data[SIGNATURE_SIZE:]
	metadata := message[0:META_SIZE]
	cipherText := message[META_SIZE:]
	if len(cipherText) == 0 || len(cipherText)%aes.BlockSize != 0 {
		panic("ciphertext size is wrong")
	}
	// read metadata
	aesEntropy := metadata[0:32]
	hmacEntropy := metadata[32:64]
	iv := metadata[64:80]

	// check signature
	signatureKey := deriveKey(password, hmacEntropy)
	if !verifySignature(signature, message, signatureKey) {
		panic("signature does not match")
	}

	aesKey := deriveKey(password, aesEntropy)
	plainText := decryptAESCBC(cipherText, aesKey, iv)
	return unpadPKCS7(plainText)
}

func verifySignature(signature, message, key []byte) bool {
	expected := hmacSHA256(message, key)
	return hmac.Equal(signature, expected)
}

func decryptAESCBC(cipherText []byte, key []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aesCBC := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(cipherText))
	aesCBC.CryptBlocks(plaintext, cipherText)
	return plaintext
}

func unpadPKCS7(msg []byte) []byte {
	padSize := int(msg[len(msg)-1])
	plainTextSize := len(msg) - padSize
	return msg[:plainTextSize]
}
