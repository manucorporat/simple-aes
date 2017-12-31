package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func Encrypt(plaintext []byte, password string) []byte {
	// Collect random data for the IV (initial vector=), and for the key derivation
	// of the AES key and the HMAC key
	aesIV := getRandom128()
	aesEntropy := getRandom256()
	hmacEntropy := getRandom256()

	// Derive the password using the entropy collected
	aesKey := deriveKey(password, aesEntropy)
	signatureKey := deriveKey(password, hmacEntropy)

	// Plaintext size must be a multiple of the block size of AES
	plaintext = padPKCS7(plaintext)

	// Generate the ciphertext using fron the plaintext, the generated aesKey and the iv
	cipherText := encryptAESCBC(plaintext, aesKey, aesIV)

	// Build the mensage to be signed using the HMAC
	// The message is all the entropy + ciphertext
	message := buildMessage(aesEntropy, hmacEntropy, aesIV, cipherText)

	// Generate signature using HMAC
	signature := hmacSHA256(message, signatureKey)

	// Build final package
	output := buildFinal(signature, message)

	return output
}

func padPKCS7(msg []byte) []byte {
	msgLen := len(msg)
	padSize := aes.BlockSize - msgLen%aes.BlockSize
	padding := make([]byte, padSize, padSize)
	for i := 0; i < padSize; i++ {
		padding[i] = byte(padSize)
	}
	return append(msg, padding...)
}

func encryptAESCBC(plaintext []byte, key []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aesCBC := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	aesCBC.CryptBlocks(ciphertext, plaintext)
	return ciphertext
}

func buildMessage(aesEntropy, hmacEntropy, aesIV, cipherText []byte) []byte {
	/////////////////////////////////////////////////////////////////////|
	// |  randomAES  |  randomHMAC |    aesIV    |  cipherText ......... |
	// |  32 bytes   |  32 bytes   |  16 bytes   |  rest of bytes        |
	/////////////////////////////////////////////////////////////////////|
	var buffer bytes.Buffer
	buffer.Write(aesEntropy)
	buffer.Write(hmacEntropy)
	buffer.Write(aesIV)
	buffer.Write(cipherText)
	return buffer.Bytes()
}

func buildFinal(signature, message []byte) []byte {
	///////////////////////////////////////////////////////////////////////////////////|
	// |  signature  ||  randomAES  |  randomHMAC |    aesIV    |  cipherText ......... |
	// |  32 bytes   ||  32 bytes   |  32 bytes   |  32 bytes   |  rest of bytes        |
	///////////////////////////////////////////////////////////////////////////////////|
	var buffer bytes.Buffer
	buffer.Write(signature)
	buffer.Write(message)
	return buffer.Bytes()
}

func getRandom128() []byte {
	return getRandom256()[:16]
}

func getRandom256() []byte {
	buffer := make([]byte, 32)
	_, err := rand.Read(buffer)
	if err != nil {
		panic(err)
	}
	return buffer
}
