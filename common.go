package main

import (
	"crypto/hmac"
	"crypto/sha256"
)

func deriveKey(masterKey string, random []byte) []byte {
	return hmacSHA256(random, []byte(masterKey))
}

func hmacSHA256(message []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write(message)
	if err != nil {
		panic(err)
	}
	return mac.Sum(nil)
}
