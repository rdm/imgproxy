package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	errInvalidSignature         = errors.New("Invalid signature")
	errInvalidSignatureEncoding = errors.New("Invalid signature encoding")
)

type securityKey []byte

func validatePath(signature, path string) error {
	messageMAC, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return errInvalidSignatureEncoding
	}
	fmt.Printf("messageMAC %d: %s\n", len(messageMAC), hex.EncodeToString(messageMAC));

	for i := 0; i < len(conf.Keys); i++ {
		fmt.Printf("i: %d, conf.Key[i]: %s\n", i, hex.EncodeToString(conf.Keys[i]));
		if hmac.Equal(messageMAC, signatureFor(path, i)) {
			return nil
		}
	}

	return errInvalidSignature
}

func signatureFor(str string, pairInd int) []byte {
	mac := hmac.New(sha256.New, conf.Keys[pairInd])
	fmt.Printf("pairInd: %d\n", pairInd)
	fmt.Printf("key: %d: %s\n", len(conf.Keys[pairInd]), hex.EncodeToString(conf.Keys[pairInd]))
	mac.Write(conf.Salts[pairInd])
	fmt.Printf("salt: %d: %s\n", len(conf.Salts[pairInd]), hex.EncodeToString(conf.Salts[pairInd]))
	fmt.Printf("str: %d: %s\n", len(str), str)
	mac.Write([]byte(str))
	expectedMAC := mac.Sum(nil)
	fmt.Printf("expectedMAC: %d -- %s\n", len(expectedMAC), hex.EncodeToString(expectedMAC))
	fmt.Printf("conf.SignatureSize: %d\n", conf.SignatureSize);
	if conf.SignatureSize < 32 {
		return expectedMAC[:conf.SignatureSize]
	}
	return expectedMAC
}
