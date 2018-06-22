package sup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

func Encrypt(key, text string) (ciphertext string, err error) {
	key32 := sha256.Sum256([]byte(key))
	plaintext := []byte(text)

	block, err := aes.NewCipher(key32[0:])
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce := make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}

	for {
		_ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
		ciphertext = base64.URLEncoding.EncodeToString(_ciphertext)
		if !strings.HasPrefix(ciphertext, "-") {
			break
		}
	}
	return
}

//func Decrypt(key, text string) (plaintext string, err error) {
func Decrypt(key, text string) (plaintext string, err error) {
	key32 := sha256.Sum256([]byte(key))

	_ciphertext, err := base64.URLEncoding.DecodeString(text)
	if err != nil {
		return
	}
	ciphertext := []byte(_ciphertext)

	block, err := aes.NewCipher(key32[0:])
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonceSize := 12
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	_plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}

	plaintext = string(_plaintext)
	return
}
