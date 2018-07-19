package sec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type AESCipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

func NewAES(key string) AESCipher {
	return &aesClient{
		aesKey: []byte(key),
	}
}

type aesClient struct {
	aesKey []byte
}

func (this *aesClient) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(this.aesKey) //选择加密算法
	plaintext = _PKCS7Padding(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	blockModel := cipher.NewCBCEncrypter(block, iv)

	blockModel.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil

}

func (this *aesClient) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(this.aesKey) //选择加密算法
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ChiperTextTooShort")

	}
	iv := ciphertext[:aes.BlockSize]

	ciphertext = ciphertext[aes.BlockSize:]
	blockModel := cipher.NewCBCDecrypter(block, iv)
	plantText := make([]byte, len(ciphertext))
	blockModel.CryptBlocks(plantText, ciphertext)
	return plantText, nil
}

func _PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
