package sec

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"strings"
)

type RSAType int

const (
	// 私钥类型
	RSAPKCS1 RSAType = iota
	RSAPKCS8
)

// base64编码
func ToBase64(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

type RSACipher interface {
	SetHash(crypto.Hash)
	SetBusinessPubKey(publicKey []byte) error
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	Sign(src []byte) ([]byte, error)
	Verify(src []byte, sign []byte) error
	VerifyBusiness(src []byte, sign []byte) error
}

type pkcsClient struct {
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	businessPubKey *rsa.PublicKey
	hash           crypto.Hash
}

func (this *pkcsClient) SetHash(hash crypto.Hash) {
	this.hash = hash
}
func (this *pkcsClient) SetBusinessPubKey(publicKey []byte) error {
	blockPub, _ := pem.Decode(publicKey)
	if blockPub == nil {
		return errors.New("PublicKeyError")
	}
	pubKey, err := genPubKey(blockPub.Bytes)
	if err != nil {
		log.Println("BlockBusinessPubKeyError")
		return err
	}
	this.businessPubKey = pubKey
	return nil
}

func (this *pkcsClient) Encrypt(plaintext []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, this.publicKey, plaintext)
}
func (this *pkcsClient) Decrypt(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, this.privateKey, ciphertext)
}

func (this *pkcsClient) Sign(src []byte) ([]byte, error) {
	h := this.hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, this.privateKey, this.hash, hashed)
}

func (this *pkcsClient) Verify(src []byte, sign []byte) error {
	h := this.hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.VerifyPKCS1v15(this.publicKey, this.hash, hashed, sign)
}

func (this *pkcsClient) VerifyBusiness(src []byte, sign []byte) error {

	if this.businessPubKey == nil {
		return errors.New("YouMustSetTheBusinessPublicKeyFirst")
	}
	h := this.hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.VerifyPKCS1v15(this.businessPubKey, this.hash, hashed, sign)
}

//NewRSADefault 默认客户端，pkcs1私钥格式，pem编码
func NewRSADefault(privateKey, publicKey []byte) (RSACipher, error) {
	return NewRSA(privateKey, publicKey, RSAPKCS1)
}

// New 生成RSA 客户端
func NewRSA(privateKey, publicKey []byte, privateKeyType RSAType) (RSACipher, error) {
	blockPri, _ := pem.Decode(privateKey)
	if blockPri == nil {
		return nil, errors.New("PrivateKeyError")
	}

	blockPub, _ := pem.Decode(publicKey)
	if blockPub == nil {
		return nil, errors.New("PublicKeyError")
	}

	priKey, err := genPriKey(blockPri.Bytes, privateKeyType)
	if err != nil {
		log.Println("BlockPriError")
		return nil, err
	}
	pubKey, err := genPubKey(blockPub.Bytes)
	if err != nil {
		log.Println("BlockPubError")
		return nil, err
	}
	return &pkcsClient{privateKey: priKey, publicKey: pubKey}, nil
}

func genPubKey(publicKey []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}

func genPriKey(privateKey []byte, privateKeyType RSAType) (*rsa.PrivateKey, error) {
	var priKey *rsa.PrivateKey
	var err error
	switch privateKeyType {
	case RSAPKCS1:
		{
			priKey, err = x509.ParsePKCS1PrivateKey([]byte(privateKey))
			if err != nil {
				return nil, err
			}
		}
	case RSAPKCS8:
		{
			log.Println("type", privateKeyType)
			prkI, err := x509.ParsePKCS8PrivateKey([]byte(privateKey))
			if err != nil {
				return nil, err
			}
			log.Println("type", privateKeyType)
			priKey = prkI.(*rsa.PrivateKey)
		}
	default:
		{
			log.Println("default", privateKeyType)
			return nil, errors.New("UnsupportPrivateKeyType")
		}
	}
	return priKey, nil
}
func ParsePublicKey(raw string) (result []byte) {
	return parseKey(raw, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----")
}
func ParsePrivateKey(raw string) (result []byte) {
	return parseKey(raw, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----")
}
func parseKey(raw, prefix, suffix string) (result []byte) {
	raw = strings.Replace(raw, prefix, "", 1)
	raw = strings.Replace(raw, suffix, "", 1)
	raw = strings.Replace(raw, " ", "", -1)
	raw = strings.Replace(raw, "\n", "", -1)
	raw = strings.Replace(raw, "\r", "", -1)
	raw = strings.Replace(raw, "\t", "", -1)

	var buf bytes.Buffer
	buf.WriteString(prefix + "\n")
	const KEYLINE = 64
	var slen = len(raw)
	var i = 0
	for i+KEYLINE < slen {
		buf.WriteString(raw[i : i+KEYLINE])
		buf.WriteString("\n")
		i += KEYLINE
	}
	buf.WriteString(raw[i:])
	buf.WriteString("\n")
	buf.WriteString(suffix)
	return buf.Bytes()
}
