package sec

import (
	"crypto"
	"io/ioutil"
	"testing"
)

// 多数业务只会使用一对密钥，在初始化时创建加密客户端，保存指针以复用

var RSAClient RSACipher
var BusinessRSAClient RSACipher

func init() {
	initCipher()
	initBusinessCipher()
}

func initCipher() {
	// 读取公钥私钥文件
	const priPath = "secret/private.pem"
	const pubPath = "secret/public.pem"
	privateKey, err1 := ioutil.ReadFile(priPath)
	publicKey, err2 := ioutil.ReadFile(pubPath)
	if err1 != nil || err2 != nil {
		panic("RSAKey Read Error")
	}

	// 生成加密客户端
	// 默认使用PKCS1私钥
	rsaClient, err := NewRSADefault(privateKey, publicKey)
	// // 设置私钥格式(使用PKCS8)
	// rsaClient, err := sec.NewRSA(privateKey, publicKey, sec.RSAPKCS8)
	if err != nil {
		panic("PrivateKeyOrPublicKeyError")
	}

	// 设置签名算法
	const hash = crypto.SHA256
	rsaClient.SetHash(hash)

	// 设置业务方公钥 (加解密签名使用己方密钥对，验签需使用业务方公钥)
	// // 解析字符串公钥
	// var businessPub = sec.ParsePublicKey(businessPubKey)

	// 读取业务方公钥文件
	const businessPubPath = "secret/businessPublic.pem"
	businessPub, _ := ioutil.ReadFile(businessPubPath)
	rsaClient.SetBusinessPubKey(businessPub)

	RSAClient = rsaClient
}
func initBusinessCipher() {
	const priPath = "secret/businessPrivate.pem"
	const pubPath = "secret/businessPublic.pem"
	privateKey, err1 := ioutil.ReadFile(priPath)
	publicKey, err2 := ioutil.ReadFile(pubPath)
	if err1 != nil || err2 != nil {
		panic("RSAKey Read Error")
	}
	// 生成加密客户端
	// 默认使用PKCS1私钥
	rsaClient, err := NewRSADefault(privateKey, publicKey)
	// // 设置私钥格式(使用PKCS8)
	// rsaClient, err := sec.NewRSA(privateKey, publicKey, sec.RSAPKCS8)
	if err != nil {
		panic("PrivateKeyOrPublicKeyError")
	}

	// 设置签名算法
	const hash = crypto.SHA256
	rsaClient.SetHash(hash)

	BusinessRSAClient = rsaClient
}

// 测试加密解密
func TestRSAEncryptAndDecrypt(test *testing.T) {
	var testStr = "abc=123"
	test.Log("TestStr: ", testStr)
	enBytes, _ := RSAClient.Encrypt([]byte(testStr))
	test.Log("Encypt: ", ToBase64(enBytes))
	deBytes, _ := RSAClient.Decrypt(enBytes)
	test.Log("Decrypt: ", string(deBytes))
	if string(deBytes) != testStr {
		test.Error("RSA Decrypt string can not match Encrypt string")
	}
}

// 测试签名验签
func TestSignAndVerify(test *testing.T) {
	var testStr = "abc=123"
	test.Log("TestStr: ", testStr)
	signBytes, _ := RSAClient.Sign([]byte(testStr))
	signStr := ToBase64(signBytes)
	test.Log("Sign: ", signStr)
	signBytes, _ = ToBytes(signStr)
	err := RSAClient.Verify([]byte(testStr), signBytes)
	if err != nil {
		test.Errorf("Verify Error:%v", err)
	}
}

// 测试业务方验签
func TestBusinessVerify(test *testing.T) {
	var testStr = "abc=123"
	test.Log("TestStr: ", testStr)
	//业务方签名
	signBytes, _ := BusinessRSAClient.Sign([]byte(testStr))

	signStr := ToBase64(signBytes)
	test.Log("Sign: ", signStr)
	signBytes, _ = ToBytes(signStr)

	//己方验签
	err := RSAClient.VerifyBusiness([]byte(testStr), signBytes)

	if err != nil {
		test.Errorf("VerifyBusiness Error:%v", err)
	}
}
