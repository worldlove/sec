# rsa aes 加密通用接口
rsa 加密 解密 签名 验签通用接口
aes 加密 解密 通用接口

## 安装
```bash
    go get github.com/worldlove/sec
```



## rsa使用方法
```go
import (
    "github.com/worldlove/sec"
    "io/ioutil"
    "crypto"
)

// 多数业务只会使用一对密钥，在初始化时创建加密客户端，保存指针以复用

var RSAClient sec.RSACipher

func init() {

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
	rsaClient, err := sec.NewRSADefault(privateKey, publicKey)
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




// 接口列表

type RSACipher interface {
	SetHash(crypto.Hash)                          // 设置签名算法
	SetBusinessPubKey(publicKey []byte) error     // 设置业务方公钥
	Encrypt(plaintext []byte) ([]byte, error)     // 加密
	Decrypt(ciphertext []byte) ([]byte, error)    // 解密
	Sign(src []byte) ([]byte, error)              // 签名
	Verify(src []byte, sign []byte) error         // 验签 （用于测试己方签名）
	VerifyBusiness(src []byte, sign []byte) error // 验签 （验证业务方签名）
}

```

## aes 使用方法
### aes 使用CBC随机填充方法，保证每次加密结果都不相同

```go
var key = "asdlfkajg1028412035ulj.c,xmop830"
var AESClient = sec.NewAES(key)

// 加密
enBytes, err := AESClient.Encrypt("123")
// 解密
deBytes, err := AESClient.Decrypt(enBytes)

```

# LICENSE

The MIT License (MIT)

Copyright (c) 2018 worldlove
