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
    priKey, err1 := ioutil.ReadFile(priPath)
    pubKey, err2 := ioutil.ReadFile(pubPath)
    if err1 != nil || err2 != nil {
        panic("RSAKey Read Error")
    }

    // 生成加密客户端
    rsaClient, err := sec.NewRSADefault(privateKey, publicKey)
    if err != nil {
        Panic("PrivateKeyOrPublicKeyError")
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

    RSACipher = rsaClient
}




// 通用接口
type RSACipher interface {
	SetHash(crypto.Hash)
	SetBusinessPubKey(publicKey []byte) error
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	Sign(src []byte) ([]byte, error)
	Verify(src []byte, sign []byte) error
	VerifyBusiness(src []byte, sign []byte) error
}

```

## aes 使用方法
### aes 使用CBC随机填充方法，保证每次加密结果都不相同，提高安全性

```go
var key = "123asdfaksjglasdjglk"
var AESClient = sec.NewAES(key)

// 加密
enBytes, err := AESClient.Encrypt("123")
// 解密
deBytes, err := AESClient.Decrypt(enBytes)

```

# LICENSE

The MIT License (MIT)

Copyright (c) 2018 worldlove
